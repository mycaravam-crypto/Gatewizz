# End-to-end check of the firewall service (#59) with the shipping gatewizz.exe. It needs an elevated prompt;
# GitHub's Windows runners are elevated.
#
# It installs the service from a test config:
# - the executable and the config are copied to %ProgramFiles%\Gatewizz
# - the service runs as LocalSystem from there, never from the user-writable build directory
# - the filters are installed
# Then it changes the rules with `firewall apply` and checks the service picked them up. Finally it removes
# everything and checks that nothing is left: no service, no filters, no files.
#
#   pwsh .github/scripts/windows-firewall-smoke.ps1 -Exe target\release\gatewizz.exe
param([Parameter(Mandatory)] [string] $Exe)
$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path $Exe).Path
$failures = [System.Collections.Generic.List[string]]::new()
$home_ = Join-Path $env:ProgramFiles 'Gatewizz'
$work = Join-Path $env:RUNNER_TEMP ('gatewizz-fw-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Invoke-Gatewizz([string[]] $Arguments) {
    $ErrorActionPreference = 'Continue'
    $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = $out }
}

function Check([string] $Name, [bool] $Ok, [string] $Detail = '') {
    if ($Ok) { Write-Host "ok    $Name" }
    else { Write-Host "FAIL  $Name`n$Detail"; $failures.Add($Name) }
}

# Polls instead of sleeping a fixed time, so a slow runner is not a failure and a fast one does not wait.
function Wait-Until([scriptblock] $Condition, [int] $Seconds = 30) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 250
    }
    [bool](& $Condition)
}

function Applied-Count {
    $log = Join-Path $home_ 'service.log'
    if (Test-Path $log) { @(Select-String -Path $log -Pattern 'Applied ' -SimpleMatch).Count } else { 0 }
}

function Filter-Count {
    $r = Invoke-Gatewizz @('firewall', 'status')
    if ($r.Text -match 'installed with (\d+) filter') { [int]$Matches[1] } else { 0 }
}

# TEST-NET-1 addresses (RFC 5737) are never routed, so these rules affect nothing real.
$one = Join-Path $work 'one.toml'
Set-Content -Path $one -Value @'
[[connection_rules]]
id = "smoke-block-one"
ip = ["192.0.2.1"]
port = [9]
action = "block"
'@
$two = Join-Path $work 'two.toml'
Set-Content -Path $two -Value @'
[[connection_rules]]
id = "smoke-block-one"
ip = ["192.0.2.1"]
port = [9]
action = "block"

[[connection_rules]]
id = "smoke-block-two"
ip = ["192.0.2.2"]
port = [9]
action = "block"
'@

try {
    $r = Invoke-Gatewizz @('firewall', 'install', '--config', $one)
    Check 'firewall install succeeds' ($r.Code -eq 0) $r.Text

    $svc = Get-CimInstance Win32_Service -Filter "Name='gatewizz-fw'"
    Check 'service is running' ($svc -and $svc.State -eq 'Running') "$($svc | Format-List | Out-String)"
    Check 'service runs as LocalSystem' ($svc -and $svc.StartName -eq 'LocalSystem') $svc.StartName
    Check 'service starts automatically' ($svc -and $svc.StartMode -eq 'Auto') $svc.StartMode
    Check 'service runs the protected copy, not the build output' (
        $svc -and $svc.PathName -like "*$home_\gatewizz.exe*" -and $svc.PathName -notlike "*$(Split-Path $Exe)*") $svc.PathName
    Check 'executable and config are in Program Files' (
        (Test-Path (Join-Path $home_ 'gatewizz.exe')) -and (Test-Path (Join-Path $home_ 'firewall.toml')))

    # Users must not be able to write the service's files.
    $acl = Get-Acl $home_
    $userWrite = $acl.Access | Where-Object {
        $_.IdentityReference -match 'Users|Everyone|Authenticated' -and $_.AccessControlType -eq 'Allow' -and
        ($_.FileSystemRights.ToString() -match 'Write|Modify|FullControl|CreateFiles')
    }
    Check 'Program Files\Gatewizz is not writable by users' (-not $userWrite) ($userWrite | Out-String)

    # Self allows for both copies, the service's and this build's, on two layers each (4), plus the one IPv4 block.
    # The service applies before it reports running, so they are in force when install returns.
    $count = Filter-Count
    $expected = 2 * 2 + 1
    Check 'filters installed by the service' ($count -eq $expected) "filters: $count, expected $expected"
    $appliedAtStart = Applied-Count
    Check 'service log records the first refresh' ($appliedAtStart -ge 1) "applied lines: $appliedAtStart"

    $r = Invoke-Gatewizz @('firewall', 'apply', '--config', $two)
    Check 'firewall apply with the service installed succeeds' ($r.Code -eq 0 -and $r.Text -match 'service') $r.Text
    Check 'protected config was updated' ((Get-Content -Raw (Join-Path $home_ 'firewall.toml')) -match 'smoke-block-two')
    Check 'apply added the second rule' ((Filter-Count) -eq $count + 1) "filters: $(Filter-Count)"

    # The reload request makes the service refresh on its own; its log gets another "Applied" line.
    $reloaded = Wait-Until { (Applied-Count) -gt $appliedAtStart }
    Check 'service refreshed after the reload request' $reloaded "$(Get-Content -Raw (Join-Path $home_ 'service.log'))"

    # Restarting keeps the rules, read from the protected copy. Restart-Service returns once the service reports
    # running, and it applies before that.
    Restart-Service gatewizz-fw
    Check 'filters survive a service restart' ((Filter-Count) -eq $count + 1) "filters: $(Filter-Count)"

    $r = Invoke-Gatewizz @('firewall', 'status')
    Check 'status shows the running service' ($r.Code -eq 0 -and $r.Text -match 'running') $r.Text
}
finally {
    $r = Invoke-Gatewizz @('firewall', 'remove')
    Check 'firewall remove succeeds' ($r.Code -eq 0) $r.Text
    Check 'service is gone' (-not (Get-Service gatewizz-fw -ErrorAction SilentlyContinue))
    Check 'no filters are left' ((Invoke-Gatewizz @('firewall', 'status')).Text -match 'filters: not installed')
    Check 'Program Files\Gatewizz is gone' (-not (Test-Path $home_))
    $r = Invoke-Gatewizz @('firewall', 'remove')
    Check 'firewall remove is idempotent' ($r.Code -eq 0) $r.Text
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if ($failures.Count) { throw "$($failures.Count) check(s) failed: $($failures -join '; ')" }
Write-Host 'All firewall service checks passed.'
