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

    # One rule, no address-less filters: the self allows for both copies (two layers each) plus the IPv4 block.
    $count = Filter-Count
    Check 'filters installed by the service' ($count -ge 3) "filters: $count"

    $r = Invoke-Gatewizz @('firewall', 'apply', '--config', $two)
    Check 'firewall apply with the service installed succeeds' ($r.Code -eq 0 -and $r.Text -match 'service') $r.Text
    Check 'protected config was updated' ((Get-Content -Raw (Join-Path $home_ 'firewall.toml')) -match 'smoke-block-two')
    Check 'apply added the second rule' ((Filter-Count) -eq $count + 1) "filters: $(Filter-Count)"

    # The service re-reads the protected config on its own; its log shows each refresh.
    Start-Sleep -Seconds 2
    $log = Join-Path $home_ 'service.log'
    Check 'service log records a successful refresh' (
        (Test-Path $log) -and ((Get-Content -Raw $log) -match 'Applied')) "$(if (Test-Path $log) { Get-Content -Raw $log })"

    # Restarting the service keeps the rules: it reads the protected copy.
    Restart-Service gatewizz-fw
    Start-Sleep -Seconds 2
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
