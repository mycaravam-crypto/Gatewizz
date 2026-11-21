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
# With -WinDivertDir (CI passes the verified WinDivert 2.2.2-A x64 directory), it also checks holding (#60): a held
# connection completes after "allow once", and one answered "deny always" is refused at once.
param([Parameter(Mandatory)] [string] $Exe, [string] $WinDivertDir = $env:GATEWIZZ_WINDIVERT_DIR)
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
id = "smoke-ask-two"
ip = ["192.0.2.2"]
port = [9]
action = "ask"

[[connection_rules]]
id = "smoke-block-three"
ip = ["192.0.2.3"]
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

    # A connection the rule blocks shows up in the service log, named by program and destination.
    & curl.exe -s -o NUL --max-time 5 http://192.0.2.1:9/ 2>$null
    $blockedLogged = Wait-Until {
        $log = Join-Path $home_ 'service.log'
        (Test-Path $log) -and ((Get-Content -Raw $log) -match 'blocked: curl\.exe -> 192\.0\.2\.1:9 tcp')
    }
    Check 'service logs the blocked connection' $blockedLogged "$(Get-Content -Raw (Join-Path $home_ 'service.log'))"

    $r = Invoke-Gatewizz @('firewall', 'apply', '--config', $two)
    Check 'firewall apply with the service installed succeeds' ($r.Code -eq 0 -and $r.Text -match 'service') $r.Text
    Check 'protected config was updated' ((Get-Content -Raw (Join-Path $home_ 'firewall.toml')) -match 'smoke-ask-two')
    Check 'apply added the two new rules' ((Filter-Count) -eq $count + 2) "filters: $(Filter-Count)"

    # The reload request makes the service refresh on its own; its log gets another "Applied" line.
    $reloaded = Wait-Until { (Applied-Count) -gt $appliedAtStart }
    Check 'service refreshed after the reload request' $reloaded "$(Get-Content -Raw (Join-Path $home_ 'service.log'))"

    # Without --config, apply re-applies the installed rules; it must never replace them with an empty set.
    $r = Invoke-Gatewizz @('firewall', 'apply')
    Check 'apply without --config keeps the installed rules' (
        $r.Code -eq 0 -and (Filter-Count) -eq $count + 2 -and
        (Get-Content -Raw (Join-Path $home_ 'firewall.toml')) -match 'smoke-ask-two') "$($r.Text) filters: $(Filter-Count)"

    # Restarting keeps the rules, read from the protected copy. Restart-Service returns once the service reports
    # running, and it applies before that.
    Restart-Service gatewizz-fw
    Check 'filters survive a service restart' ((Filter-Count) -eq $count + 2) "filters: $(Filter-Count)"

    # The prompt loop over the pipe, as the tray app will run it: a connection blocked by an ask rule becomes a
    # notice, and an "allow once" answer becomes a temporary rule, i.e. one more filter. A block rule stays silent.
    Check 'service serves the prompt pipe' ([bool](Get-ChildItem '\\.\pipe\' | Where-Object Name -eq 'gatewizz-fw'))
    # Asynchronous: synchronous I/O on one pipe handle is serialized, so a pending read would block a write.
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'gatewizz-fw', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
    $pipe.Connect(5000)
    $reader = New-Object System.IO.StreamReader($pipe)
    $writer = New-Object System.IO.StreamWriter($pipe)
    $writer.AutoFlush = $true
    $before = Filter-Count
    $pending = $reader.ReadLineAsync()
    # 192.0.2.3:9 is blocked by smoke-block-three: logged, never offered. Drops are handled in order, so had it
    # been offered, its notice would arrive before the one below.
    & curl.exe -s -o NUL --max-time 5 http://192.0.2.3:9/ 2>$null
    # 192.0.2.2:9 is blocked by smoke-ask-two and has not been tried yet, so this attempt is a new notice.
    & curl.exe -s -o NUL --max-time 5 http://192.0.2.2:9/ 2>$null
    $notice = if ($pending.Wait(20000)) { $pending.Result | ConvertFrom-Json } else { $null }
    Check 'a blocked connection reaches the pipe as a notice' (
        $notice -and $notice.type -eq 'notice' -and $notice.program -eq 'curl.exe' -and $notice.port -eq 9 -and
        $notice.remote -eq '192.0.2.2') "$($notice | ConvertTo-Json -Compress)"
    Check 'a block rule is logged, not offered' (
        (Get-Content -Raw (Join-Path $home_ 'service.log')) -match 'blocked: curl\.exe -> 192\.0\.2\.3:9 tcp') "$(Get-Content -Raw (Join-Path $home_ 'service.log'))"
    if ($notice) {
        $writer.WriteLine((@{ type = 'decision'; id = $notice.id; action = 'allow'; lasting = 'once' } | ConvertTo-Json -Compress))
        $pending = $reader.ReadLineAsync()
        $result = if ($pending.Wait(20000)) { $pending.Result | ConvertFrom-Json } else { $null }
        Check 'the decision is accepted' ($result -and $result.type -eq 'result' -and $result.ok) "$($result | ConvertTo-Json -Compress)"
        Check 'the temporary rule adds its filter' (Wait-Until { (Filter-Count) -eq $before + 1 }) "filters: $(Filter-Count), before $before"
        # A made-up id is refused: the service only accepts answers to notices it sent.
        $writer.WriteLine((@{ type = 'decision'; id = 999999; action = 'allow'; lasting = 'always' } | ConvertTo-Json -Compress))
        $pending = $reader.ReadLineAsync()
        $forged = if ($pending.Wait(20000)) { $pending.Result | ConvertFrom-Json } else { $null }
        Check 'a forged decision is refused' ($forged -and -not $forged.ok -and $forged.message -match 'unknown') "$($forged | ConvertTo-Json -Compress)"
    }
    $pipe.Dispose()
    Check 'the protected config is unchanged by temporary and forged decisions' (
        -not ((Get-Content -Raw (Join-Path $home_ 'firewall.toml')) -match 'prompt-'))

    # Holding (#60): the next connections an ask rule covers wait for the answer instead of failing.
    if ($WinDivertDir) {
        foreach ($f in 'WinDivert.dll', 'WinDivert64.sys') { Copy-Item (Join-Path $WinDivertDir $f) (Split-Path $Exe) -Force }
        $target = ([System.Net.Dns]::GetHostAddresses('example.com') | Where-Object AddressFamily -eq 'InterNetwork' | Select-Object -First 1).ToString()
        $three = Join-Path $work 'three.toml'
        # The [firewall] table comes before the [[connection_rules]] tables.
        Set-Content -Path $three -Value ("[firewall]`nhold = true`n`n" + (Get-Content -Raw $two) + @"

[[connection_rules]]
id = "smoke-ask-held"
ip = ["$target"]
port = [80, 443]
protocol = "tcp"
action = "ask"
"@)
        $r = Invoke-Gatewizz @('firewall', 'apply', '--config', $three)
        Check 'apply with hold = true copies the verified WinDivert files' (
            $r.Code -eq 0 -and $r.Text -match 'WinDivert' -and (Test-Path (Join-Path $home_ 'WinDivert64.sys'))) $r.Text
        $holding = Wait-Until { (Test-Path (Join-Path $home_ 'service.log')) -and ((Get-Content -Raw (Join-Path $home_ 'service.log')) -match 'holding new connections') }
        Check 'the service starts holding' $holding "$(Get-Content -Raw (Join-Path $home_ 'service.log'))"

        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'gatewizz-fw', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
        $pipe.Connect(5000)
        $reader = New-Object System.IO.StreamReader($pipe)
        $writer = New-Object System.IO.StreamWriter($pipe)
        $writer.AutoFlush = $true
        function Start-Curl([string] $Url) {
            $out = Join-Path $work ('curl-' + [guid]::NewGuid().ToString('N') + '.txt')
            $p = Start-Process curl.exe -ArgumentList "-s -k -o NUL -w %{http_code} --max-time 25 -H `"Host: example.com`" $Url" -NoNewWindow -PassThru -RedirectStandardOutput $out
            [pscustomobject]@{ Process = $p; Out = $out; Started = Get-Date }
        }
        function Wait-Curl($c) {
            $null = $c.Process.WaitForExit(30000)
            [pscustomobject]@{ Status = (Get-Content -Raw $c.Out -ErrorAction SilentlyContinue); Seconds = ((Get-Date) - $c.Started).TotalSeconds }
        }

        # Allow once: the held connection simply completes.
        $pending = $reader.ReadLineAsync()
        $c = Start-Curl "http://${target}:80/"
        $notice = if ($pending.Wait(20000)) { $pending.Result | ConvertFrom-Json } else { $null }
        Check 'a held connection reaches the pipe as a held notice' (
            $notice -and $notice.held -and $notice.remote -eq $target -and $notice.port -eq 80 -and $notice.program -eq 'curl.exe') "$($notice | ConvertTo-Json -Compress)"
        if ($notice) {
            Start-Sleep -Seconds 2
            $writer.WriteLine((@{ type = 'decision'; id = $notice.id; action = 'allow'; lasting = 'once' } | ConvertTo-Json -Compress))
            $result = Wait-Curl $c
            Check 'allowed, the held connection completes without curl retrying' ($result.Status -and $result.Status -ne '000' -and $result.Seconds -ge 2) "status $($result.Status) after $($result.Seconds) s"
        }

        # Deny always: the held connection is refused at once, not left to time out.
        $pending = $reader.ReadLineAsync()
        $c = Start-Curl "https://${target}:443/"
        $notice = $null
        while ($pending.Wait(20000)) {
            $m = $pending.Result | ConvertFrom-Json
            if ($m.type -eq 'notice') { $notice = $m; break }
            # The result of the earlier decision may come first.
            $pending = $reader.ReadLineAsync()
        }
        Check 'a second held connection is noticed' ($notice -and $notice.held -and $notice.port -eq 443) "$($notice | ConvertTo-Json -Compress)"
        if ($notice) {
            $writer.WriteLine((@{ type = 'decision'; id = $notice.id; action = 'block'; lasting = 'always' } | ConvertTo-Json -Compress))
            $result = Wait-Curl $c
            Check 'denied, the held connection is refused at once' ($result.Status -eq '000' -and $result.Seconds -lt 20) "status $($result.Status) after $($result.Seconds) s"
        }
        $pipe.Dispose()
        $log = Get-Content -Raw (Join-Path $home_ 'service.log')
        Check 'the service log records the hold, the release and the refusal' (
            $log -match 'holding: curl\.exe' -and $log -match 'released: curl\.exe' -and $log -match 'refused \(denied\): curl\.exe') $log
    }

    $r = Invoke-Gatewizz @('firewall', 'status')
    Check 'status shows the running service' ($r.Code -eq 0 -and $r.Text -match 'running') $r.Text
}
finally {
    $r = Invoke-Gatewizz @('firewall', 'remove')
    Check 'firewall remove succeeds' ($r.Code -eq 0) $r.Text
    Check 'service is gone' (-not (Get-Service gatewizz-fw -ErrorAction SilentlyContinue))
    Check 'no filters are left' ((Invoke-Gatewizz @('firewall', 'status')).Text -match 'filters: not installed')
    Check 'Program Files\Gatewizz is gone' (-not (Test-Path $home_))
    $driver = Get-Service WinDivert -ErrorAction SilentlyContinue
    Check 'the WinDivert driver is not left running' (-not $driver -or $driver.Status -ne 'Running') "$($driver.Status)"
    $r = Invoke-Gatewizz @('firewall', 'remove')
    Check 'firewall remove is idempotent' ($r.Code -eq 0) $r.Text
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if ($failures.Count) { throw "$($failures.Count) check(s) failed: $($failures -join '; ')" }
Write-Host 'All firewall service checks passed.'
