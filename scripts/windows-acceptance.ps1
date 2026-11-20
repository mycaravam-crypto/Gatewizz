# Gatewizz manual acceptance on a real Windows machine: the checks left open in #17 (M1), #22 (M2), #35 (M3 approval
# and tray) and #36 (M3.1 background application). Everything that can be measured is measured; what only a person
# can see (the icon, the tray, a window flash) is asked as a y/n/s question. The result is a Markdown report to paste
# into the issues.
#
#   powershell -ExecutionPolicy Bypass -File scripts\windows-acceptance.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\windows-acceptance.ps1 -SmartwizzRepo C:\src\some-repo
#
# The script uses its own config, listen port and event file under %TEMP%, so your configuration and event log are
# not touched. It needs about 10 minutes and these hosts: example.com, example.net, example.org.
#
# Parameters:
#   -Exe            gatewizz.exe to test (default: the README install location)
#   -Port           test listen port (default 18899, so it never clashes with your 8899 setup)
#   -SmartwizzRepo  a git checkout with changed source files; runs `smartwizz check` through Gatewizz (#17)
#   -SkipCa         skip the HTTPS interception and secret-routing part (#22), which adds and removes the CA
#   -SkipApproval   skip the interactive approval and tray part (#35)
#   -Report         where to write the Markdown report
param(
    [string] $Exe = (Join-Path $env:LOCALAPPDATA 'Programs\Gatewizz\gatewizz.exe'),
    [int] $Port = 18899,
    [string] $SmartwizzRepo = '',
    [switch] $SkipCa,
    [switch] $SkipApproval,
    [string] $Report = (Join-Path (Get-Location) ("gatewizz-acceptance-{0:yyyyMMdd-HHmm}.md" -f (Get-Date)))
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

if (-not (Test-Path -LiteralPath $Exe)) { throw "gatewizz.exe not found at $Exe; pass -Exe <path>." }
$Exe = (Resolve-Path -LiteralPath $Exe).Path
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { throw 'curl.exe is required (it ships with Windows 10 1803 and later).' }

$work = Join-Path $env:TEMP ('gatewizz-acceptance-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$events = Join-Path $work 'events.jsonl'
$proxy = "http://127.0.0.1:$Port"
$me = "$env:USERDOMAIN\$env:USERNAME"
$results = New-Object System.Collections.Generic.List[object]
$evidence = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------- helpers

function Record([string] $Issue, [string] $Name, [string] $Status, [string] $Detail = '') {
    $results.Add([pscustomobject]@{ Issue = $Issue; Name = $Name; Status = $Status; Detail = $Detail })
    $color = @{ pass = 'Green'; fail = 'Red'; skip = 'Yellow' }[$Status]
    Write-Host ('{0,-4} #{1}  {2}' -f $Status.ToUpper(), $Issue, $Name) -ForegroundColor $color
    if ($Detail -and $Status -eq 'fail') { Write-Host "      $Detail" -ForegroundColor DarkGray }
}

function Check([string] $Issue, [string] $Name, [bool] $Ok, [string] $Detail = '') {
    Record $Issue $Name ($(if ($Ok) { 'pass' } else { 'fail' })) $Detail
}

function Ask([string] $Issue, [string] $Name, [string] $Question) {
    do { $a = (Read-Host "  ? $Question [y]es/[n]o/[s]kip").Trim().ToLower() } while ($a -notin 'y', 'n', 's')
    Record $Issue $Name (@{ y = 'pass'; n = 'fail'; s = 'skip' }[$a])
}

function Step([string] $Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Say([string] $Text) { Write-Host "  > $Text" -ForegroundColor White }

function Quote([string] $Value) { '"' + $Value + '"' }

function Invoke-Gatewizz([string[]] $Arguments) {
    $ErrorActionPreference = 'Continue'   # usage errors on stderr are expected
    $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = $out }
}

function Test-Port {
    $client = New-Object System.Net.Sockets.TcpClient
    try { $client.Connect('127.0.0.1', $Port); $true } catch { $false } finally { $client.Dispose() }
}

function Wait-Until([scriptblock] $Condition, [int] $Seconds = 20) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 250
    }
    [bool](& $Condition)
}

function Write-Config([string] $Name, [string] $Body) {
    $path = Join-Path $work $Name
    # TOML literal strings ('...') keep Windows backslashes as they are.
    $text = "[general]`nlisten = `"127.0.0.1:$Port`"`n[events]`npath = '$events'`n" + $Body
    [System.IO.File]::WriteAllText($path, $text)
    $path
}

function Start-Gatewizz([string] $Config) {
    $p = Start-Process -FilePath $Exe -ArgumentList @('--config', (Quote $Config)) -PassThru
    if (-not (Wait-Until { Test-Port } 20)) { throw "Gatewizz did not start listening on $proxy (config $Config)." }
    $p
}

function Stop-Gatewizz {
    Get-Process -Name gatewizz -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe } | Stop-Process -Force
    $null = Wait-Until { -not (Test-Port) } 10
}

# Extra curl.exe flags for intercepted HTTPS; set when Schannel's revocation check rejects the local CA's leaves.
$script:curlTls = @()

# Runs curl.exe through the test proxy; returns the HTTP status and curl's PID. -Background returns at once.
function Invoke-Curl([string[]] $Arguments, [switch] $Background) {
    $out = Join-Path $work ('curl-' + [guid]::NewGuid().ToString('N') + '.txt')
    $all = @('-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '90', '-x', $proxy) + $script:curlTls + $Arguments
    # Start-Process joins arguments with spaces and does not quote them itself.
    $all = $all | ForEach-Object { if ($_ -match '\s') { Quote $_ } else { $_ } }
    $p = Start-Process -FilePath curl.exe -ArgumentList $all -NoNewWindow -PassThru -RedirectStandardOutput $out -Wait:(-not $Background)
    [pscustomobject]@{ Process = $p; Pid = $p.Id; Out = $out }
}

function Get-Status($Call) {
    $Call.Process.WaitForExit()
    if (Test-Path $Call.Out) { (Get-Content -Raw $Call.Out).Trim() } else { '' }
}

function Read-GwEvents {
    if (-not (Test-Path $events)) { return @() }
    @(Get-Content -LiteralPath $events | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}

function Find-GwEvent([scriptblock] $Where, [int] $Seconds = 10) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $found = @(Read-GwEvents | Where-Object $Where) | Select-Object -Last 1
        if ($found) { return $found }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    $null
}

function Format-GwEvent($Ev) {
    if (-not $Ev) { return '(no event)' }
    ($Ev | ConvertTo-Json -Compress -Depth 6).Replace($env:USERNAME, '<user>')
}

# ---------------------------------------------------------------- preflight

$version = (Invoke-Gatewizz @('--version')).Text.Trim()
Write-Host "Gatewizz acceptance: $version at $Exe" -ForegroundColor Cyan
Write-Host "Work directory: $work"

$running = @(Get-Process -Name gatewizz -ErrorAction SilentlyContinue)
if ($running) {
    Say 'Gatewizz is already running. Only one instance runs per Windows session, so quit it first'
    Say '(tray icon > Quit). The script waits.'
    $null = Wait-Until { -not (Get-Process -Name gatewizz -ErrorAction SilentlyContinue) } 300
    if (Get-Process -Name gatewizz -ErrorAction SilentlyContinue) { throw 'Gatewizz is still running.' }
}

# ---------------------------------------------------------------- #36: CLI from a console

Step '#36 CLI subcommands from a console'
$r = Invoke-Gatewizz @('--version')
Check 36 '--version prints the version' ($r.Code -eq 0 -and $r.Text -match '^gatewizz \d+\.\d+\.\d+') $r.Text
$r = Invoke-Gatewizz @('--help')
Check 36 '--help lists ca and startup subcommands' ($r.Code -eq 0 -and $r.Text -match 'ca install' -and $r.Text -match 'startup status') $r.Text
$plain = Write-Config 'plain.toml' ''
$r = Invoke-Gatewizz @('--config', $plain, '--check-config')
Check 36 '--check-config prints the effective config' ($r.Code -eq 0 -and $r.Text -match '\[general\]') $r.Text
$r = Invoke-Gatewizz @('startup', 'status')
Check 36 'startup status answers' ($r.Code -eq 0 -and $r.Text -match 'Gatewizz') $r.Text
$r = Invoke-Gatewizz @('--bogus')
Check 36 'a usage error exits 2 and says why' ($r.Code -eq 2 -and $r.Text -match '\[usage\]') $r.Text
Say 'Now printed straight to this console, not captured:'
# PowerShell does not wait for a GUI-subsystem exe started with &, so share the console and wait explicitly.
Start-Process -FilePath $Exe -ArgumentList '--version' -NoNewWindow -Wait
Ask 36 'CLI output is visible in the console' 'Did "gatewizz x.y.z" appear on the line above?'

# ---------------------------------------------------------------- #36: icon, single instance

Step '#36 icon and single instance'
$main = Start-Gatewizz $plain
Check 36 "starts and listens on $proxy" $true
Start-Process explorer.exe -ArgumentList "/select,$(Quote $Exe)"
Ask 36 'Explorer shows the embedded icon' 'An Explorer window opened on gatewizz.exe. Does it show the Gatewizz icon (not a generic exe icon)?'
Ask 36 'tray shows the icon' 'Is the Gatewizz icon in the notification area (check the ^ overflow too)?'
Ask 36 'no window flash on start' 'Did Gatewizz start without showing or flashing its window?'

$second = Start-Process -FilePath $Exe -ArgumentList @('--config', (Quote $plain)) -PassThru -Wait
$instances = @(Get-Process -Name gatewizz -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe })
$listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
Check 36 'second launch exits 0 and leaves one process and one listener' (
    $second.ExitCode -eq 0 -and $instances.Count -eq 1 -and $listeners.Count -eq 1) "exit $($second.ExitCode), processes $($instances.Count), listeners $($listeners.Count)"
Ask 36 'still one tray icon' 'Is there still exactly one Gatewizz tray icon?'

# ---------------------------------------------------------------- #17: attribution and event privacy

Step '#17 process attribution and event privacy'
$http = Invoke-Curl @('-H', 'X-Acceptance: header-value-must-not-be-logged', 'http://example.com/?q=query-must-not-be-logged')
Check 17 'plain HTTP through the proxy' ((Get-Status $http) -eq '200') "status $(Get-Status $http)"
$https = Invoke-Curl @('https://example.com/?q=query-must-not-be-logged')
Check 17 'HTTPS (CONNECT tunnel) through the proxy' ((Get-Status $https) -eq '200') "status $(Get-Status $https)"

$e = Find-GwEvent { $_.method -eq 'GET' -and $_.host -eq 'example.com' }
$known = if ($e -and $e.process.PSObject.Properties['known']) { $e.process.known } else { $null }
Check 17 'event shows the client PID' ($known -and $known.pid -eq $http.Pid) (Format-GwEvent $e)
Check 17 'event shows the image path' ($known -and $known.image -like '*\curl.exe') (Format-GwEvent $e)
Check 17 'event shows the user' ($known -and $known.user -eq $me) (Format-GwEvent $e)
$evidence.Add("HTTP request event: ``$(Format-GwEvent $e)``")
$t = Find-GwEvent { $_.method -eq 'CONNECT' -and $_.host -eq 'example.com' }
Check 17 'CONNECT event with coverage tunneled' ($t -and $t.coverage -eq 'tunneled') (Format-GwEvent $t)
$evidence.Add("CONNECT tunnel event: ``$(Format-GwEvent $t)``")
$raw = if (Test-Path $events) { Get-Content -Raw $events } else { '' }
Check 17 'no query string or header value in the event log' (
    $raw -and $raw -notmatch 'must-not-be-logged') 'the event file contains a query string or header value'

if ($SmartwizzRepo) {
    if (-not (Get-Command smartwizz -ErrorAction SilentlyContinue)) {
        Record 17 'smartwizz review through Gatewizz' 'skip' 'smartwizz is not on PATH'
    } else {
        Say "Running smartwizz check in $SmartwizzRepo through $proxy ..."
        $env:HTTPS_PROXY = $proxy; $env:HTTP_PROXY = $proxy
        Push-Location $SmartwizzRepo
        try { $ErrorActionPreference = 'Continue'; smartwizz check 2>&1 | Tee-Object -Variable sw | Out-Host; $swCode = $LASTEXITCODE }
        finally { Pop-Location; $ErrorActionPreference = 'Stop'; Remove-Item Env:HTTPS_PROXY, Env:HTTP_PROXY }
        $s = Find-GwEvent { $_.process.PSObject.Properties['known'] -and $_.process.known.image -match '(smartwizz|dotnet)\.exe$' }
        Check 17 'smartwizz request attributed to smartwizz/dotnet' ([bool]$s) (Format-GwEvent $s)
        $evidence.Add("smartwizz exit code $swCode; event: ``$(Format-GwEvent $s)``")
        Ask 17 'smartwizz reviewed at least one file' 'Did smartwizz report one or more reviewed files (not 0)?'
    }
} else {
    Record 17 'smartwizz review through Gatewizz' 'skip' 'rerun with -SmartwizzRepo <checkout with changes>'
}

# ---------------------------------------------------------------- #36: startup removal

Step '#36 startup removal'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$before = (Get-ItemProperty -Path $runKey -Name Gatewizz -ErrorAction SilentlyContinue)
$before = if ($before) { $before.Gatewizz } else { $null }
$r = Invoke-Gatewizz @('startup', 'install', '--config', $plain)
$r2 = Invoke-Gatewizz @('startup', 'remove')
$after = Get-ItemProperty -Path $runKey -Name Gatewizz -ErrorAction SilentlyContinue
Check 36 'startup remove deletes the Run entry' ($r.Code -eq 0 -and $r2.Code -eq 0 -and -not $after) $r2.Text
if ($before) {
    Say "Your startup entry was: $before"
    do { $keep = (Read-Host '  ? Leave startup removed so you can confirm at your next sign-in that Gatewizz does NOT start? [y/n]').Trim().ToLower() } while ($keep -notin 'y', 'n')
    if ($keep -eq 'n') { Set-ItemProperty -Path $runKey -Name Gatewizz -Value $before; Say 'Startup entry restored.' }
    else { Say 'After the next sign-in, restore it with: gatewizz startup install --config <your config>' }
}

# ---------------------------------------------------------------- #22: TLS interception and secret routing

Stop-Gatewizz
if ($SkipCa) {
    Record 22 'TLS interception and secret routing' 'skip' '-SkipCa'
} else {
    Step '#22 TLS interception and secret routing'
    $caFile = Join-Path $env:LOCALAPPDATA 'gatewizz\ca.cer'
    $hadCa = Test-Path $caFile
    Say 'Windows will ask to trust the Gatewizz CA (current user only). Answer Yes.'
    $r = Invoke-Gatewizz @('ca', 'install')
    Check 22 'ca install' ($r.Code -eq 0 -and (Test-Path $caFile)) $r.Text

    $tls = Write-Config 'tls.toml' @'
[tls]
intercept = true
tunnel_hosts = ["example.org"]

[[rules]]
id = "secrets-only-to-approved-models"
description = "Secrets may only be sent to the approved model host"
match = { finding = "secret.*", not_host = ["example.com"] }
action = "block"
severity = "critical"
'@
    $null = Start-Gatewizz $tls

    $get = Invoke-Curl @('https://example.com/?q=query-must-not-be-logged')
    $status = Get-Status $get
    if ($status -eq '000') {
        # Schannel fails closed when it cannot check revocation, and the local CA's leaves carry no CRL or OCSP URL.
        $script:curlTls = @('--ssl-revoke-best-effort')
        $get = Invoke-Curl @('https://example.com/?q=query-must-not-be-logged')
        $retry = Get-Status $get
        Check 22 'curl.exe (Schannel) accepts the intercepted certificate' $false (
            "status 000 by default; $retry with --ssl-revoke-best-effort (leaf certificates have no CRL/OCSP)")
    } else {
        Check 22 'curl.exe (Schannel) accepts the intercepted certificate' ($status -eq '200') "status $status"
    }
    $e = Find-GwEvent { $_.method -eq 'GET' -and $_.host -eq 'example.com' -and $_.coverage -eq 'inspected' }
    Check 22 'decrypted request logged with path, without query' ($e -and $e.path -eq '/') (Format-GwEvent $e)
    try {
        $iwr = Invoke-WebRequest -Uri 'https://example.com/' -Proxy $proxy -UseBasicParsing
        Check 22 '.NET client accepts the intercepted certificate' ($iwr.StatusCode -eq 200)
    } catch { Check 22 '.NET client accepts the intercepted certificate' $false "$_" }
    $tun = Invoke-Curl @('https://example.org/')
    $e = Find-GwEvent { $_.method -eq 'CONNECT' -and $_.host -eq 'example.org' }
    Check 22 'tunnel_hosts entry stays tunneled' ((Get-Status $tun) -eq '200' -and $e -and $e.coverage -eq 'tunneled') (Format-GwEvent $e)

    # A fake GitHub-format token, generated here so no token-shaped literal lives in the repository.
    $chars = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $key = 'gh' + 'p_' + -join (1..36 | ForEach-Object { $chars | Get-Random })
    $secretDir = Join-Path $env:TEMP ('gatewizz-secret-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $secretDir | Out-Null
    $bodyFile = Join-Path $secretDir 'body.json'
    $body = @{ model = 'gpt-test'; messages = @(@{ role = 'user'; content = "Review this diff:`n+const TOKEN = `"$key`";`n" }) } | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($bodyFile, $body)
    $post = @('-H', 'Content-Type: application/json', '--data-binary', ('@' + $bodyFile))

    $blocked = Invoke-Curl ($post + @('https://example.net/v1/chat/completions'))
    $e = Find-GwEvent { $_.method -eq 'POST' -and $_.host -eq 'example.net' }
    Check 22 'secret to a host outside the allowlist: 403 naming the rule' (
        (Get-Status $blocked) -eq '403' -and $e -and $e.rule -eq 'secrets-only-to-approved-models') (Format-GwEvent $e)
    $evidence.Add("Blocked secret event: ``$(Format-GwEvent $e)``")
    $passed = Invoke-Curl ($post + @('https://example.com/v1/chat/completions'))
    $e = Find-GwEvent { $_.method -eq 'POST' -and $_.host -eq 'example.com' }
    $kinds = if ($e) { @($e.findings | ForEach-Object { $_.kind }) } else { @() }
    Check 22 'secret to the allowlisted host passes, inspected' (
        (Get-Status $passed) -ne '403' -and $e -and $e.coverage -eq 'inspected' -and $kinds -contains 'secret.github_token') (Format-GwEvent $e)
    $evidence.Add("Allowed secret event: ``$(Format-GwEvent $e)``")
    Remove-Item -Recurse -Force $secretDir

    Stop-Gatewizz
    $hits = @(
        foreach ($dir in @($work, (Join-Path $env:LOCALAPPDATA 'gatewizz'))) {
            if (Test-Path $dir) { Get-ChildItem -LiteralPath $dir -Recurse -File | Select-String -SimpleMatch $key -List }
        })
    Check 22 'the key is nowhere under %LOCALAPPDATA%\gatewizz or the test directory' ($hits.Count -eq 0) (($hits | ForEach-Object Path) -join ', ')

    if ($hadCa) {
        Say 'You had a Gatewizz CA before this run, so it is kept. `gatewizz ca remove` is not tested.'
        Record 22 'ca remove' 'skip' 'CA existed before the run'
    } else {
        Say 'Windows will ask to remove the Gatewizz CA. Answer Yes.'
        $r = Invoke-Gatewizz @('ca', 'remove')
        $left = @(Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'gatewizz' })
        Check 22 'ca remove: no Gatewizz CA left in CurrentUser\Root, files deleted' (
            $r.Code -eq 0 -and $left.Count -eq 0 -and -not (Test-Path $caFile)) $r.Text
    }
}

# ---------------------------------------------------------------- #35: approval, workspace and tray

if ($SkipApproval) {
    Record 35 'approval, workspace and tray' 'skip' '-SkipApproval'
} else {
    Step '#35 approval workspace and tray'
    $approve = Write-Config 'approve.toml' @'
[approval]
timeout_secs = 20

[[rules]]
id = "acceptance-ask-example-org"
match = { host = ["example.org"] }
action = "approve"
severity = "low"
'@
    $null = Start-Gatewizz $approve
    $url = 'http://example.org/'

    Say 'A request is waiting. The Gatewizz window should open on its own. Click "Allow once".'
    $c = Invoke-Curl @($url) -Background
    Check 35 'Allow once forwards (200)' ((Get-Status $c) -eq '200') "status $(Get-Status $c)"
    Ask 35 'tray icon changed colour while waiting' 'Did the tray icon change colour while the request was waiting?'

    Say 'Next request: click "Deny".'
    $c = Invoke-Curl @($url) -Background
    Check 35 'Deny blocks (403)' ((Get-Status $c) -eq '403') "status $(Get-Status $c)"

    Say 'Next request: do NOT answer. It times out after 20 seconds.'
    $c = Invoke-Curl @($url) -Background
    Check 35 'unanswered request times out and is blocked' ((Get-Status $c) -eq '403') "status $(Get-Status $c)"

    Say 'Next request: close the Gatewizz window with its X button.'
    $c = Invoke-Curl @($url) -Background
    Check 35 'closing the workspace denies the waiting request' ((Get-Status $c) -eq '403') "status $(Get-Status $c)"
    Ask 35 'closing hides to the tray' 'Did the window disappear while the tray icon stayed?'

    Say 'Next request: click "Hide to tray" in the status bar, then click the tray icon to reopen it, and click "Allow once".'
    $c = Invoke-Curl @($url) -Background
    Check 35 'Hide to tray keeps the request waiting; tray click reopens it' ((Get-Status $c) -eq '200') "status $(Get-Status $c)"

    Say 'Right-click the tray icon and choose Pause. Press Enter when paused.'
    $null = Read-Host
    $c = Invoke-Curl @($url)
    Check 35 'Pause (tray menu) blocks requests that need approval' ((Get-Status $c) -eq '403') "status $(Get-Status $c)"
    $c = Invoke-Curl @('http://example.com/')
    Check 35 'Pause does not block requests without an approve rule' ((Get-Status $c) -eq '200') "status $(Get-Status $c)"
    Ask 35 'paused state is visible' 'Does the tray icon and the window show the paused state (banner with Resume)?'
    Say 'Resume, using either the tray menu or the status bar.'

    Say 'Next request: choose a timed grant of 5 min and allow it. A second request should then pass without a prompt.'
    $c = Invoke-Curl @($url) -Background
    Check 35 'Allow for N minutes forwards (200)' ((Get-Status $c) -eq '200') "status $(Get-Status $c)"
    $c = Invoke-Curl @($url)
    Check 35 'a matching request within the grant passes without a prompt' ((Get-Status $c) -eq '200') "status $(Get-Status $c)"

    Say 'Right-click the tray icon and choose "Copy proxy address". Press Enter.'
    $null = Read-Host
    Check 35 'tray Copy proxy address' ((Get-Clipboard -Raw) -match [regex]::Escape("127.0.0.1:$Port")) "clipboard: $(Get-Clipboard -Raw)"
    Say 'Click "Copy" in the window status bar. Press Enter.'
    $null = Read-Host
    Check 35 'status bar Copy' ((Get-Clipboard -Raw) -match [regex]::Escape("127.0.0.1:$Port")) "clipboard: $(Get-Clipboard -Raw)"

    Say 'Open the Activity tab. Filter on "example.org", pick the Blocked chip, then click "Copy CSV". Press Enter.'
    $null = Read-Host
    $csv = Get-Clipboard -Raw
    $rows = @($csv -split "`r`n" | Where-Object { $_ })
    Check 35 'Activity tab: filtered CSV copy' (
        $rows.Count -ge 2 -and $rows[0] -match 'time_utc' -and -not ($rows | Select-Object -Skip 1 | Where-Object { $_ -notmatch 'example\.org' })) "$($rows.Count) line(s): $($rows | Select-Object -First 3)"
    Ask 35 'Activity details panel' 'Does clicking a row show its details (rule, coverage, reason)?'

    Say 'Choose "Open event log" from the tray menu.'
    Ask 35 'tray Open event log' 'Did the event log open?'

    Say 'Choose "Quit" from the tray menu.'
    $quit = Wait-Until { -not (Get-Process -Name gatewizz -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe }) } 60
    Check 35 'tray Quit stops Gatewizz and its listener' ($quit -and -not (Test-Port))
}

# ---------------------------------------------------------------- #17: Ctrl+C

Step '#17 Ctrl+C shutdown'
Say 'A console window running Gatewizz opens. Press Ctrl+C in it once this script says so.'
# cmd /k keeps the console open; the outer quotes keep cmd from stripping the inner ones.
$cc = Start-Process -FilePath cmd.exe -ArgumentList ('/k "' + (Quote $Exe) + ' --config ' + (Quote $plain) + '"') -PassThru
if (Wait-Until { Test-Port } 20) {
    $last = Invoke-Curl @('http://example.com/?q=query-must-not-be-logged')
    $code = Get-Status $last
    Say 'Now press Ctrl+C in the Gatewizz console window.'
    $stopped = Wait-Until { -not (Get-Process -Name gatewizz -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe }) -and -not (Test-Port) } 120
    $e = Find-GwEvent { $_.method -eq 'GET' -and $_.process.PSObject.Properties['known'] -and $_.process.known.pid -eq $last.Pid } 5
    Check 17 'Ctrl+C stops Gatewizz; the last request is in the event log' ($stopped -and $code -eq '200' -and $e) (Format-GwEvent $e)
    Stop-Process -Id $cc.Id -ErrorAction SilentlyContinue
} else {
    Check 17 'Ctrl+C shutdown' $false 'Gatewizz did not start in the console window'
}
Stop-Gatewizz
$raw = if (Test-Path $events) { Get-Content -Raw $events } else { '' }
Check 17 'whole run: no query string or header value in the event log' ($raw -notmatch 'must-not-be-logged')

# ---------------------------------------------------------------- report

$issueTitles = [ordered]@{
    '17' = 'M1: Windows smoke test'
    '22' = 'M2: secret routing'
    '35' = 'M3: approval window and tray'
    '36' = 'M3.1: icon, manifest and background start'
}
$os = (Get-CimInstance Win32_OperatingSystem)
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("## Windows acceptance run ($(Get-Date -Format 'yyyy-MM-dd HH:mm'))")
$lines.Add('')
$lines.Add("$version, $($os.Caption) $($os.Version), PowerShell $($PSVersionTable.PSVersion). Script: ``scripts/windows-acceptance.ps1``.")
foreach ($issue in $issueTitles.Keys) {
    $rows = @($results | Where-Object { $_.Issue -eq $issue })
    if (-not $rows) { continue }
    $lines.Add('')
    $lines.Add("### #$issue $($issueTitles[$issue])")
    foreach ($row in $rows) {
        $box = @{ pass = '[x]'; fail = '[ ] **FAIL**'; skip = '[ ] skipped' }[$row.Status]
        $note = if ($row.Status -ne 'pass' -and $row.Detail) { ': ' + ($row.Detail.Trim() -replace '\s+', ' ') } else { '' }
        $lines.Add("- $box $($row.Name)$note")
    }
}
if ($evidence.Count) {
    $lines.Add('')
    $lines.Add('### Event lines (metadata only; user name redacted)')
    foreach ($item in $evidence) { $lines.Add("- $item") }
}
[System.IO.File]::WriteAllLines($Report, $lines)
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue

$failed = @($results | Where-Object Status -eq 'fail').Count
$skipped = @($results | Where-Object Status -eq 'skip').Count
Write-Host ''
Write-Host ("{0} passed, {1} failed, {2} skipped. Report: {3}" -f (@($results | Where-Object Status -eq 'pass').Count), $failed, $skipped, $Report) -ForegroundColor $(if ($failed) { 'Red' } else { 'Green' })
