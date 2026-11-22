# Gatewizz manual acceptance on a real Windows machine: the checks left open in #17 (M1), #22 (M2), #35 (M3 approval
# and tray), #36 (M3.1 background application), #57 (connection monitor) and, with -Firewall, #59 (connection
# firewall). Everything that can be measured is measured; what only a person
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
#   -SkipMonitor    skip the connection monitor part (#57)
#   -Firewall       also run the connection firewall part (#59). Needs an elevated prompt (Run as administrator). It
#                   installs the gatewizz-fw service with test rules for curl.exe only and removes it at the end, so
#                   it refuses to run if the firewall is already installed (that would replace your rules).
#                   With WinDivert.dll and WinDivert64.sys (Gatewizz release assets) next to gatewizz.exe, or in
#                   -WinDivertDir, it also checks holding connections while asking (#60).
#   -Report         where to write the Markdown report
param(
    [string] $Exe = (Join-Path $env:LOCALAPPDATA 'Programs\Gatewizz\gatewizz.exe'),
    [int] $Port = 18899,
    [string] $SmartwizzRepo = '',
    [switch] $SkipCa,
    [switch] $SkipApproval,
    [switch] $SkipMonitor,
    [switch] $Firewall,
    [string] $WinDivertDir = '',
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

# Start-Process hands -ArgumentList to the new process as one command line: array items are joined with spaces and
# are not quoted (Windows PowerShell 5.1 and PowerShell 7 alike). So every call below builds that line here, where
# the quoting is visible, and passes a single string.
function Join-CommandLine([string[]] $Arguments) {
    ($Arguments | ForEach-Object { if ($_ -match '[\s"]') { Quote ($_ -replace '"', '\"') } else { $_ } }) -join ' '
}

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
    $p = Start-Process -FilePath $Exe -ArgumentList (Join-CommandLine @('--config', $Config)) -PassThru
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
    $p = Start-Process -FilePath curl.exe -ArgumentList (Join-CommandLine $all) -NoNewWindow -PassThru -RedirectStandardOutput $out -Wait:(-not $Background)
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
        # A record without a property the filter reads (a monitor "connection" line has no method) simply does not
        # match; under Set-StrictMode the bare property access would otherwise end the whole run.
        $found = @(Read-GwEvents | Where-Object { try { & $Where } catch { $false } }) | Select-Object -Last 1
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

$second = Start-Process -FilePath $Exe -ArgumentList (Join-CommandLine @('--config', $plain)) -PassThru -Wait
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

# ---------------------------------------------------------------- #57: connection monitor

Stop-Gatewizz
if ($SkipMonitor) {
    Record 57 'connection monitor' 'skip' '-SkipMonitor'
} else {
    Step '#57 connection monitor'
    $monitorConfig = Write-Config 'monitor.toml' "[monitor]`nenabled = true`npoll_ms = 250`n"
    $null = Start-Gatewizz $monitorConfig
    # Straight out, not through the proxy: only the monitor can see this one. The page is ~1.2 KB, so 500 B/s keeps
    # the connection open for a couple of seconds, well over the sampling interval.
    $direct = Start-Process -FilePath curl.exe -ArgumentList (Join-CommandLine @('-s', '-o', 'NUL', '--limit-rate', '500', '--noproxy', '*', 'https://example.com/')) -NoNewWindow -PassThru -Wait
    $c = Find-GwEvent { $_.PSObject.Properties['kind'] -and $_.kind -eq 'connection' -and $_.state -eq 'opened' -and
        $_.process.PSObject.Properties['known'] -and $_.process.known.pid -eq $direct.Id } 10
    Check 57 'a direct (unproxied) curl.exe connection is logged with its PID and image' (
        $c -and $c.process.known.image -like '*\curl.exe' -and $c.port -eq 443) (Format-GwEvent $c)
    Check 57 'its hostname comes from the DNS cache' ($c -and $c.hostname -eq 'example.com') (Format-GwEvent $c)
    $closed = Find-GwEvent { $_.PSObject.Properties['kind'] -and $_.kind -eq 'connection' -and $_.state -eq 'closed' -and
        $_.process.PSObject.Properties['known'] -and $_.process.known.pid -eq $direct.Id } 10
    Check 57 'and logged as closed once curl.exe exits' ([bool]$closed) (Format-GwEvent $closed)
    $evidence.Add("Monitor event (direct curl.exe): ``$(Format-GwEvent $c)``")
    Say 'Open the Network tab in the Gatewizz window (tray icon).'
    Ask 57 'Network tab lists programs and hosts' 'Does the Network tab show programs (e.g. your browser) with hostnames and New badges?'
    if ($SmartwizzRepo -and (Get-Command smartwizz -ErrorAction SilentlyContinue)) {
        Say 'Run smartwizz now (any command that reaches its model) in another window, then answer.'
        Ask 57 'smartwizz appears with its model host' 'Does the Network tab show smartwizz/dotnet with the model host?'
    }
    $proc = Get-Process -Name gatewizz -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe } | Select-Object -First 1
    if ($proc) {
        $cpu0 = $proc.TotalProcessorTime; Start-Sleep -Seconds 20; $proc.Refresh()
        $pct = (($proc.TotalProcessorTime - $cpu0).TotalSeconds / 20 / [Environment]::ProcessorCount) * 100
        $evidence.Add(('Monitor overhead at poll_ms = 250: {0:N2} % of total CPU over 20 s (Gatewizz process, {1} logical CPUs)' -f $pct, [Environment]::ProcessorCount))
        Record 57 ('CPU at poll_ms = 250 measured: {0:N2} % of total CPU' -f $pct) 'pass'
    }
    Stop-Gatewizz
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

# ---------------------------------------------------------------- #59: connection firewall

if (-not $Firewall) {
    Record 59 'connection firewall' 'skip' 'run with -Firewall from an elevated prompt'
} elseif (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Record 59 'connection firewall' 'skip' 'needs an elevated prompt (Run as administrator)'
} elseif (Get-Service gatewizz-fw -ErrorAction SilentlyContinue) {
    Record 59 'connection firewall' 'skip' 'the firewall is already installed; this part would replace your rules'
} else {
    Step '#59 connection firewall'
    $fwHome = Join-Path $env:ProgramFiles 'Gatewizz'
    $curl = (Get-Command curl.exe).Source
    # A renamed curl copy stands in for a wizz tool: it may reach only the proxy (the proxy-enforcement preset).
    $wizz = Join-Path $work 'wizzcurl.exe'
    Copy-Item -LiteralPath $curl -Destination $wizz
    $fwConfig = Write-Config 'firewall.toml' @"
[[connection_rules]]
id = "acceptance-ask-curl"
process = ['$curl']
action = "ask"

[[connection_rules]]
id = "acceptance-wizz-only-through-gatewizz"
process = ['$wizz']
ip = ["127.0.0.1"]
port = [$Port]
action = "allow"

[[connection_rules]]
id = "acceptance-wizz-nowhere-else"
process = ['$wizz']
action = "block"
"@
    # One fixed address per host, so a retry never lands on another address (which would be a new prompt).
    $pin = @{}
    foreach ($h in 'example.net', 'example.org', 'example.com') {
        $pin[$h] = ([System.Net.Dns]::GetHostAddresses($h) | Where-Object AddressFamily -eq 'InterNetwork' | Select-Object -First 1).ToString()
    }
    # A direct connection, past the proxy; returns curl's HTTP status ("000" when the connection is blocked).
    function Invoke-Direct([string] $Program, [string] $HostName, [int] $ToPort, [string] $Scheme, [int] $MaxTime = 5) {
        $out = Join-Path $work ('direct-' + [guid]::NewGuid().ToString('N') + '.txt')
        $arguments = @('-s', '-k', '-o', 'NUL', '-w', '%{http_code}', '--max-time', "$MaxTime", '--noproxy', '*',
            '--resolve', "${HostName}:${ToPort}:$($pin[$HostName])", "${Scheme}://${HostName}:${ToPort}/")
        Start-Process -FilePath $Program -ArgumentList (Join-CommandLine $arguments) -NoNewWindow -Wait -RedirectStandardOutput $out | Out-Null
        if (Test-Path $out) { (Get-Content -Raw $out).Trim() } else { '' }
    }
    # Missing files read as empty: a failed install then fails its checks instead of ending the run.
    function Read-Text([string] $Path) { if (Test-Path -LiteralPath $Path) { Get-Content -Raw -LiteralPath $Path } else { '' } }
    function Protected-Config { Read-Text (Join-Path $fwHome 'firewall.toml') }

    # The test rules come off again whatever happens, so a failed check never leaves them installed.
    try {
        $r = Invoke-Gatewizz @('firewall', 'install', '--config', $fwConfig)
        Check 59 'firewall install succeeds' ($r.Code -eq 0) $r.Text
        $null = Start-Gatewizz $plain
        Say 'Open the Gatewizz window from the tray icon.'
        Ask 59 'the tray app connects to the service' 'Does the status bar show "Firewall prompt on"?'

        Say 'curl.exe now connects to example.net:80 directly. The window should show it as blocked. Click "Allow once".'
        $first = Invoke-Direct $curl 'example.net' 80 'http'
        Check 59 'an ask rule blocks the first attempt' ($first -eq '000') "status $first"
        $allowed = Wait-Until { (Invoke-Direct $curl 'example.net' 80 'http') -ne '000' } 120
        Check 59 'Allow once lets the retry through' $allowed
        Ask 59 'the blocked connection was shown with program and address' 'Did the queue show curl.exe and the address of example.net, port 80?'

        Say 'Next: example.org:443. Click "Allow always".'
        $null = Invoke-Direct $curl 'example.org' 443 'https'
        $always = Wait-Until { (Invoke-Direct $curl 'example.org' 443 'https') -ne '000' } 120
        Check 59 'Allow always lets the retry through' $always
        Check 59 'Allow always is written to the protected configuration' ((Protected-Config) -match 'prompt-allow-curl\.exe') (Protected-Config)

        Say 'Next: example.com:8080. Click "Deny always".'
        $null = Invoke-Direct $curl 'example.com' 8080 'http'
        $denied = Wait-Until { (Protected-Config) -match 'prompt-block-curl\.exe' } 120
        Check 59 'Deny always is written to the protected configuration' $denied (Protected-Config)
        Start-Sleep -Seconds 2
        Say 'curl.exe tries example.com:8080 again now. Watch the window.'
        $again = Invoke-Direct $curl 'example.com' 8080 'http'
        Check 59 'Deny always keeps blocking' ($again -eq '000') "status $again"
        Ask 59 'Deny always blocks silently' 'Did the second attempt stay out of the queue (no new prompt)?'

        # The service reads the protected configuration again when it starts, as at boot (it starts automatically).
        Restart-Service gatewizz-fw
        Check 59 'Allow always survives a service restart' ((Invoke-Direct $curl 'example.org' 443 'https') -ne '000')
        $svc = Get-CimInstance Win32_Service -Filter "Name='gatewizz-fw'"
        Check 59 'the service starts at boot' ($svc -and $svc.StartMode -eq 'Auto') "$($svc.StartMode)"

        $bypass = Invoke-Direct $wizz 'example.com' 80 'http'
        Check 59 'proxy enforcement: the wizz tool cannot connect past the proxy' ($bypass -eq '000') "status $bypass"
        $through = Start-Process -FilePath $wizz -ArgumentList (Join-CommandLine @('-s', '-o', 'NUL', '--max-time', '30', '-x', $proxy, 'http://example.com/')) -NoNewWindow -Wait -PassThru
        Check 59 'proxy enforcement: the wizz tool reaches the network through Gatewizz' ($through.ExitCode -eq 0) "curl exit $($through.ExitCode)"

        # Holding (#60): with the WinDivert files next to gatewizz.exe, asked-about connections wait for the answer.
        $wdFiles = 'WinDivert.dll', 'WinDivert64.sys'
        $exeDir = Split-Path $Exe
        if ($WinDivertDir) { foreach ($f in $wdFiles) { Copy-Item (Join-Path $WinDivertDir $f) $exeDir -Force } }
        if (@($wdFiles | Where-Object { -not (Test-Path (Join-Path $exeDir $_)) }).Count -eq 0) {
            $holdConfig = Join-Path $work 'firewall-hold.toml'
            Set-Content -Path $holdConfig -Value ((Get-Content -Raw $fwConfig) + "`n[firewall]`nhold = true`n")
            $r = Invoke-Gatewizz @('firewall', 'apply', '--config', $holdConfig)
            Check 60 'apply with hold = true copies the verified WinDivert files' ($r.Code -eq 0 -and (Test-Path (Join-Path $fwHome 'WinDivert64.sys'))) $r.Text
            $holding = Wait-Until { (Read-Text (Join-Path $fwHome 'service.log')) -match 'holding new connections' } 30
            Check 60 'the service holds connections' $holding (Read-Text (Join-Path $fwHome 'service.log'))
            Ask 60 'Microsoft Defender lets WinDivert load' 'Did Windows Security stay quiet about WinDivert (no warning, nothing quarantined)?'

            Say 'curl.exe connects to example.net:443 once and waits. The window shows it as Waiting. Click "Allow once".'
            $started = Get-Date
            $held = Invoke-Direct $curl 'example.net' 443 'https' 30
            Check 60 'allowed, a held connection completes on its first attempt' ($held -ne '000') "status $held after $([int]((Get-Date) - $started).TotalSeconds) s"
            Ask 60 'the held connection showed as Waiting' 'Did the queue show curl.exe to example.net:443 as Waiting (not Blocked)?'

            Say 'Next: example.org:80 waits. Click "Deny always".'
            $started = Get-Date
            $refused = Invoke-Direct $curl 'example.org' 80 'http' 30
            $took = ((Get-Date) - $started).TotalSeconds
            Check 60 'denied, a held connection is refused, not left to time out' ($refused -eq '000' -and $took -lt 25) "status $refused after $([int]$took) s"

            Say 'Next: example.org:8443 waits. Do NOT answer; it is refused after 20 seconds.'
            $started = Get-Date
            $timedOut = Invoke-Direct $curl 'example.org' 8443 'https' 30
            $took = ((Get-Date) - $started).TotalSeconds
            Check 60 'unanswered, a held connection is refused after the hold timeout' ($timedOut -eq '000' -and $took -ge 15 -and $took -lt 25) "status $timedOut after $([int]$took) s"
            $evidence.Add('Hold log lines: ' + ((((Read-Text (Join-Path $fwHome 'service.log')) -split "`n") | Where-Object { $_ -match 'holding:|released:|refused \(' } | Select-Object -Last 4) -join ' | ').Replace($env:USERNAME, '<user>'))
        } else {
            Record 60 'holding connections' 'skip' 'WinDivert.dll and WinDivert64.sys (from the Gatewizz release) are not next to gatewizz.exe; or pass -WinDivertDir'
        }

        $log = Read-Text (Join-Path $fwHome 'service.log')
        $evidence.Add('Firewall service log, blocked lines: ' + ((($log -split "`n") | Where-Object { $_ -match 'blocked:' } | Select-Object -Last 3) -join ' | ').Replace($env:USERNAME, '<user>'))

    } finally {
        Stop-Gatewizz
        $r = Invoke-Gatewizz @('firewall', 'remove')
    }
    Check 59 'firewall remove leaves no service, filters or files' (
        $r.Code -eq 0 -and -not (Get-Service gatewizz-fw -ErrorAction SilentlyContinue) -and -not (Test-Path $fwHome)) $r.Text
}

# ---------------------------------------------------------------- report

$issueTitles = [ordered]@{
    '17' = 'M1: Windows smoke test'
    '22' = 'M2: secret routing'
    '35' = 'M3: approval window and tray'
    '36' = 'M3.1: icon, manifest and background start'
    '57' = 'Firewall Phase 1: connection monitor'
    '59' = 'Firewall Phase 2: connection rules and prompt'
    '60' = 'Firewall Phase 3: holding connections while asking'
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
