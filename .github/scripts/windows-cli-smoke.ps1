# Smoke test of the shipping gatewizz.exe from a console (#36): every CLI subcommand prints and exits as documented,
# and `startup install/status/remove` round-trips the current-user Run entry. It runs in CI after the release build
# and is safe to run by hand; it leaves no Run entry behind (one that existed before is put back).
#
#   pwsh .github/scripts/windows-cli-smoke.ps1 -Exe target\release\gatewizz.exe
param(
    [Parameter(Mandatory)] [string] $Exe,
    [string] $Config = (Join-Path $PSScriptRoot '..\..\config\gatewizz.example.toml')
)
$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path $Exe).Path
$Config = (Resolve-Path $Config).Path
$failures = [System.Collections.Generic.List[string]]::new()

function Invoke-Gatewizz([string[]] $Arguments) {
    # Windows PowerShell 5.1 turns native stderr into errors; usage errors on stderr are expected here.
    $ErrorActionPreference = 'Continue'
    $out = & $Exe @Arguments 2>&1 | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = $out }
}

function Check([string] $Name, [bool] $Ok, [string] $Detail = '') {
    if ($Ok) { Write-Host "ok    $Name" }
    else { Write-Host "FAIL  $Name`n$Detail"; $failures.Add($Name) }
}

$version = (Select-String -Path (Join-Path $PSScriptRoot '..\..\Cargo.toml') -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value

$r = Invoke-Gatewizz '--version'
Check '--version prints the crate version' ($r.Code -eq 0 -and $r.Text.Trim() -eq "gatewizz $version") $r.Text

$r = Invoke-Gatewizz '--help'
$names = 'ca install', 'ca remove', 'startup install', 'startup remove', 'startup status', '--check-config', '--config'
Check '--help names every subcommand' ($r.Code -eq 0 -and -not ($names | Where-Object { -not $r.Text.Contains($_) })) $r.Text

$r = Invoke-Gatewizz '--config', $Config, '--check-config'
Check '--check-config prints the effective config' ($r.Code -eq 0 -and $r.Text -match '\[general\]' -and $r.Text -match 'listen = ') $r.Text

$r = Invoke-Gatewizz '--no-such-flag'
Check 'unknown flag is a usage error (exit 2)' ($r.Code -eq 2 -and $r.Text -match '\[usage\]') $r.Text

$r = Invoke-Gatewizz 'ca'
Check 'ca without an action is a usage error' ($r.Code -eq 2 -and $r.Text -match '\[usage\]') $r.Text

# Startup round trip. Keep whatever Run entry a developer already has.
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$before = (Get-ItemProperty -Path $runKey -Name Gatewizz -ErrorAction SilentlyContinue).Gatewizz
try {
    $null = Invoke-Gatewizz 'startup', 'remove'
    $r = Invoke-Gatewizz 'startup', 'status'
    Check 'startup status reports not registered' ($r.Code -eq 0 -and $r.Text -match 'not registered') $r.Text

    $r = Invoke-Gatewizz 'startup', 'install', '--config', $Config
    $value = (Get-ItemProperty -Path $runKey -Name Gatewizz -ErrorAction SilentlyContinue).Gatewizz
    Check 'startup install writes the Run entry with exe and absolute config' (
        $r.Code -eq 0 -and $value -and $value.Contains("`"$Exe`"") -and $value.Contains("--config `"$Config`"")) "$($r.Text)`nRun value: $value"

    $r = Invoke-Gatewizz 'startup', 'status'
    Check 'startup status shows the registered command' ($r.Code -eq 0 -and $r.Text.Contains($Exe)) $r.Text

    $r = Invoke-Gatewizz 'startup', 'remove'
    $value = (Get-ItemProperty -Path $runKey -Name Gatewizz -ErrorAction SilentlyContinue).Gatewizz
    Check 'startup remove deletes the Run entry' ($r.Code -eq 0 -and -not $value) "$($r.Text)`nRun value: $value"

    $r = Invoke-Gatewizz 'startup', 'remove'
    Check 'startup remove is idempotent' ($r.Code -eq 0 -and $r.Text -match 'was not registered') $r.Text
}
finally {
    if ($before) { Set-ItemProperty -Path $runKey -Name Gatewizz -Value $before }
}

if ($failures.Count) { throw "$($failures.Count) check(s) failed: $($failures -join '; ')" }
Write-Host 'All CLI smoke checks passed.'
