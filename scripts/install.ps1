# Installs or updates Gatewizz for the current Windows user.
#
# Downloads the latest GitHub release, verifies gatewizz.exe against
# SHA256SUMS.txt, installs it to %LOCALAPPDATA%\Programs\Gatewizz, creates
# %LOCALAPPDATA%\gatewizz\gatewizz.toml from the example if it does not exist
# (an existing configuration is never overwritten) and validates it.
# No administrator rights are needed.

$ErrorActionPreference = "Stop"

$repo = "mycaravam-crypto/Gatewizz"
$installDir = Join-Path $env:LOCALAPPDATA "Programs\Gatewizz"
$configDir = Join-Path $env:LOCALAPPDATA "gatewizz"
$configPath = Join-Path $configDir "gatewizz.toml"
$tempDir = Join-Path $installDir (".install-" + [guid]::NewGuid().ToString("N"))

try {
    New-Item -ItemType Directory -Force -Path $installDir, $configDir, $tempDir | Out-Null

    Write-Host "Finding latest Gatewizz release..."
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
    $exeAsset = $release.assets | Where-Object { $_.name -match '^gatewizz-v[0-9]+\.[0-9]+\.[0-9]+-windows-x64\.exe$' } | Select-Object -First 1
    $sumAsset = $release.assets | Where-Object { $_.name -eq "SHA256SUMS.txt" } | Select-Object -First 1

    if (-not $exeAsset -or -not $sumAsset) {
        throw "The release is missing the Windows executable or SHA256SUMS.txt."
    }

    $downloadExe = Join-Path $tempDir $exeAsset.name
    $downloadSums = Join-Path $tempDir "SHA256SUMS.txt"

    Write-Host "Downloading $($release.tag_name)..."
    Invoke-WebRequest -Uri $exeAsset.browser_download_url -OutFile $downloadExe -UseBasicParsing
    Invoke-WebRequest -Uri $sumAsset.browser_download_url -OutFile $downloadSums -UseBasicParsing

    $pattern = "(?m)^([0-9a-fA-F]{64})\s+\*?" + [regex]::Escape($exeAsset.name) + "\s*$"
    $match = [regex]::Match((Get-Content -Raw -LiteralPath $downloadSums), $pattern)
    if (-not $match.Success) {
        throw "No checksum entry found for $($exeAsset.name)."
    }

    $expectedHash = $match.Groups[1].Value.ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $downloadExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 verification failed. The executable was not installed."
    }
    Write-Host "SHA-256 verified."

    $exePath = Join-Path $installDir "gatewizz.exe"
    $backupPath = $null

    # Stop only the Gatewizz process running from this installation directory.
    $runningInstances = Get-Process -Name "gatewizz" -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Path -and [System.IO.Path]::GetFullPath($_.Path) -ieq [System.IO.Path]::GetFullPath($exePath)
        }

    foreach ($instance in $runningInstances) {
        Stop-Process -Id $instance.Id -ErrorAction Stop
        Wait-Process -Id $instance.Id -Timeout 10 -ErrorAction SilentlyContinue
        if (Get-Process -Id $instance.Id -ErrorAction SilentlyContinue) {
            Stop-Process -Id $instance.Id -Force -ErrorAction Stop
        }
    }

    # The staging directory is on the same volume as the destination, allowing
    # Windows to replace the executable atomically and retain a rollback copy.
    if (Test-Path -LiteralPath $exePath) {
        $backupPath = Join-Path $tempDir "gatewizz.previous.exe"
        [System.IO.File]::Replace($downloadExe, $exePath, $backupPath, $true)
    }
    else {
        [System.IO.File]::Move($downloadExe, $exePath)
    }

    if (-not (Test-Path -LiteralPath $configPath)) {
        $configUrl = "https://raw.githubusercontent.com/$repo/$($release.tag_name)/config/gatewizz.example.toml"
        Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing
        Write-Host "Created configuration: $configPath"
    }
    else {
        Write-Host "Keeping existing configuration: $configPath"
    }

    # This is a Windows GUI-subsystem executable. Start-Process reliably
    # exposes its process exit code; $LASTEXITCODE is not populated here.
    $validation = Start-Process -FilePath $exePath `
        -ArgumentList @("--config", "`"$configPath`"", "--check-config") `
        -Wait -PassThru -NoNewWindow
    if ($validation.ExitCode -ne 0) {
        throw "Configuration validation failed (exit code $($validation.ExitCode)). Review $configPath before starting Gatewizz."
    }

    if ($backupPath -and (Test-Path -LiteralPath $backupPath)) {
        Remove-Item -LiteralPath $backupPath -Force
    }

    Write-Host ""
    Write-Host "Gatewizz $($release.tag_name) installed successfully."
    Write-Host "Executable: $exePath"
    Write-Host "Config:     $configPath"
}
catch {
    # Rollback is best-effort and must never hide the original install error.
    $installError = $_
    if ($backupPath -and (Test-Path -LiteralPath $backupPath)) {
        try {
            if (Test-Path -LiteralPath $exePath) {
                [System.IO.File]::Delete($exePath)
            }
            [System.IO.File]::Move($backupPath, $exePath)
            Write-Warning "Restored the previous Gatewizz executable."
        }
        catch {
            Write-Warning "Could not restore the previous executable: $($_.Exception.Message)"
            Write-Warning "Rollback copy remains at: $backupPath"
        }
    }
    throw $installError
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
