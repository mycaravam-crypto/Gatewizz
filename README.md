# gatewizz

A local HTTPS security gate for code sent to AI models on Windows.

gatewizz is a loopback proxy for developer tools and coding agents. It attributes connections to processes, optionally decrypts HTTPS, checks requests against local rules, and allows, blocks or holds them for approval. Decisions are logged as metadata; request content and secrets are never persisted.

**Status:** M1–M3 implementation is merged. Real-Windows acceptance of proxy integrations and tray/approval interactions is still open: [#17](https://github.com/mycaravam-crypto/Gatewizz/issues/17), [#22](https://github.com/mycaravam-crypto/Gatewizz/issues/22), [#35](https://github.com/mycaravam-crypto/Gatewizz/issues/35), [#36](https://github.com/mycaravam-crypto/Gatewizz/issues/36).

## Install on Windows

**Requirements:** Windows 10/11 x64 and PowerShell 5.1 or later. No Rust, .NET runtime or administrator rights are required.

Open PowerShell and paste this entire block. It downloads the latest Windows release, verifies the executable against the release checksum, installs it for the current user, downloads the example configuration and validates it. Existing configuration is never overwritten.

```powershell
$ErrorActionPreference = "Stop"

$repo = "mycaravam-crypto/Gatewizz"
$installDir = Join-Path $env:LOCALAPPDATA "Programs\Gatewizz"
$configDir = Join-Path $env:LOCALAPPDATA "gatewizz"
$configPath = Join-Path $configDir "gatewizz.toml"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("gatewizz-" + [guid]::NewGuid().ToString("N"))

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
    Invoke-WebRequest -Uri $exeAsset.browser_download_url -OutFile $downloadExe
    Invoke-WebRequest -Uri $sumAsset.browser_download_url -OutFile $downloadSums

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
    Move-Item -LiteralPath $downloadExe -Destination $exePath -Force

    if (-not (Test-Path -LiteralPath $configPath)) {
        $configUrl = "https://raw.githubusercontent.com/$repo/$($release.tag_name)/config/gatewizz.example.toml"
        Invoke-WebRequest -Uri $configUrl -OutFile $configPath
        Write-Host "Created configuration: $configPath"
    }
    else {
        Write-Host "Keeping existing configuration: $configPath"
    }

    & $exePath --config $configPath --check-config
    if ($LASTEXITCODE -ne 0) {
        throw "Configuration validation failed. Review $configPath before starting Gatewizz."
    }

    Write-Host ""
    Write-Host "Gatewizz $($release.tag_name) installed successfully."
    Write-Host "Executable: $exePath"
    Write-Host "Config:     $configPath"
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
```

The executable is installed in `%LOCALAPPDATA%\Programs\Gatewizz`; the configuration and event log live under `%LOCALAPPDATA%\gatewizz`.

## Start and use

Paste this into the same PowerShell window to start Gatewizz and route commands launched from that window through it:

```powershell
$gatewizz = Join-Path $env:LOCALAPPDATA "Programs\Gatewizz\gatewizz.exe"
$config = Join-Path $env:LOCALAPPDATA "gatewizz\gatewizz.toml"

# Start the proxy and tray application.
& $gatewizz --config $config

# Route tools started from this PowerShell session through Gatewizz.
$env:HTTP_PROXY  = "http://127.0.0.1:8899"
$env:HTTPS_PROXY = "http://127.0.0.1:8899"

# Example:
smartwizz check
```

The proxy listens on `127.0.0.1:8899` by default. Proxy variables set this way apply only to the current PowerShell window and child processes. They do not change Windows-wide proxy settings.

To start Gatewizz automatically at each Windows login:

```powershell
& $gatewizz startup install --config $config
& $gatewizz startup status

# Remove automatic startup:
& $gatewizz startup remove
```

Gatewizz runs as a per-user tray application, not a Windows Service. The tray process owns the proxy and approval UI in the interactive user session. A per-session mutex prevents duplicate instances.

## HTTPS inspection (optional)

By default, HTTPS connections are **blind tunnels**: Gatewizz can see the requesting process and destination host, but not the encrypted HTTP request. This requires no local CA.

To inspect HTTPS request content, edit `%LOCALAPPDATA%\gatewizz\gatewizz.toml` and set:

```toml
[tls]
intercept = true
tunnel_hosts = []
```

Then install the local CA for the current Windows user and restart Gatewizz:

```powershell
& $gatewizz ca install
& $gatewizz --config $config
```

Windows displays a certificate trust confirmation. Administrator rights are not required. Gatewizz stores the CA private key protected with Windows DPAPI under `%LOCALAPPDATA%\gatewizz`. Remove the CA when you no longer need inspection:

```powershell
& $gatewizz ca remove
```

Certificate-pinned and mutual-TLS endpoints may need to be listed in `tunnel_hosts`; those connections remain encrypted tunnels and cannot be inspected.

## Configuration

All configuration keys are optional; defaults and commented examples are in [config/gatewizz.example.toml](config/gatewizz.example.toml). Unknown keys are rejected.

A rule can match host, process, path prefix, detected secret kind or AI traffic. Actions are `allow`, `block` and `approve`. A block takes precedence over approval, and approval requests are held before an upstream connection is opened.

See [Configuration and rules](docs/REFERENCE.md#configuration-and-rules) for matching semantics, examples and fail-closed behavior.

## Documentation

- [Reference](docs/REFERENCE.md): CA lifecycle, HTTPS inspection, rules, approvals, event records, tool integration, limitations, build and CI.
- [Engineering plan](PLAN.md): scope, non-goals, engineering rules, architecture and milestone status.
- [Example configuration](config/gatewizz.example.toml)
- [GitHub Releases](https://github.com/mycaravam-crypto/Gatewizz/releases)

## Development

Run the same core checks used in CI:

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

CI also builds and tests on Windows, scans dependencies with Trivy and runs the SmartWizz review workflow. Release builds publish a versioned Windows x64 executable and SHA-256 checksums. See [CI and releases](docs/REFERENCE.md#ci-and-releases).

## License

Apache-2.0. See [LICENSE](LICENSE).
