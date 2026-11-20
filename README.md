# gatewizz

A local HTTPS security gate for code sent to AI models on Windows.

gatewizz is a loopback proxy for developer tools and coding agents. It attributes connections to processes, optionally decrypts HTTPS, checks requests against local rules, and allows, blocks or holds them for approval. Decisions are logged as metadata; request content and secrets are never persisted.

**Status:** M1–M3 implementation is merged. Real-Windows acceptance of proxy integrations and tray/approval interactions is still open: [#17](https://github.com/mycaravam-crypto/Gatewizz/issues/17), [#22](https://github.com/mycaravam-crypto/Gatewizz/issues/22), [#35](https://github.com/mycaravam-crypto/Gatewizz/issues/35), [#36](https://github.com/mycaravam-crypto/Gatewizz/issues/36).

## Install

Download `gatewizz-vX.Y.Z-windows-x64.exe` and `SHA256SUMS.txt` from [GitHub Releases](https://github.com/mycaravam-crypto/Gatewizz/releases/latest). Verify the download in PowerShell:

```powershell
Get-FileHash .\gatewizz-vX.Y.Z-windows-x64.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

The release is a single executable for Windows 10/11 x64. No runtime installation is required.

To build from source, use Rust stable and the Windows SDK/MSVC toolchain:

```bash
cargo build --release --locked
```

Linux/WSL cross-build instructions are in the [reference](docs/REFERENCE.md#build).

## Quick start

Download the [example configuration](config/gatewizz.example.toml) alongside the executable, install the local CA for HTTPS inspection, then validate and start the proxy:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/mycaravam-crypto/Gatewizz/main/config/gatewizz.example.toml -OutFile .\gatewizz.toml
gatewizz ca install
# Set [tls].intercept = true in gatewizz.toml when content inspection is required.
gatewizz --config .\gatewizz.toml --check-config
gatewizz --config .\gatewizz.toml
```

In a second PowerShell window, route a tool through the proxy:

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:8899"
$env:HTTP_PROXY  = "http://127.0.0.1:8899"
smartwizz check
```

Without TLS interception, HTTPS is a blind CONNECT tunnel: process and host are visible, request content is not. See the [configuration and TLS reference](docs/REFERENCE.md#https-inspection).

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
