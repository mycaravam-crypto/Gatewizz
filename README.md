# gatewizz

A local HTTPS security gate for code sent to AI models on Windows. It is a loopback proxy for developer tools and coding agents: it attributes each connection to its process, optionally decrypts HTTPS, checks requests against local rules, and allows, blocks or holds them for approval in a tray app. Decisions are logged as metadata; request content and secrets are never stored.

An optional connection firewall extends this beyond the proxy: it decides every outgoing connection of every program through the Windows Filtering Platform, so AI tools can be limited to reaching the network only through gatewizz.

**Status:** the proxy (M1–M3) and firewall Phases 1–2 are merged; Phase 3, holding a connection while asking, is in progress ([#60](https://github.com/mycaravam-crypto/Gatewizz/issues/60)). Manual acceptance on real Windows is tracked in [#66](https://github.com/mycaravam-crypto/Gatewizz/issues/66).

## Install

Needs Windows 10/11 x64 and PowerShell 5.1+; no Rust, .NET runtime or administrator rights. In PowerShell:

```powershell
irm https://raw.githubusercontent.com/mycaravam-crypto/Gatewizz/main/scripts/install.ps1 | iex
```

[`scripts/install.ps1`](scripts/install.ps1) downloads the latest [release](https://github.com/mycaravam-crypto/Gatewizz/releases), verifies it against `SHA256SUMS.txt`, installs `gatewizz.exe` to `%LOCALAPPDATA%\Programs\Gatewizz` and creates `%LOCALAPPDATA%\gatewizz\gatewizz.toml` from the example without overwriting an existing one. Run it again to update. To read it first, download it and run `powershell -ExecutionPolicy Bypass -File install.ps1`.

## Quick start

```powershell
$gatewizz = "$env:LOCALAPPDATA\Programs\Gatewizz\gatewizz.exe"
$config   = "$env:LOCALAPPDATA\gatewizz\gatewizz.toml"

& $gatewizz --config $config                 # start the proxy and tray app

$env:HTTP_PROXY  = "http://127.0.0.1:8899"   # route tools started from this window
$env:HTTPS_PROXY = "http://127.0.0.1:8899"
smartwizz check
```

The proxy variables apply only to this window and its children; Windows-wide proxy settings are untouched. `& $gatewizz startup install --config $config` starts gatewizz at each login.

## What it does

- **Per-process attribution:** every proxied connection is tied to the program that opened it.
- **Rules:** match host, process, path prefix, detected secret kind or AI traffic; actions are `allow`, `block` and `approve`. Block wins over approval, and nothing is sent upstream before a decision.
- **Approvals:** held requests appear in the tray app with program, host and rule: allow once, deny, or allow the program for N minutes. Timeouts block.
- **HTTPS inspection (opt-in):** by default HTTPS is a blind tunnel. With `[tls] intercept = true` and `gatewizz ca install`, a per-user local CA (key protected by DPAPI) lets gatewizz inspect request content. Pinned or mutual-TLS hosts stay tunnels via `tunnel_hosts`.
- **Connection monitor (opt-in, `[monitor] enabled = true`):** the **Network** tab shows every TCP connection on the machine by program, hostname and port, and flags a program's first connection to a host.
- **Connection firewall (opt-in, administrator):** `[[connection_rules]]` by program, address, port and protocol, enforced by the `gatewizz-fw` service from `%ProgramFiles%\Gatewizz`. `ask` rules put blocked connections into the tray's approval queue: allow once, for a while or always, or deny. Manage it with `gatewizz firewall install|apply|status|remove`.
- **Activity history:** recent decisions from the event log, filterable by host, program and decision, and copyable as CSV.

## Project boundaries

- **Local only:** listens on loopback; tools opt in through proxy variables. The proxy never captures system-wide traffic; only the optional firewall acts machine-wide.
- **Metadata, not content:** request bodies, headers and secrets are never persisted.
- **Per-user:** runs as a tray app in the interactive session, not a Windows Service. Only the firewall needs administrator rights.

## Documentation

- [Reference](docs/REFERENCE.md): commands, configuration and rule semantics, HTTPS inspection and CA lifecycle, approvals, connection monitor and firewall, event records, tool integration, limitations
- [Engineering plan](PLAN.md): scope, architecture and milestone status
- [Example configuration](config/gatewizz.example.toml)
- [Releases](https://github.com/mycaravam-crypto/Gatewizz/releases)

## Development

Quality gates used in CI:

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

CI also builds and tests on Windows, smoke-tests the release binary, scans dependencies with Trivy and publishes a versioned Windows x64 executable with SHA-256 checksums. Manual Windows acceptance is scripted in `scripts/windows-acceptance.ps1`. See [CI and releases](docs/REFERENCE.md#ci-and-releases).

## License

Apache-2.0. See [LICENSE](LICENSE).
