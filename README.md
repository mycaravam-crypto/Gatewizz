# gatewizz

A local security gate for outgoing traffic on Windows. It is a loopback HTTPS proxy: it attributes each connection to its process, optionally decrypts HTTPS, checks requests against local rules, and allows, blocks or holds them for approval in a tray app. Decisions are logged as metadata; request content and secrets are never stored.

An optional connection firewall extends this beyond the proxy: it decides every outgoing connection of every program through the Windows Filtering Platform, so any program can be limited to reaching the network only through gatewizz.

One common use is keeping developer tools and coding agents from sending secrets or private code to AI providers unnoticed. The rules themselves work for any program and any host.

**Status:** the proxy (M1–M3) and firewall Phases 1–3 are implemented and merged. Phase 3 release packaging is configured; real-Windows and Microsoft Defender acceptance remains open in [#66](https://github.com/mycaravam-crypto/Gatewizz/issues/66).

## Install

Needs Windows 10/11 x64 and PowerShell 5.1+; no Rust, .NET runtime or administrator rights. In PowerShell, download the installer, read it, then run it:

```powershell
irm https://raw.githubusercontent.com/mycaravam-crypto/Gatewizz/main/scripts/install.ps1 -OutFile install.ps1
notepad install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

[`scripts/install.ps1`](scripts/install.ps1) downloads the latest [release](https://github.com/mycaravam-crypto/Gatewizz/releases), verifies `gatewizz.exe` against `SHA256SUMS.txt`, installs it to `%LOCALAPPDATA%\Programs\Gatewizz` and creates `%LOCALAPPDATA%\gatewizz\gatewizz.toml` from the example without overwriting an existing one. Run it again to update. To install the optional WinDivert files needed for `[firewall] hold = true`, run `./install.ps1 -WithWinDivert` from the directory containing the downloaded installer. This option is not needed for the default block-then-ask firewall.

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
- **Connection firewall (opt-in, administrator):** `[[connection_rules]]` by program, address, port and protocol, enforced by the `gatewizz-fw` service from `%ProgramFiles%\Gatewizz`. `ask` rules put blocked connections into the tray's approval queue: allow once, for a while or always, or deny; with `[firewall] hold = true` (opt-in; install with `-WithWinDivert`), new TCP connections wait for your answer instead of failing their first attempt. Manage it with `gatewizz firewall install|apply|status|remove`.
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
