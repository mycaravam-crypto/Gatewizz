# Reference

This document describes gatewizz runtime behavior and operational details. The [README](../README.md) is the user entry point; [PLAN.md](../PLAN.md) records scope, architecture and milestone status.

## Runtime model

gatewizz listens on loopback (default `127.0.0.1:8899`). Applications must explicitly use it through `HTTP_PROXY` or `HTTPS_PROXY`; it does not capture system-wide traffic.

For HTTPS, the client first establishes a CONNECT tunnel. With TLS interception disabled, gatewizz forwards the tunnel without seeing its HTTP requests. With interception enabled, gatewizz terminates client TLS using a locally generated CA, inspects each HTTP/1.1 request, and creates a separately verified TLS connection to the upstream host.

Each request is evaluated before any upstream connection is opened. Blocked or unanswered approval requests send no request bytes upstream.

## Installation and commands

The release executable targets Windows 10/11 x64 and has no runtime dependencies. Download the executable and `SHA256SUMS.txt` from [GitHub Releases](https://github.com/mycaravam-crypto/Gatewizz/releases).

Common commands:

```powershell
gatewizz --help
gatewizz --version
gatewizz --config .\gatewizz.toml --check-config
gatewizz --config .\gatewizz.toml
gatewizz ca install
gatewizz ca remove
gatewizz startup install
gatewizz startup install --config .\gatewizz.toml
gatewizz startup status
gatewizz startup remove
```

- `gatewizz`: starts the proxy and tray application; Ctrl+C or **Quit** in the tray stops it (exit 130).
- `--config <path>`: selects a TOML configuration file.
- `--check-config`: validates and prints effective configuration (exit 0; exit 2 on error).
- `ca install`: creates the local CA if needed and trusts it for the current Windows user.
- `ca remove`: removes gatewizz CA certificates from the current user's store and deletes its key files.
- `startup install [--config <path>]`: registers the current executable in the current user's Windows Run key. The optional config path is resolved to an absolute path and retained for login startup.
- `startup status`: displays the current Run registration.
- `startup remove`: removes only Gatewizz's Run value; it does not uninstall the executable or remove the CA.

`gatewizz --help` is authoritative for the complete flag list and exit codes.

## Configuration and rules

Start with [gatewizz.example.toml](../config/gatewizz.example.toml). Every key is optional and defaults are documented inline. Unknown keys are rejected.

### General behavior

- The listener must bind to loopback; non-loopback addresses are rejected.
- CONNECT destinations are restricted to configured ports (443 by default).
- `[limits]` bounds connections, headers, request bodies, timeouts and shutdown.
- Request bodies up to `max_body_bytes` are buffered and inspected before forwarding.
- Larger or compressed bodies follow `over_limit`: `block` rejects them (default, fail closed); `allow` forwards them as partially inspected.

### Rule matching

Each `[[rules]]` entry has an optional `match` object. All supplied match conditions must hold:

| Match key | Meaning |
|---|---|
| `host` | Exact host names or wildcard suffix patterns |
| `not_host` | Hosts that must not match |
| `process` | Client executable name, e.g. `smartwizz.exe` |
| `path_prefix` | Request path prefix |
| `finding` | A detected kind, e.g. `secret.github_token`, or `secret.*` |
| `ai` | Whether the request targets a recognized AI model endpoint |

Actions are `allow`, `block` or `approve`. Precedence is **block, approve, allow**. If no rule matches, `[general].default_action` applies (default: `allow`).

A blocked request receives HTTP 403 with the deciding rule, severity and event time. No request is sent upstream. An approval request waits in the Windows approval window; it is blocked if denied, unanswered, paused, queued without a window, or rejected because the queue is full.

Example: block detected secrets from every host except the approved internal model gateway:

```toml
[[rules]]
id = "secrets-only-to-approved-models"
description = "Secrets may only be sent to the internal model gateway"
match = { finding = "secret.*", not_host = ["llm.internal.example"] }
action = "block"
severity = "critical"
```

Rules using `path_prefix`, `finding` or `ai` need request inspection. In a blind tunnel, those facts are unavailable; a `block` rule depending on them blocks the tunnel (fail closed). Enable TLS interception to evaluate each decrypted request.

A finding-dependent block also applies when inspection is incomplete, including an over-limit body configured to pass or a compressed body.

## HTTPS inspection

Enable interception in the configuration:

```toml
[tls]
intercept = true
tunnel_hosts = []
```

Install the CA before starting with interception enabled:

```powershell
gatewizz ca install
```

If the CA is missing, startup fails; gatewizz does not silently fall back to blind tunnels.

For each CONNECT tunnel, gatewizz:

1. Presents a host certificate signed by the local CA.
2. Establishes a separate TLS connection to the same upstream host.
3. Verifies the upstream certificate against the Windows certificate store.
4. Inspects and evaluates each HTTP/1.1 request before forwarding it.

An invalid upstream certificate results in HTTP 502. A decrypted request whose `Host` header names a different site is rejected with HTTP 421. A client that rejects the gatewizz certificate is logged and is not silently bypassed.

Use `tunnel_hosts` for hosts that must remain blind tunnels, such as certificate-pinned or mutual-TLS endpoints. These hosts cannot be inspected.

### Local CA lifecycle

`gatewizz ca install` creates an ECDSA P-256 CA if one does not already exist and adds it to the **current user's** Windows Trusted Root store. Windows displays its certificate confirmation dialog. Administrator rights are not required; other Windows users are not affected. Re-running the command reuses the existing CA.

Files are stored in `%LOCALAPPDATA%\gatewizz`:

- `ca.cer`: public certificate.
- `ca.key`: private key encrypted with Windows DPAPI so only the current Windows account can read it.

The CA can issue leaf certificates (path length zero). Protect the Windows account that owns this key accordingly.

`gatewizz ca remove` removes gatewizz CA certificates from the current user's store and deletes both files. Windows displays its confirmation dialog again.

## Background startup and process lifecycle

Gatewizz is a per-user desktop application, not a Windows Service. A traditional service runs in Session 0 and cannot own the interactive approval windows. The proxy, tray and approval UI therefore live in one process in the logged-in user's session.

Register automatic login startup:

```powershell
gatewizz startup install --config .\gatewizz.toml
gatewizz startup status
gatewizz startup remove
```

The registration is stored as a `REG_SZ` value named `Gatewizz` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. It needs no administrator rights. The config path, if supplied, is stored as an absolute path. The registration starts the executable after that user signs in; it does not start before login.

Only one Gatewizz process is allowed per interactive Windows session. A named mutex prevents duplicate proxy listeners. A second launch exits cleanly. The tray must initialize successfully before the proxy worker starts; if tray creation fails, Gatewizz fails startup instead of leaving an invisible proxy running. The approval viewport starts hidden and appears only when an approval is waiting or the tray is clicked.

Quit withdraws pending approvals (fail closed), stops the proxy and flushes the event writer. Pending approvals and temporary grants are memory-only and are never restored after restart.

## Tray and approvals

On Windows, the tray icon indicates state:

- Green: running.
- Grey: paused.
- Amber: an approval is waiting.

Clicking the icon opens the approval window. The context menu provides **Pause/Resume**, **Open event log**, **Copy proxy address** and **Quit**.

An approval entry shows the requesting program, PID, user, host, rule, finding kinds and remaining time. It never displays request content. Available decisions:

- **Allow once**: allow this request.
- **Deny**: block this request.
- **Allow program for N minutes**: create a temporary grant for that program and host.

Timeout, closing the last approval window, a full queue or pausing the proxy blocks the request. Closing one of multiple windows does not withdraw requests while another remains open. Ctrl+C in the console stops gatewizz.

## Events and privacy

Events are written as JSON Lines. The default path is `%LOCALAPPDATA%\gatewizz\events.jsonl`; configure `[events].path` to change it or use `-` for stdout. Files rotate at the configured size and retain a bounded number of previous files.

Events contain decision metadata, including process, host, path without query string, status, inspection coverage, detected secret kinds, AI model and deciding rule. They do not contain request bodies, header values, query strings, credentials or detected secret values.

## Use with developer tools

Start gatewizz in one terminal and set proxy variables in the shell that launches the tool:

```powershell
# Terminal 1
gatewizz --config .\gatewizz.toml

# Terminal 2
$env:HTTPS_PROXY = "http://127.0.0.1:8899"
$env:HTTP_PROXY  = "http://127.0.0.1:8899"
smartwizz check
# Also applies to testwizz, docwizz --ai and gitwizz.
```

The .NET-based SmartWizz, TestWizz, DocWizz and GitWizz tools honor these variables and use the Windows certificate store.

Important routing behavior:

- **Loopback is not proxied by .NET.** Local model endpoints such as Ollama on `localhost` bypass gatewizz. This is intentional because the traffic does not leave the machine.
- **`NO_PROXY` takes precedence.** Hosts listed there connect directly and are not visible to gatewizz.
- **Blind tunnels reveal metadata only.** Without TLS interception, gatewizz sees the process and destination host, not the HTTP request content.
- **Other runtimes may need CA configuration.** Examples include `NODE_EXTRA_CA_CERTS` for Node.js, `SSL_CERT_FILE` for Python, and the corresponding trust configuration for Java and Firefox.

## Build

The application targets Windows 10/11 x64.

On Windows, use Rust stable, the MSVC toolchain and the Windows SDK:

```bash
cargo build --release --locked
```

From Linux/WSL, install the MinGW cross compiler and target:

```bash
sudo apt install gcc-mingw-w64-x86-64
rustup target add x86_64-pc-windows-gnu
cargo build --release --locked --target x86_64-pc-windows-gnu
```

The executable embeds its icon and manifest via `build.rs`. The manifest requests per-monitor DPI v2 and `asInvoker`. Release builds have no console window when launched from Explorer; startup errors are shown in a message box. When started from a terminal, command output is written there and the prompt returns immediately. Debug builds retain a console.

## CI and releases

GitHub Actions run tests on pull requests and `main`:

- **test**: formatting, Clippy and tests on Linux; Clippy, tests and a release build on Windows.
- **security**: Trivy dependency vulnerability scan of `Cargo.lock`, also scheduled weekly. A fixable critical finding fails the job.
- **smartwizz**: AI review of pull requests; high or critical findings fail the check. This workflow requires a valid `SMARTWIZZ_API_KEY` repository secret.
- **release**: each merged pull request into `main` can publish the next SemVer version. The release contains `gatewizz-vX.Y.Z-windows-x64.exe` and `SHA256SUMS.txt`. Git tags are authoritative. Labels select the version bump: `release:patch` (default), `release:minor`, `release:major`, or `release:none`.

## Known limitations and boundaries

- Only applications configured to use the proxy are inspected. Direct egress is outside gatewizz's visibility.
- Localhost traffic bypasses the .NET proxy behavior described above.
- Certificate-pinned and mutual-TLS hosts can only be tunneled or blocked, not inspected.
- The proxy handles HTTP/1.1. HTTP/2 and QUIC/HTTP/3 are not transparently captured.
- Applications with private certificate stores need their own CA configuration.
- Process attribution can be `unknown` if the client exits before process lookup completes.
- This is not a system-wide firewall or transparent egress control. It does not prevent an application from bypassing it by ignoring proxy settings.
