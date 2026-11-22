# Reference

This document describes gatewizz runtime behavior and operational details. The [README](../README.md) is the user entry point; [PLAN.md](../PLAN.md) records scope, architecture and milestone status.

## Runtime model

gatewizz listens on loopback (default `127.0.0.1:8899`). Applications must explicitly use it through `HTTP_PROXY` or `HTTPS_PROXY`; it does not capture system-wide traffic.

For HTTPS, the client first establishes a CONNECT tunnel. With TLS interception disabled, gatewizz forwards the tunnel without seeing its HTTP requests. With interception enabled, gatewizz terminates client TLS using a locally generated CA, inspects each HTTP/1.1 request, and creates a separately verified TLS connection to the upstream host.

Each request is evaluated before any upstream connection is opened. Blocked or unanswered approval requests send no request bytes upstream.

## Installation and commands

The release executable targets Windows 10/11 x64 and has no runtime dependencies. [`scripts/install.ps1`](../scripts/install.ps1) installs or updates it for the current user (see the [README](../README.md#install)); alternatively, download the executable and `SHA256SUMS.txt` from [GitHub Releases](https://github.com/mycaravam-crypto/Gatewizz/releases).

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
gatewizz firewall install --config .\gatewizz.toml # asks for administrator rights (UAC)
gatewizz firewall apply --config .\gatewizz.toml   # asks for administrator rights (UAC)
gatewizz firewall status                           # asks for administrator rights (UAC)
gatewizz firewall remove                           # asks for administrator rights (UAC)
```

- `gatewizz`: starts the proxy and tray application; Ctrl+C or **Quit** in the tray stops it (exit 130).
- `--config <path>`: selects a TOML configuration file. Without it, Gatewizz (and `--check-config`, `startup install`) uses `%LOCALAPPDATA%\gatewizz\gatewizz.toml`, the file the installer creates, if it exists; otherwise every default applies. `--check-config` prints which file it loaded on its first line. The `firewall` commands keep their own protected copy and still need `--config` to change it.
- `--check-config`: validates and prints effective configuration (exit 0; exit 2 on error).
- `ca install`: creates the local CA if needed and trusts it for the current Windows user.
- `ca remove`: removes gatewizz CA certificates from the current user's store and deletes its key files.
- `startup install [--config <path>]`: registers the current executable in the current user's Windows Run key. The optional config path is resolved to an absolute path and retained for login startup.
- `startup status`: displays the current Run registration.
- `startup remove`: removes only Gatewizz's Run value; it does not uninstall the executable or remove the CA.
- `firewall install|apply [--config <path>]`, `firewall status`, `firewall remove`: see [Connection firewall](#connection-firewall).

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

A blocked request receives HTTP 403 with the deciding rule, severity and event time. No request is sent upstream. An approval request waits in the Windows approval window; it is blocked if denied, unanswered, paused, queued without a window, or rejected because the queue is full. Its card shows the request line, headers and the first 4 KiB of the body, so you can see what you are allowing. Credential headers (`Authorization`, `Cookie`, API-key headers) and detected secrets are shown as `[redacted]`, and a body with a secret that cannot be masked is hidden. The preview exists only while the request waits; it is never logged or written to disk. A blind HTTPS tunnel shows no content: enable TLS interception to see it.

A client that is not a Windows process, such as a program in WSL with mirrored networking, has no entry in the Windows TCP table, so Gatewizz cannot name it; it is shown as "WSL / VM" and `process` rules do not match it.

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

Clicking the icon opens the workspace window. The context menu provides **Pause/Resume**, **Open event log**, **Copy proxy address** and **Quit**.

An approval entry shows the requesting program, PID, user, host, rule, finding kinds and remaining time. It never displays request content. Available decisions:

- **Allow once**: allow this request.
- **Deny**: block this request.
- **Allow program for N minutes**: create a temporary grant for that program and host.

Timeout, a full queue or pausing approvals blocks the request. All approvals share one workspace window. Closing it with its ✕ button denies every waiting request and hides the window to the tray. **Hide to tray** in the status bar only hides it, and the requests keep waiting. Ctrl+C in the console stops gatewizz.

## Activity history

The Gatewizz window has three tabs: **Overview** (summary counts, pending approvals and, with the connection firewall, blocked connections to decide), **Activity history** and **Network** (see [Connection monitor](#connection-monitor)). The history tab shows recent decisions read back from the event log. It shows only the metadata the log already holds, never request content.

- **Source:** the current event file and up to five rotated files (`events.jsonl.1` to `.5`). From each file only the last 1 MiB is read, and at most 500 events are shown, newest first. The list refreshes every two seconds. If `[events].path = "-"` (stdout), there is no file to read and the tab says that persistent history is disabled.
- **Summary:** counts of recent, blocked and other events.
- **Filters:** a text filter that matches the host or the program name, ignoring case, and a decision filter (all, allowed, blocked, approval). Both filters must match.
- **Details:** selecting a row shows time, method, status, destination, path (or "CONNECT tunnel"), inspection coverage, the deciding rule, the AI model and the proxy's reason.
- **Copy CSV:** copies the rows currently shown to the clipboard as CSV with CRLF line endings and every field quoted. Columns: `time_utc, process, host, port, method, path, decision, status, coverage, rule, reason, model`. Nothing is written to disk.

## Connection monitor

The proxy only sees tools that use it. The connection monitor shows everything else too: every TCP connection on the computer, attributed to its program. It is Phase 1 of the connection firewall (#56, #57). It only watches, it needs no admin rights, and it is off by default:

```toml
[monitor]
enabled = true
# poll_ms = 1000
# dns_cache_size = 4096
```

- **What is shown:** the **Network** tab lists the current connections grouped by program. Each one shows the hostname (or the IP), the remote address and port, and the direction. A **New** badge marks the first connection from a program to a host since Gatewizz started. The search box matches the program, the hostname or the IP.
- **What is logged:** each connection that opens or closes is written to the event log as a `connection` record. A record holds the time, `opened`/`closed`, the process (PID, image, user), `tcp`, the direction, the remote IP and port, the hostname or `null`, and `first_seen`. It never holds content: the monitor reads no bytes of any connection. At most one record per process, remote address and state is written every 10 seconds. Records left out are counted in the next one's `suppressed` field. The Activity tab ignores these records, so its counts are unchanged.
- **How:** the IP Helper TCP tables (IPv4 and IPv6) are read every `poll_ms`. A connection is inbound when its program listens on its local port, and outbound otherwise. Loopback connections (tools to the proxy, local model servers) and sockets without an owner (`TIME_WAIT`) are left out. Hostnames come from the Windows DNS Client cache. When a connection to an unknown address appears, Gatewizz reads the list of cached names, at most once per second. It resolves each listed name again through the DNS Client, at most once per TTL. Fresh entries are answered from the cache, so this normally adds no network traffic. An address keeps up to four recent names, and the one most recently looked up is shown.
- **Off:** with `enabled = false` nothing is sampled and the proxy behaves exactly as before. On other operating systems `enabled = true` is a startup error.

Limits:

- **Short connections:** connections that open and close between two samples are missed. Lower `poll_ms` if that matters. Phase 2 (#59) adds WFP connection filtering; the manual acceptance for both phases is tracked in #66.
- **UDP and QUIC:** these are not shown. The Windows UDP table lists local sockets only, without a remote address.
- **Hostnames are best effort:** apps that resolve names themselves (DNS over HTTPS in a browser, hard-coded IPs) show an IP only. A CDN address shared by many sites shows the name that was looked up most recently. The DNS cache does not say which program asked.
- **Overhead:** the CPU cost at the default interval still has to be measured on a real machine (#57). Reading the tables is one system call per address family per sample.

## Connection firewall

The connection firewall turns `[[connection_rules]]` into Windows Filtering Platform (WFP) filters. Those filters allow or block outgoing connections per program, address, port and protocol, for every program, whether or not it uses the proxy. It is Phase 2 of #56 and needs administrator rights. Nothing else in Gatewizz does. From a normal prompt, the `firewall` commands ask for them through the UAC prompt, run in an elevated copy of `gatewizz.exe`, and print its output in the same console. That output comes back over a private pipe that accepts only the elevated process this command started, and nothing is written to disk. From an elevated prompt they run directly. Declining the UAC prompt changes nothing.

```powershell
gatewizz firewall install --config .\gatewizz.toml # install the service that keeps the rules current
gatewizz firewall apply --config .\gatewizz.toml   # change the rules (or apply once, without the service)
gatewizz firewall status                           # filters and service state
gatewizz firewall remove                           # remove the service, every filter and its files
```

- **The service (`gatewizz-fw`):** `firewall install` sets up a Windows service that keeps the rules current.
  - It resolves program paths and host addresses again every 60 seconds, and at once after `firewall apply`.
  - It starts automatically at boot, before anyone signs in.
  - It runs as LocalSystem, so it never runs or reads anything a normal user can write. `install` copies `gatewizz.exe` and the validated configuration into `%ProgramFiles%\Gatewizz`, which only administrators can change, and the service runs from that copy. `firewall apply` updates the copy, again with administrator rights. Editing your own configuration file changes nothing until you run `apply`.
  - It writes each refresh, and any error, to `%ProgramFiles%\Gatewizz\service.log`. That file rotates at 256 KiB.
  - It logs each connection Gatewizz's filters block: `blocked: <program> -> <address>:<port> <protocol> (<program path>)`. Retries of the same program, host and port within a minute count as one. Drops by other firewalls are not logged. The service turns on WFP's net event collection for this, which Windows keeps in memory only.
  - When a refresh fails, or the service stops, the last filters stay in force (fail closed).
- **Without the service:** `firewall apply` installs the filters once, with names resolved at that moment.

- **Rules:** see the commented `[firewall]` and `[[connection_rules]]` example in [gatewizz.example.toml](../config/gatewizz.example.toml).
  - The most specific matching rule wins: first by how many of program, address, port and protocol it pins down, then by how narrow its address is (exact host, then `*.suffix`, then IP prefix width).
  - A rule's `action` is `allow`, `block` or `ask`. `ask` blocks like `block`, and its blocked connections are also offered to the prompt (below).
  - Between equally specific rules, `block` and `ask` beat `allow`; after that, the first rule in the file wins.
  - So an `allow` for one program to `127.0.0.1:8899` overrides a `block` for that program alone. This is the proxy-enforcement pair: the wizz tools can then reach the network only through Gatewizz.
- **Enforcement:**
  - Filters sit at WFP's connect layers (IPv4 and IPv6) in Gatewizz's own provider and sublayer. They decide connection attempts and never read traffic.
  - Block filters are hard blocks, so other software cannot override them.
  - Filters are persistent: they stay in force after a reboot, or when Gatewizz is not running, until `firewall remove`.
  - `apply` replaces the whole set in one transaction, so a failed apply leaves the previous rules in place.
- **Names:** WFP works with full program paths and IP addresses, so names are resolved on every apply and every service refresh. A program file name covers the copies on `PATH` and those running at that moment. A host covers the addresses it resolves to at that moment. A wildcard host (`*.example.com`) covers the addresses of the matching names in the Windows DNS cache, that is the names this machine has looked up lately. A name looked up for the first time is covered from the next refresh, at most 60 seconds later with the service. `apply` warns about anything it could not resolve, since that part of a rule is not enforced until a later refresh finds it. Use full paths in `process`, and `ip`, for what must always be covered.
- **Gatewizz itself** is always allowed: the service's copy, and the copy that ran `install` or `apply` (your tray app and proxy). No rule can block it.
- **`default`:**
  - `allow` (the default) filters only what rules name.
  - `block` blocks every program without a matching allow rule, Windows services included. Use it only with allow rules for everything that must keep working.
  - `ask` blocks like `block`, and offers each blocked connection to the prompt.

- **The prompt pipe:** the service serves `\\.\pipe\gatewizz-fw`, which only SYSTEM, administrators and interactively logged-on users can open. Each connection is checked too: the client must run in the active console session (the person at the machine) or be an elevated administrator. Another user signed in at the same time, by fast user switching or Remote Desktop, is refused; over Remote Desktop, start the tray app elevated to answer prompts. Remote clients are rejected, and one client is served at a time. While a client is connected, each new connection blocked by an `ask` rule or the `ask` default is sent to it as a notice: program, path, address, port and protocol. Connections blocked by `block` rules, including "Deny always" answers, are only logged. The client answers with a decision.
  - **What the service accepts:** only answers to notices it sent itself, within the last 10 minutes. The program, address and port always come from that notice. An answer may only widen to "any host" or "any port", choose allow or block, and pick "once" (2 minutes), 5, 15, 60 or 480 minutes, or "always".
  - **Where the rules go:** "always" rules are appended to the protected configuration as `[[connection_rules]]` (your text and comments stay) and validated first. Timed rules stay in the service's memory until they expire.
  - **The service only asks:** with no client connected, nothing is asked and the connection stays blocked.

- **The prompt in the tray app:** while it runs, the tray app connects to the pipe, retrying every 2 seconds. It talks only to the running `gatewizz-fw` service, which it checks by comparing the pipe server's process id with the service's, so another program that created a pipe of the same name is ignored. The status bar shows **Firewall prompt on** while connected.
  - Each notice appears in the Overview's approval queue and opens the window, like a held request. Repeats for the same program, address, port and protocol fold into one entry, which counts the attempts.
  - The choices are **Allow once**, **Allow for** 5 or 15 minutes, 1 or 8 hours, **Allow always** and **Deny always**. **Any address** and **Any port** widen the rule; by default it covers only that program, address and port. The service's answer (the rule it added, or why it refused) shows in the status bar.
  - Unlike a held request, a blocked connection has no timer: it has failed already, and the program retries once a rule allows it. Closing the window, pausing approvals, or the service restarting drops the waiting notices, and those connections stay blocked. A notice that is not answered within 9 minutes is dropped too, since the service forgets it after 10.

- **Holding connections (`[firewall] hold = true`, #60):** without holding, the first attempt of an asked-about connection fails before you answer, and programs that don't retry show an error. With holding, a new TCP connection that an `ask` rule or `default = "ask"` covers waits for your answer instead. The queue shows it as **Waiting**.
  - **Allowed:** the connection simply goes on, without the program retrying.
  - **Denied, or unanswered after `hold_timeout_secs`** (default 20, at most 20, because Windows programs give up connecting after about 21 s): the program gets *connection refused* at once.
  - **How:** the service uses [WinDivert](https://github.com/basil00/WinDivert) 2.2.2, a signed packet driver, to take the connection's first packet (the TCP SYN) off the wire. It re-sends that packet on allow, and answers with a TCP reset on deny. It finds the program from the connection's row in the TCP table, and classifies the connection against the same filters WFP enforces. Connections no `ask` filter could cover are sent on at once, without that lookup.
  - **Fail closed:** the persistent `ask` filters keep blocking at connect. While the service holds, it adds permits just above them, in a dynamic WFP session that Windows deletes when the service stops or crashes. With no tray app connected, held connections are refused at once. So are connections whose program cannot be found, and any beyond 256 waiting at a time.
  - **Setup:** run `scripts/install.ps1 -WithWinDivert`, which downloads `WinDivert.dll`, `WinDivert64.sys` and `WinDivert-LICENSE.txt` from the release and checks them against its `SHA256SUMS.txt` (or download them yourself and put them next to `gatewizz.exe`), set `hold = true`, and run `firewall install` or `firewall apply`. Gatewizz checks both files against the SHA-256 of WinDivert 2.2.2-A before it copies or loads them, and refuses any other build. `firewall remove` unloads the driver and deletes the files.
  - **Limits:**
    - Holding is TCP only; UDP keeps block-then-ask.
    - It is off by default because endpoint protection may flag packet-interception drivers. In [upstream WinDivert issue #411](https://github.com/basil00/WinDivert/issues/411), opened in October 2026, a user reports Microsoft Defender quarantining the official 2.2.2-A archive as `Misleading:Win32/Malgent!AMTB`; other reports mention `HackTool:Win64/WinDivert`. This is an unresolved compatibility risk, not a reason to disable Defender. If Defender removes or blocks the files, holding stays off and asking falls back to block-then-ask. Real-machine acceptance must be performed with Defender enabled and recorded in #66.
    - Every new outbound TCP connection's first packet passes through the service once. Later packets never do.
    - WinDivert is licensed LGPL v3 / GPL v2 and ships unmodified with its licence.

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

## Acceptance testing on Windows

Some checks need a real Windows session: the icon, the tray, approvals clicked by a person, Ctrl+C in a console and the Windows certificate dialogs. [`scripts/windows-acceptance.ps1`](../scripts/windows-acceptance.ps1) is the scripted entry point for the consolidated real-Windows acceptance tracker, [#66](https://github.com/mycaravam-crypto/Gatewizz/issues/66). With `-Firewall`, it also exercises the firewall service and prompt; Phase 3 holding requires the packaged WinDivert files next to `gatewizz.exe` or supplied through `-WinDivertDir`. It measures what it can, asks y/n questions for what only a person can see, and writes a Markdown report to paste into the issues.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows-acceptance.ps1
# Optional: include a SmartWizz review; skip the CA or approval checks if already covered.
powershell -ExecutionPolicy Bypass -File scripts\windows-acceptance.ps1 -SmartwizzRepo C:\src\repo -SkipCa
# From an elevated prompt (Run as administrator): also the connection firewall and its prompt. Results belong in #66.
powershell -ExecutionPolicy Bypass -File scripts\windows-acceptance.ps1 -Firewall
```

The script uses its own config, port (18899) and event file under `%TEMP%`, so your setup is left alone. Quit a running Gatewizz first, because only one instance runs per session. It removes the CA again only if it was not installed before the run. Every check that involves Windows dialogs or a person stays manual. The firewall part installs the `gatewizz-fw` service with test rules for `curl.exe` and a renamed copy of it (the proxy-enforcement preset), asks you to answer three prompts, and removes everything at the end. It refuses to run if the firewall is already installed, since installing would replace your rules. "Allow always survives a reboot" is checked as a service restart plus the automatic start; both read the same protected configuration that a boot does.

CI runs [`.github/scripts/windows-cli-smoke.ps1`](../.github/scripts/windows-cli-smoke.ps1) on the release binary. It checks the CLI output and exit codes and the `startup install/status/remove` Run-key round trip.

## CI and releases

GitHub Actions run tests on pull requests and `main`:

- **test**: formatting, Clippy and tests on Linux; Clippy, tests and a release build on Windows.
- **security**: Trivy dependency vulnerability scan of `Cargo.lock`, also scheduled weekly. A fixable critical finding fails the job.
- **smartwizz**: AI review of pull requests; high or critical findings fail the check. This workflow requires a valid `SMARTWIZZ_API_KEY` repository secret.
- **release**: each merged pull request into `main` can publish the next SemVer version. The release contains `gatewizz-vX.Y.Z-windows-x64.exe`, `WinDivert.dll`, `WinDivert64.sys`, `WinDivert-LICENSE.txt` and `SHA256SUMS.txt`. The WinDivert 2.2.2-A archive is pinned and hash-verified before packaging. Git tags are authoritative. Labels select the version bump: `release:patch` (default), `release:minor`, `release:major`, or `release:none`.

## Known limitations and boundaries

- Only applications configured to use the proxy are inspected. Direct egress is outside gatewizz's visibility.
- Localhost traffic bypasses the .NET proxy behavior described above.
- Certificate-pinned and mutual-TLS hosts can only be tunneled or blocked, not inspected.
- The proxy handles HTTP/1.1. HTTP/2 and QUIC/HTTP/3 are not transparently captured.
- Applications with private certificate stores need their own CA configuration.
- Process attribution can be `unknown` if the client exits before process lookup completes.
- This is not a system-wide firewall or transparent egress control. It does not prevent an application from bypassing it by ignoring proxy settings. With `[monitor] enabled = true` such connections are at least visible (see [Connection monitor](#connection-monitor)); blocking them is Phase 2 of #56.
