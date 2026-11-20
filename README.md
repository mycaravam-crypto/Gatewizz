# gatewizz

A local HTTPS gate for code sent to AI models, for Windows.

Tools that send code to a model (smartwizz, testwizz, `docwizz --ai`, gitwizz, coding agents) run through gatewizz via
`HTTPS_PROXY`. It decrypts each request with a local CA, checks it against a few TOML rules, and allows, blocks or holds
it for approval before any byte goes upstream. Every decision is logged; content never is.

**Status:** M1–M3 implementation is merged. The proxy supports TLS interception, rule-based allow/block/approval,
a Windows tray and approval window, and metadata-only event logging. Real-Windows acceptance of the M1/M2 tool flows
and M3 tray interactions remains open in [#17](https://github.com/mycaravam-crypto/Gatewizz/issues/17),
[#22](https://github.com/mycaravam-crypto/Gatewizz/issues/22), [#35](https://github.com/mycaravam-crypto/Gatewizz/issues/35)
and [#36](https://github.com/mycaravam-crypto/Gatewizz/issues/36). Design and milestones:
[PLAN.md](PLAN.md) and [#1](https://github.com/mycaravam-crypto/Gatewizz/issues/1).

## Usage

    gatewizz [--config gatewizz.toml]                 # run until Ctrl+C; exits 130
    gatewizz [--config gatewizz.toml] --check-config  # print the effective config; exits 0, or 2 on an error

    gatewizz ca install                               # create the local CA if missing and trust it (current user)
    gatewizz ca remove                                # untrust every gatewizz CA and delete its files

Every config key is optional; [config/gatewizz.example.toml](config/gatewizz.example.toml) lists them with their
defaults. Events hold metadata only (process, host, path without query, status, coverage, secret kinds found, AI model),
never header values, secrets or bodies.

`gatewizz --help` lists every flag and the exit codes.

## Local CA

TLS interception (M2) needs a CA that the wizz tools trust. `gatewizz ca install` creates one and adds it to the
**current user's** Trusted Root store; Windows shows its own confirmation dialog. No admin rights are needed and other
users are not affected. Re-running it reuses the existing CA.

- **Files** in `%LOCALAPPDATA%\gatewizz`: `ca.cer` (the public certificate) and `ca.key` (the ECDSA P-256 key,
  encrypted with DPAPI so that only your Windows account can read it). The key is never written in the clear.
- **What it can do:** sign certificates that the current user's Windows-store clients (the .NET wizz tools, curl.exe,
  Edge, Chrome) accept for any host. That is why the key stays DPAPI-protected and the CA is per-user. Its basic
  constraints allow leaf certificates only (path length 0).
- `gatewizz ca remove` removes every gatewizz CA from the store (Windows asks again) and deletes both files.

### Decrypting HTTPS

With the CA installed, turn on interception in the config and start gatewizz with it:

```toml
[tls]
intercept = true
tunnel_hosts = []   # pinned or mutual-TLS hosts that must keep a blind tunnel, e.g. ["*.pinned.example"]
```

Each request inside a CONNECT tunnel is then decrypted, forwarded over a separate TLS connection to the same host, and
logged on its own (method, path without query). The upstream certificate is checked against the Windows store, with no
way to skip that check: a bad one gets `502` before the client sends anything. A `Host` header naming any other site
gets `421`, so a tunnel to an allowed host cannot reach a different site behind the same server. A client that rejects
the gatewizz certificate is logged, never silently passed through. Without `ca install`, `intercept = true` stops
gatewizz at startup instead of falling back to blind tunnels.

## Rules

`[[rules]]` in the config decide whether a request goes upstream. Every key under `match` is optional and all must
hold: `host`, `not_host`, `process` (e.g. `smartwizz.exe`), `path_prefix`, `finding` (`secret.*` or one kind) and `ai`.
The action is `allow`, `block` or `approve`; `block` beats `approve` beats `allow`, and with no match
`[general] default_action` (default `allow`) applies. An `approve` request waits in the approval window, before any
upstream connection is opened, and is blocked unless allowed there (see [Tray and approvals](#tray-and-approvals)). A blocked request gets
`403` naming the rule, its severity and the event time, and nothing is sent upstream. Every event records the action
and the deciding rule (`default` when none matched). An allowlist is one `block` rule with `not_host`:

```toml
[[rules]]
id = "secrets-only-to-approved-models"
match = { finding = "secret.*", not_host = ["llm.internal.example"] }
action = "block"
severity = "critical"
```

Rules on `path_prefix`, `finding` or `ai` need to see inside the request. In a blind tunnel they cannot, so a `block`
rule using them blocks the tunnel (fail closed); with `[tls] intercept` each decrypted request is decided instead.
`finding` and `ai` are decided after the body is read: a body that was only partly inspected (over
`[limits] max_body_bytes` with `over_limit = "allow"`, or compressed) counts as unknown, so a `block` rule on them
applies.

## Tray and approvals

On Windows, `gatewizz` shows a tray icon while it runs. Its colour shows the state: green when running, grey when paused,
amber when an approval is waiting. Clicking the icon opens the approval window. The right-click menu offers **Pause /
Resume**, **Open event log**, **Copy proxy address** and **Quit**.

When a rule holds a request for approval (the `approve` action, M3), the window opens and shows the program, PID, user,
host, rule and finding kinds, never content, with the time left. **Allow once**, **Deny**, or **Allow <program> for N
min** (that program and host, without asking again). A timeout, closing the window, a full queue or **Pause** all block
the request. Ctrl+C in the console still stops gatewizz.

## Use with the wizz tools

Start gatewizz in one terminal, then run the tool in another with the proxy set for that shell only:

```powershell
gatewizz                                    # terminal 1
$env:HTTPS_PROXY = "http://127.0.0.1:8899"  # terminal 2 (cmd: set HTTPS_PROXY=http://127.0.0.1:8899)
$env:HTTP_PROXY  = "http://127.0.0.1:8899"
smartwizz check                             # or testwizz …, docwizz generate --ai
```

smartwizz, testwizz, docwizz and gitwizz are .NET tools: they honour `HTTPS_PROXY` without any change, and each model
request then shows up in `events.jsonl` with the tool's process, the model host and `"coverage": "tunneled"`.

- **Local models bypass gatewizz.** .NET never proxies `localhost`, so an Ollama on the same machine is not seen. That is
  intended: the traffic never leaves the machine. A model on another host is seen.
- **`NO_PROXY` wins.** A host listed there (smartwizz suggests it for internal model hosts) goes direct and is not seen.
- **Without `[tls] intercept`, HTTPS is tunneled.** gatewizz sees which process talks to which host and how much, not
  the content. See [Decrypting HTTPS](#decrypting-https).

## Build

The app targets Windows 10/11 x64. Two ways to build it:

**On Windows** (MSVC toolchain, with the Windows SDK installed through Visual Studio Build Tools):

    cargo build --release

**From Linux/WSL** (needs mingw-w64: `apt install gcc-mingw-w64-x86-64`):

    rustup target add x86_64-pc-windows-gnu
    cargo build --release --target x86_64-pc-windows-gnu

The output is a single `gatewizz.exe` with its icon and manifest (per-monitor DPI v2, `asInvoker`) embedded by
`build.rs`. A release build has no console window of its own: started from Explorer it runs in the tray, and a startup
error is shown in a message box. Started from a terminal, its output (`--help`, `--check-config`, `ca …`, the
`listening on` line) appears in that terminal, but the prompt returns right away. Debug builds keep a console.

## Checks

    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test

## CI and releases

GitHub Actions run on every pull request and on `main`:

- **test**: `fmt`, `clippy -D warnings` and `cargo test` on Linux; `clippy`, `cargo test` and the release build on Windows.
- **security**: Trivy scans `Cargo.lock` for CVEs (weekly too). A fixable CRITICAL fails the job.
- **smartwizz**: AI review of every pull request; high or critical findings fail the check.
- **release**: each merged PR into `main` tags the next SemVer version and publishes a GitHub release with
  `gatewizz-vX.Y.Z-windows-x64.exe` and `SHA256SUMS.txt`. Git tags are the source of truth. A PR label picks the bump:
  `release:patch` (the default), `release:minor`, `release:major`, or `release:none` to skip the release.
  `gatewizz --version` shows the version.

## Known limitations

These are by design and hold once the proxy exists:

- **Only proxy-aware traffic is seen.** Tools must use `HTTPS_PROXY`; direct egress is invisible.
- **Local model endpoints bypass gatewizz.** Loopback traffic (e.g. Ollama on `localhost`) skips the proxy, which is
  fine: it never leaves the machine.
- **Apps with their own trust store** need the gatewizz CA configured: `NODE_EXTRA_CA_CERTS` for Node, `SSL_CERT_FILE`
  for Python, and equivalents for Java and Firefox. The .NET wizz tools use the Windows store and need nothing.
- **Process attribution** is `unknown` when the client exits before the lookup.
- **Pinned and mutual-TLS hosts** can only be tunneled or blocked, never inspected.
