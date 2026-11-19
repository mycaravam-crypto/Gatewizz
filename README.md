# gatewizz

A local HTTPS gate for code sent to AI models, for Windows.

Tools that send code to a model (smartwizz, testwizz, `docwizz --ai`, gitwizz, coding agents) run through gatewizz via
`HTTPS_PROXY`. It decrypts each request with a local CA, checks it against a few TOML rules, and allows, blocks or holds
it for approval before any byte goes upstream. Every decision is logged; content never is.

**Status:** early development. `gatewizz` forwards plain HTTP and tunnels HTTPS (CONNECT to port 443) on
`127.0.0.1:8899`, names the client process of each connection, and writes one JSON line per request to
`%LOCALAPPDATA%\gatewizz\events.jsonl`. TLS interception and rules follow in M2. Design and milestones:
[PLAN.md](PLAN.md) and [#1](https://github.com/mycaravam-crypto/Gatewizz/issues/1).

## Usage

    gatewizz [--config gatewizz.toml]                 # run until Ctrl+C; exits 130
    gatewizz [--config gatewizz.toml] --check-config  # print the effective config; exits 0, or 2 on an error
    set HTTPS_PROXY=http://127.0.0.1:8899

Every config key is optional; [config/gatewizz.example.toml](config/gatewizz.example.toml) lists them with their
defaults. Events hold metadata only (process, host, path without query, status, coverage), never header values or
bodies.

## Build

The app targets Windows 10/11 x64. Two ways to build it:

**On Windows** (MSVC toolchain, with the Windows SDK installed through Visual Studio Build Tools):

    cargo build --release

**From Linux/WSL** (needs mingw-w64: `apt install gcc-mingw-w64-x86-64`):

    rustup target add x86_64-pc-windows-gnu
    cargo build --release --target x86_64-pc-windows-gnu

The output is a single `gatewizz.exe`.

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
