# PLAN.md: gatewizz — local HTTPS gate for code sent to AI models

The source of truth for scope is the epic, [#1](https://github.com/mycaravam-crypto/Gatewizz/issues/1). This file keeps the
engineering rules, the architecture and the status next to the code.

## 1. Goal

A loopback proxy for Windows. Tools that send code to AI models (smartwizz, testwizz, `docwizz --ai`, gitwizz, coding
agents) run through it via `HTTPS_PROXY`. It decrypts each request with a local CA, checks it against a few TOML rules,
and allows, blocks or holds it for approval before any byte goes upstream. Every decision is logged; content never is.

**Out until a concrete need:** system-wide proxy, Windows service, WFP/transparent capture, HTTP/2, QUIC, database,
web UI or API, AI analysis, Linux.

## 2. YAGNI and engineering rules

The [smartwizz engineering standard](https://github.com/mycaravam-crypto/smartwizz/blob/main/ENGINEERING_STANDARD.md)
applies. On top of it, as in reswizz and powerwizz:

1. **Build only what an acceptance criterion needs.** No stubs or scaffolding for later milestones.
2. **One crate, flat `src/`.** One file per concern; split at ~300 lines or at an `unsafe` Win32 boundary.
3. **No abstraction with one implementation.** Windows code lives in `#[cfg(windows)]` functions with a non-Windows
   fallback that returns an error. Pure logic is tested on every OS.
4. **No new dependency if std or ~30 lines covers it.**
5. **`Result<T, String>`** until a caller has to branch on distinct errors.
6. **`// ponytail:`** marks every deliberate compromise, with its limitation and upgrade path.
7. **Fail closed.** If a rule needs inspection or approval and can't get it, block.
8. **Store no content.** Events carry metadata and finding kinds, never bodies, header values or secrets.

## 3. Technology

| Part | Choice | Introduced |
|---|---|---|
| Language | Rust stable, edition 2024, single `gatewizz.exe` | M1 |
| Async / HTTP | `tokio` (minimal features), `hyper` 1 (http1) | M1 |
| Config / CLI | `serde`, `toml`, `clap` | M1 |
| Win32 | `windows-sys` (IP Helper, Threading, DPAPI, certificate store) | M1 |
| TLS | `rustls`, `tokio-rustls`, `rcgen`, `rustls-platform-verifier` | M2 |
| Approval window | `eframe`/`egui` (glow), reswizz look | M3 |

Dependencies are added by the issue that first needs them, not before.

## 4. Module layout

```
src/
├── config.rs    # TOML config: defaults, unknown keys rejected, errors name the key (#4)
├── event.rs     # JSON Lines events, metadata only; bounded queue, writer thread, size rotation (#4)
├── main.rs      # entry point, --config/--check-config, Ctrl+C drain, exit codes (0 ok, 2 failure, 130 cancelled)
├── process.rs   # client process of a loopback connection via IP Helper, keyed by (pid, start) (#5)
└── proxy.rs     # HTTP/1.1 forward proxy and CONNECT tunnels; streams bodies, never retries (#3)
```

Request framing is parsed by hyper alone and re-framed towards the upstream, so client and upstream cannot disagree
about request boundaries (no smuggling). Tests in `proxy.rs` drive the real listener against raw TCP peers.

## 5. Milestones

| Milestone | Goal | Done when | Status |
|---|---|---|---|
| **M1: See it** | Proxy, CONNECT, attribution, config, events, CI/release | `smartwizz check` works unchanged through gatewizz; each connection is logged with process and host | in progress (#2, #3, #4, #5 done) |
| **M2: Block it** | CA, TLS interception, detectors, `allow`/`block` rules | A test API key in a smartwizz diff is blocked for an unlisted endpoint and passes for an allowlisted one; the key is nowhere on disk | planned |
| **M3: Ask first** | `approve` action, egui window | A held request sends zero bytes upstream until allowed; deny and timeout both block | planned |

## 6. Quality gates

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
bash .github/scripts/semver-next.test.sh
```

**Performance budget:** under 5 ms added p50 for requests without a body, measured with powerwizz (from M1).
