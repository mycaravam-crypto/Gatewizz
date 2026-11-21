# PLAN.md: gatewizz — local security gate for outgoing traffic

The source of truth for scope is the epic, [#1](https://github.com/mycaravam-crypto/Gatewizz/issues/1). This file keeps the
engineering rules, the architecture and the status next to the code. User-facing operational documentation is indexed
in [docs/README.md](docs/README.md).
## 1. Goal

A loopback proxy for Windows, a generic gate for outgoing HTTPS traffic. Any tool can run through it via `HTTPS_PROXY`.
The motivating case is tools that send code to AI models (smartwizz, testwizz, `docwizz --ai`, gitwizz, coding agents),
but rules are not tied to AI hosts. It decrypts each request with a local CA, checks it against a few TOML rules,
and allows, blocks or holds it for approval before any byte goes upstream. Every decision is logged; content never is.

**Out until a concrete need:** system-wide proxy, Windows service, WFP/transparent capture, HTTP/2, QUIC, database,
web UI or API, AI analysis, Linux.

**Connection firewall (#56):** Phase 1, a read-only, no-admin connection monitor (`[monitor]`, #57), is in.

**Decision (2026-11-20, #59): a Windows service and WFP move from out to in, as an optional, elevated step.**
- **Why:** the proxy only governs tools that opt in through `HTTPS_PROXY`. Enforcing "these programs (for example the AI
  tools) reach the network only through Gatewizz" needs per-app connection filters, and only the Windows Filtering
  Platform (WFP) can set those without a kernel driver. Managing WFP filters needs elevation, and only a service can
  hold that while the user's app stays unprivileged.
- **Shape:** an optional service, `gatewizz-fw` (LocalSystem), installed and removed with
  `gatewizz firewall install/remove` behind a UAC prompt.
  - It owns one WFP provider and sublayer, the connection rules and the blocked-connection events.
  - The per-user tray app keeps every UI, because a service has no desktop (Session 0). The two talk over a named
    pipe whose ACL admits only the interactive user and SYSTEM.
  - The service validates every rule change it receives.
- **What stays as it was:** the proxy, the monitor and the no-admin install are unchanged. Without
  `firewall install`, nothing runs elevated.
- **Fail closed:** WFP filters are persistent, so they keep enforcing when the service is down. `default = "ask"`
  blocks when no window can ask. Gatewizz's own program is always allowed, and that rule can't be edited.
- **Still out:** our own kernel driver and packet interception. Holding a connection while the user decides is
  Phase 3 (#60), decided separately.
- **Order:** the pure rule core lands first (`firewall.rs`, every OS). Next is `firewall apply/remove/status`,
  which installs the rules as WFP filters from an elevated prompt (`wfp.rs`; Windows CI runs elevated). The
  `[firewall]` and `[[connection_rules]]` keys arrive in that step, because it is the first one that uses them.
  Then come the service and the pipe, which keep program paths and host IPs current, and last the prompt and
  config write-back.

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
| Config / CLI | `serde`, `toml`; flags are hand-rolled (four flags do not justify `clap`) | M1 |
| Win32 | `windows-sys` (IP Helper, Threading, DPAPI, certificate store) | M1 |
| TLS | `rustls`, `tokio-rustls`, `rcgen`, `rustls-platform-verifier` | M2 |
| Approval window | `eframe`/`egui` (glow), reswizz look | M3 |

Dependencies are added by the issue that first needs them, not before.

## 4. Module layout

```
src/
├── approve.rs   # approval queue: hold, allow once/deny/allow for N min; timeout, full, no window, pause block (#34)
├── ca.rs        # local CA: generation, leaf issuance and cache, DPAPI key file, CurrentUser Root store (#18)
├── config.rs    # TOML config: defaults, unknown keys rejected, errors name the key (#4)
├── connections.rs # connection monitor: TCP table sampling, snapshot diff, rate limit, live list (#57)
├── wfp.rs       # WFP provider, sublayer and filters for `firewall apply/remove/status` (Windows, elevated; #59)
├── dns.rs       # IP → hostname cache for the monitor, filled from the Windows DNS Client cache (#57)
├── firewall.rs  # connection rules: matching, precedence, expiry, WFP filter plan, notice coalescing (pure; #59)
├── detect.rs    # body buffering up to max_body_bytes; secret and AI-request detectors, kinds and counts only (#20)
├── elevate.rs   # UAC self-elevation for the firewall commands; output relayed over a private pipe (#59)
├── event.rs     # JSON Lines events, metadata only; bounded queue, writer thread, size rotation (#4)
├── main.rs      # entry point, --config/--check-config, Ctrl+C drain, exit codes (0 ok, 2 failure, 130 cancelled)
├── pipe.rs      # the firewall service's named pipe to the tray app: ACL, single client, device→DOS paths (Windows; #59)
├── process.rs   # client process of a loopback connection via IP Helper, keyed by (pid, start) (#5)
├── rules.rs     # allow/block rules: pure decide(), block beats allow, fail closed on unknown facts (#21)
├── prompt.rs    # firewall prompt protocol: notices, decisions validated against sent notices, the tray's inbox (#59)
├── proxy.rs     # HTTP/1.1 forward proxy and CONNECT tunnels; streams bodies, never retries (#3)
├── tls.rs       # CONNECT interception: leaf per host, verified upstream TLS, http/1.1 only, tunnel_hosts (#19)
├── service.rs   # firewall service gatewizz-fw: protected copy in Program Files, refresh loop, install/remove (#59)
├── startup.rs   # per-user Run registration and per-session single-instance mutex (Windows only)
└── ui.rs        # tray icon, approval window, activity history with filters and CSV copy, Network tab (eframe/egui, tray-icon; Windows only); proxy on its own thread (#35, #45, #51, #53, #57)
```

Request framing is parsed by hyper alone and re-framed towards the upstream, so client and upstream cannot disagree
about request boundaries (no smuggling). Tests in `proxy.rs` drive the real listener against raw TCP peers.

## 5. Milestones

| Milestone | Goal | Done when | Status |
|---|---|---|---|
| **M1: See it** | Proxy, CONNECT, attribution, config, events, CI/release | `smartwizz check` works unchanged through gatewizz; each connection is logged with process and host | code complete and released; real-Windows acceptance pending (#17) |
| **M2: Block it** | CA, TLS interception, detectors, `allow`/`block` rules | A test API key in a smartwizz diff is blocked for an unlisted endpoint and passes for an allowlisted one; the key is nowhere on disk | code complete; automated acceptance covered by `m2_secret_reaches_only_the_allowlisted_model_host`; real-Windows smartwizz acceptance pending (#22) |
| **M3: Ask first** | `approve` action, egui approval window, tray icon and menu (pause/resume, open log, copy proxy address, quit), app icon and manifest | A held request sends zero bytes upstream until allowed; deny and timeout both block; the tray shows and opens a waiting approval | implementation merged (#37–#43); approval lifecycle regression tests and embedded manifest-resource verification added; per-user login startup and single-instance lifecycle implemented and CI-verified in #46; workspace with activity history and redesign merged (#51, #53–#55, #58); real-Windows UI and startup acceptance remain open in #35 and #36 |
| **F1: See every connection** (#56 Phase 1) | Read-only connection monitor: TCP tables per process, DNS-cache hostnames, `connection` events, Network tab | Every outgoing TCP connection is visible with its process and, where the DNS cache knows it, its hostname, without admin rights | implemented (#57); Windows CI test for the sampler; manual acceptance and overhead measurement pending |
| **F2: Decide every connection** (#56 Phase 2) | Optional elevated service with WFP per-app rules, block-then-ask prompt, proxy-enforcement preset | Unknown connections are blocked and prompted; rules persist; the wizz tools reach the network only through the proxy | rule core in (`firewall.rs`); `firewall apply/remove/status` installs persistent WFP filters (`wfp.rs`, elevated Windows CI test); `firewall install` runs the `gatewizz-fw` service from `%ProgramFiles%\Gatewizz` and keeps the filters current (`service.rs`, CI service smoke test); the service logs connections its filters block (WFP drop events, elevated CI test); it serves the prompt pipe, validates decisions and writes rules back (`pipe.rs`, `prompt.rs`, pipe ACL test); `ask` rules prompt and `block` rules stay silent; the tray app asks in the Overview queue (`ui.rs`, pipe client test); manual Windows acceptance next (#59) |

## 6. Quality gates

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
bash .github/scripts/semver-next.test.sh
```

**Performance budget:** under 5 ms added p50 for requests without a body (from M1). `proxy::tests::bodyless_requests_stay_within_the_latency_budget` checks it on every CI run (direct vs proxied keep-alive GETs on loopback; print the numbers with `cargo test --release latency -- --nocapture`). Real-world overhead is measured with powerwizz.

**Manual acceptance:** `scripts/windows-acceptance.ps1` runs the remaining real-Windows checks of M1–M3 (#17, #22, #35, #36), the monitor (#57) and, with `-Firewall`, F2 (#59) and writes a report for the issues; CI smoke-tests the release binary's CLI with `.github/scripts/windows-cli-smoke.ps1`.
