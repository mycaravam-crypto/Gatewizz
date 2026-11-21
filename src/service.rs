//! The optional firewall service `gatewizz-fw` (#59): it keeps the WFP filters in line with the connection rules as
//! programs appear and host addresses change.
//!
//! Security: the service runs as LocalSystem, so it must never run a binary or read rules that a normal user can
//! write. The per-user install (`%LOCALAPPDATA%\Programs\Gatewizz`) is user-writable. `firewall install` therefore
//! copies the executable and the configuration into [`home`] (`%ProgramFiles%\Gatewizz`, writable by
//! administrators only), and the service runs and reads only from there. Rule changes reach it the same way, through
//! an elevated `firewall apply`.
//!
//! The service needs no UI: it re-applies the rules every [`REFRESH`] and on a reload request, and logs to
//! `home\service.log`. WFP filters are persistent, so they stay in force while the service is stopped (fail closed).
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::config::Config;
use crate::{firewall, wfp};

pub const NAME: &str = "gatewizz-fw";

/// How often the service resolves program paths and host addresses again.
pub const REFRESH: Duration = Duration::from_secs(60);

/// The service control code for "read the protected configuration again and apply it now" (codes 128-255 are the
/// service's own).
const RELOAD: u32 = 128;

/// The log is rotated once past this size, so it never grows without bound.
const LOG_MAX: u64 = 256 * 1024;

/// `%ProgramFiles%\Gatewizz`: where the service's executable, configuration and log live.
pub fn home() -> PathBuf {
    let root = std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
    PathBuf::from(root).join("Gatewizz")
}

fn protected_exe() -> PathBuf {
    home().join("gatewizz.exe")
}

fn protected_config() -> PathBuf {
    home().join("firewall.toml")
}

/// Executables that are always allowed, besides the service's own: the copies `firewall install`/`apply` ran from,
/// which is where the tray app and proxy run. One path per line.
fn self_paths_file() -> PathBuf {
    home().join("self-paths.txt")
}

/// Turns `[[connection_rules]]` into WFP filters and installs them, replacing the previous set. Host names are
/// resolved now, and program file names to the paths on `PATH` or of running processes; what cannot be resolved is
/// reported, since those parts of the rules are not enforced until a later apply finds them.
pub fn apply_config(config: &Config, own_paths: &[String]) -> Result<String, String> {
    apply_plan(config, own_paths).map(|(summary, _)| summary)
}

/// [`apply_config`], also returning the filters it installed: the hold classifies connections against them.
fn apply_plan(
    config: &Config,
    own_paths: &[String],
) -> Result<(String, Vec<firewall::Filter>), String> {
    let rules = &config.connection_rules;
    let now = SystemTime::now();
    // Read once per apply: the names wildcard host rules expand to.
    let cached = crate::dns::cached_hosts();
    let resolve_host = |host: &str| resolve_host(host, &cached, lookup);
    let filters = firewall::plan(
        rules,
        config.firewall.default,
        own_paths,
        now,
        resolve_host,
        wfp::program_paths,
    );
    let applied = wfp::apply(wfp::KEYS, &filters)?;
    let mut unresolved_hosts: Vec<&str> = rules
        .iter()
        .flat_map(|r| r.host.iter())
        .map(String::as_str)
        .filter(|h| resolve_host(h).is_empty())
        .collect();
    unresolved_hosts.sort_unstable();
    unresolved_hosts.dedup();
    let summary = summary(
        &applied,
        rules.len(),
        config.firewall.default,
        &firewall::unresolved(rules, now, wfp::program_paths),
        &unresolved_hosts,
    );
    Ok((summary, filters))
}

/// What `apply` reports: the filter count and the default, then one warning per program, host or path that is not
/// enforced, since the user must know which parts of their rules do nothing yet.
fn summary(
    applied: &wfp::Applied,
    rules: usize,
    default: firewall::DefaultAction,
    unresolved_programs: &[String],
    unresolved_hosts: &[&str],
) -> String {
    let mut out = format!(
        "Applied {} Windows filter(s) for {rules} connection rule(s); connections no rule matches are {}.",
        applied.filters,
        match default {
            firewall::DefaultAction::Allow => "allowed",
            firewall::DefaultAction::Block => "blocked",
            firewall::DefaultAction::Ask =>
                "blocked, and the tray app asks about them while it runs",
        }
    );
    for program in unresolved_programs {
        out.push_str(&format!(
            "\nwarning: {program} is neither on PATH nor running, so its rules are not enforced yet. Use its full \
             path in `process`, or let the service find it once it runs."
        ));
    }
    for host in unresolved_hosts {
        out.push_str(&format!(
            "\nwarning: {host} has no IP address now (a wildcard covers only names in the DNS cache), so its rules \
             are not enforced yet. Use `ip` for addresses that must be covered."
        ));
    }
    for path in &applied.skipped {
        out.push_str(&format!(
            "\nwarning: {path} does not exist; its filters were skipped."
        ));
    }
    out
}

/// The addresses a host name resolves to now. A wildcard (`*.example.com`) resolves through the matching names in
/// `cached`, the DNS Client cache's names.
fn resolve_host(
    host: &str,
    cached: &[String],
    lookup: impl Fn(&str) -> Vec<IpAddr>,
) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = if host.starts_with("*.") {
        // A wildcard names no single host: it covers the matching names this machine has looked up lately, as the
        // DNS Client cache lists them. A name looked up later is covered from the next refresh (60 s) on.
        cached
            .iter()
            .filter(|name| crate::tls::host_matches(host, name))
            .flat_map(|name| lookup(name))
            .collect()
    } else {
        lookup(host)
    };
    ips.sort();
    ips.dedup();
    ips
}

/// The addresses a host name resolves to now, through the system resolver.
fn lookup(host: &str) -> Vec<IpAddr> {
    (host, 0)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

fn current_exe() -> Result<String, String> {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| format!("[firewall] cannot locate gatewizz.exe: {e}"))
}

fn same_file(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

/// The configuration text to install: the given file, validated; without one, the protected copy when `keep` says
/// it is the current rule set (the service is installed), so `apply` or `install` without `--config` never wipes
/// the rules; otherwise the defaults (no rules).
fn rules_to_apply(config_path: Option<&Path>, keep: bool) -> Result<String, String> {
    let given = config_path.map(read_valid).transpose()?;
    let existing = if keep && given.is_none() {
        std::fs::read_to_string(protected_config()).ok()
    } else {
        None
    };
    Ok(choose_rules(given, existing))
}

/// `--config` wins; then the existing protected copy; then the defaults.
fn choose_rules(given: Option<String>, existing: Option<String>) -> String {
    given.or(existing).unwrap_or_default()
}

/// Reads and validates a configuration file, so only a valid one ever reaches the protected copy.
fn read_valid(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("[config] cannot read {}: {e}", path.display()))?;
    Config::parse(&text).map_err(|e| format!("[config] {}: {e}", path.display()))?;
    Ok(text)
}

/// Writes the protected configuration and the list of self paths, replacing them atomically.
fn write_protected(config_text: &str, self_paths: &[String]) -> Result<(), String> {
    let dir = home();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("[firewall] cannot create {}: {e}", dir.display()))?;
    write_atomic(&protected_config(), config_text)?;
    write_atomic(&self_paths_file(), &(self_paths.join("\n") + "\n"))
}

fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)
        .map_err(|e| format!("[firewall] cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("[firewall] cannot replace {}: {e}", path.display()))
}

/// Everything the service allows as "Gatewizz itself": its own copy and the recorded user copies.
fn service_self_paths() -> Vec<String> {
    let recorded = std::fs::read_to_string(self_paths_file()).unwrap_or_default();
    let mut paths = vec![protected_exe().to_string_lossy().into_owned()];
    paths.extend(parse_self_paths(&recorded));
    paths
}

/// The non-empty, trimmed lines of the self-paths file.
fn parse_self_paths(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

/// The recorded self paths plus `me`, unless `me` is the service's own copy or already recorded (case-insensitive,
/// as Windows paths are).
fn merge_self_paths(mut recorded: Vec<String>, me: &str, protected: &Path) -> Vec<String> {
    if !same_file(Path::new(me), protected) && !recorded.iter().any(|p| p.eq_ignore_ascii_case(me))
    {
        recorded.push(me.to_string());
    }
    recorded
}

/// The self paths after this run: the recorded ones plus the executable running now (the user's copy).
fn merged_self_paths() -> Result<Vec<String>, String> {
    let recorded = std::fs::read_to_string(self_paths_file()).unwrap_or_default();
    Ok(merge_self_paths(
        parse_self_paths(&recorded),
        &current_exe()?,
        &protected_exe(),
    ))
}

/// Appends a line to the service log. Best effort: a failing log never stops the service.
fn log(line: &str) {
    log_to(&home().join("service.log"), LOG_MAX, line);
}

/// Appends one timestamped line (newlines folded) to `path`, first moving a file past `max` bytes to `<path>.1`, so
/// the log never takes more than about twice `max`.
fn log_to(path: &Path, max: u64, line: &str) {
    use std::io::Write;
    if std::fs::metadata(path).is_ok_and(|m| m.len() > max) {
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        let _ = std::fs::rename(path, rotated);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{} {}", crate::event::now(), line.replace('\n', " | "));
    }
}

/// One refresh in the service: read the protected configuration and apply it.
fn refresh() -> Result<String, String> {
    let mut config = Config::load(&protected_config())?;
    config
        .connection_rules
        .extend(temporary_rules(SystemTime::now()));
    let (summary, filters) = apply_plan(&config, &service_self_paths())?;
    #[cfg(windows)]
    holding::sync(&config.firewall, filters);
    #[cfg(not(windows))]
    drop(filters);
    Ok(summary)
}

/// Rules from the prompt that expire ("once", "for N minutes"): kept in the service's memory only, so a restart
/// drops them. Permanent ones are written to the protected configuration instead.
static TEMPORARY: std::sync::Mutex<Vec<firewall::Rule>> = std::sync::Mutex::new(Vec::new());

/// The temporary rules still in force, forgetting the expired ones.
fn temporary_rules(now: SystemTime) -> Vec<firewall::Rule> {
    let mut rules = TEMPORARY.lock().unwrap_or_else(|e| e.into_inner());
    keep_unexpired(&mut rules, now);
    rules.clone()
}

/// Drops the rules whose expiry has passed; a rule without one never expires.
fn keep_unexpired(rules: &mut Vec<firewall::Rule>, now: SystemTime) {
    rules.retain(|r| r.expires.is_none_or(|at| now < at));
}

/// Appends a permanent rule from the prompt to the protected configuration, keeping the user's text, and refuses
/// the change unless the result is a valid configuration.
fn append_rule(rule: &firewall::Rule) -> Result<(), String> {
    let path = protected_config();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    match with_rule(&text, rule)? {
        Added::Appended(new) => write_atomic(&path, &new),
        Added::Rewritten(new) => {
            // The rewrite drops comments and layout, so the original is kept next to it.
            write_atomic(&path.with_extension("toml.bak"), &text)?;
            write_atomic(&path, &new)
        }
    }
}

/// A configuration text with one more connection rule.
#[derive(Debug, PartialEq)]
enum Added {
    /// The rule appended as a `[[connection_rules]]` table: the user's text and comments stay as they are.
    Appended(String),
    /// Appending would not parse (the file writes `connection_rules = [...]` inline), so the whole configuration
    /// was serialized again with the rule added.
    Rewritten(String),
}

fn with_rule(text: &str, rule: &firewall::Rule) -> Result<Added, String> {
    let appended = format!("{text}{}", crate::prompt::rule_toml(rule));
    if Config::parse(&appended).is_ok() {
        return Ok(Added::Appended(appended));
    }
    let mut config = Config::parse(text)
        .map_err(|e| format!("[firewall] the protected configuration is not valid: {e}"))?;
    config.connection_rules.push(rule.clone());
    let rewritten = format!(
        "# Rewritten by the firewall prompt to add {}; the previous file is firewall.toml.bak.\n{}",
        rule.id,
        config.effective()
    );
    Config::parse(&rewritten)
        .map_err(|e| format!("[firewall] the prompt's rule would not be valid: {e}"))?;
    Ok(Added::Rewritten(rewritten))
}

/// `firewall apply`: with the service installed, update its protected configuration and ask it to reload, then apply
/// right away too. Without the service, apply once.
pub fn apply(config_path: Option<&Path>) -> Result<String, String> {
    let installed = status()?.is_some();
    let config_text = rules_to_apply(config_path, installed)?;
    let config = Config::parse(&config_text)?;
    if installed {
        let self_paths = merged_self_paths()?;
        write_protected(&config_text, &self_paths)?;
        let holding = install_windivert(&config)?;
        let mut all = service_self_paths();
        all.truncate(1);
        all.extend(self_paths);
        let out = apply_config(&config, &all)?;
        sys::control(RELOAD)?;
        Ok(out
            + "\nThe firewall service keeps these rules current."
            + &holding.map(|h| format!("\n{h}")).unwrap_or_default())
    } else {
        apply_config(&config, &[current_exe()?])
    }
}

/// `firewall status`: the service state and the installed filters.
pub fn describe() -> Result<String, String> {
    let filters = match wfp::installed(wfp::KEYS)? {
        Some(n) => format!("installed with {n} filter(s)"),
        None => "not installed".into(),
    };
    let service = match status()? {
        Some(state) => format!("{state}, running from {}", home().display()),
        None => "not installed".into(),
    };
    Ok(format!(
        "Gatewizz firewall filters: {filters}.\nFirewall service {NAME}: {service}."
    ))
}

/// The service's state (`running`, `stopped`, ...), or `None` when it is not installed.
pub fn status() -> Result<Option<&'static str>, String> {
    sys::state()
}

#[cfg(windows)]
pub fn install(config_path: Option<&Path>) -> Result<String, String> {
    let config_text = rules_to_apply(config_path, true)?;
    let self_paths = merged_self_paths()?;
    let existed = status()?.is_some();
    if existed {
        // The running service holds its executable open; stop it to replace the file.
        sys::stop()?;
    }
    let me = std::env::current_exe()
        .map_err(|e| format!("[firewall] cannot locate gatewizz.exe: {e}"))?;
    write_protected(&config_text, &self_paths)?;
    if !same_file(&me, &protected_exe()) {
        std::fs::copy(&me, protected_exe()).map_err(|e| {
            format!(
                "[firewall] cannot copy gatewizz.exe to {}: {e}",
                home().display()
            )
        })?;
    }
    let holding = install_windivert(&Config::parse(&config_text)?)?;
    if !existed {
        sys::create(&protected_exe())?;
    }
    sys::start()?;
    Ok(format!(
        "Installed the firewall service {NAME}, running from {}. It applies the connection rules now and keeps \
         them current every {} s; `gatewizz firewall apply --config <path>` changes them.{}",
        home().display(),
        REFRESH.as_secs(),
        holding.map(|h| format!("\n{h}")).unwrap_or_default()
    ))
}

/// With `[firewall] hold`, puts the pinned WinDivert files (#60) into [`home`], from next to this `gatewizz.exe`,
/// unless the copies there are already the pinned ones: a loaded driver's file cannot be replaced, and need not be.
#[cfg(windows)]
fn install_windivert(config: &Config) -> Result<Option<String>, String> {
    if !config.firewall.hold || crate::divert::verify(&home()).is_ok() {
        return Ok(None);
    }
    let me = std::env::current_exe()
        .map_err(|e| format!("[firewall] cannot locate gatewizz.exe: {e}"))?;
    let source = me.parent().unwrap_or(Path::new("."));
    crate::divert::verify(source).map_err(|e| {
        format!(
            "{e}\n[firewall] `hold = true` needs WinDivert.dll and WinDivert64.sys (WinDivert 2.2.2-A, attached to \
             every Gatewizz release) next to {}",
            me.display()
        )
    })?;
    for (name, _) in crate::divert::FILES {
        std::fs::copy(source.join(name), home().join(name))
            .map_err(|e| format!("[firewall] cannot copy {name} to {}: {e}", home().display()))?;
    }
    // Checked again where the service loads them from.
    crate::divert::verify(&home())?;
    Ok(Some(format!(
        "Copied WinDivert 2.2.2-A to {} for holding connections while the tray app asks.",
        home().display()
    )))
}

/// `firewall remove`: stop and delete the service, remove every filter, and delete the protected copy.
#[cfg(windows)]
pub fn uninstall() -> Result<String, String> {
    let had_service = status()?.is_some();
    if had_service {
        sys::stop()?;
        sys::delete()?;
    }
    let removed = wfp::remove(wfp::KEYS)?;
    // A loaded WinDivert driver keeps its file open; with no handle left (the service stopped), it can be unloaded.
    sys::stop_windivert();
    let dir = home();
    if dir.exists() {
        // The service process can hold its executable for a moment after it reports stopped.
        let mut last = Ok(());
        for _ in 0..20 {
            last = std::fs::remove_dir_all(&dir);
            if last.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        last.map_err(|e| format!("[firewall] cannot delete {}: {e}", dir.display()))?;
    }
    Ok(format!(
        "Removed {removed} Gatewizz firewall filter(s){}. Gatewizz no longer filters connections.",
        if had_service {
            format!(" and the service {NAME}")
        } else {
            String::new()
        }
    ))
}

/// How long repeated drops of one program to one host and port fold into a single notice.
const NOTICE_WINDOW: Duration = Duration::from_secs(60);

/// The drop-event subscription and the thread that turns Gatewizz's drops into notices.
#[cfg(windows)]
struct DropWatch {
    subscription: wfp::Subscription,
    thread: std::thread::JoinHandle<()>,
}

#[cfg(windows)]
impl DropWatch {
    /// Unsubscribes, which closes the channel and ends the thread.
    fn stop(self) {
        drop(self.subscription);
        let _ = self.thread.join();
    }
}

/// Watches WFP drop events and logs one "blocked" notice per program, host and port and [`NOTICE_WINDOW`]. Only
/// drops by Gatewizz's own filters count; their ids change on every apply, so an unknown id re-reads them (at most
/// once a second).
/// With `prompt`, a new notice from an asking filter (an `ask` rule or default) also goes to the connected tray
/// app, when the program's DOS path is known (the rule it may become needs it). Drops by `block` rules, the
/// user's own and "Deny always" from the prompt, stay silent.
#[cfg(windows)]
fn watch_drops(prompt: Option<std::sync::Arc<PromptState>>) -> Result<DropWatch, String> {
    let (tx, rx) = std::sync::mpsc::channel::<wfp::Dropped>();
    let subscription = wfp::subscribe_drops(tx)?;
    let thread = std::thread::Builder::new()
        .name("drops".into())
        .spawn(move || {
            let mut notices = firewall::Coalescer::new(NOTICE_WINDOW, 1024);
            let mut ids = wfp::filter_ids(wfp::KEYS).unwrap_or_default();
            let mut ids_read = std::time::Instant::now();
            for dropped in rx {
                if !ids.contains_key(&dropped.filter_id)
                    && ids_read.elapsed() >= Duration::from_secs(1)
                {
                    ids = wfp::filter_ids(wfp::KEYS).unwrap_or_default();
                    ids_read = std::time::Instant::now();
                }
                let Some(&asks) = ids.get(&dropped.filter_id) else {
                    continue;
                };
                let host = dropped.remote.to_string();
                if notices.push(
                    dropped.program(),
                    &host,
                    dropped.port,
                    std::time::Instant::now(),
                ) {
                    log(&blocked_line(&dropped));
                    if let Some(prompt) = prompt.as_ref().filter(|_| asks) {
                        prompt.offer(&dropped);
                    }
                }
            }
        })
        .map_err(|e| format!("[firewall] cannot start the drop watcher: {e}"))?;
    Ok(DropWatch {
        subscription,
        thread,
    })
}

/// What the prompt needs while the service runs: the notices sent, the pipe, and the drive map for device paths.
#[cfg(windows)]
struct PromptState {
    outstanding: std::sync::Mutex<crate::prompt::Outstanding>,
    server: crate::pipe::Server,
    drives: Vec<(String, String)>,
}

#[cfg(windows)]
impl PromptState {
    /// Sends a notice for a blocked connection to the tray app, if one is connected and the program's path is
    /// known. Without a tray app nothing is asked and the connection stays blocked (fail closed).
    fn offer(&self, d: &wfp::Dropped) {
        if !self.server.connected() {
            return;
        }
        let Some(path) = crate::pipe::device_to_dos(&d.app, &self.drives) else {
            log(&format!(
                "not prompting for {}: no drive letter for its path",
                d.app
            ));
            return;
        };
        let protocol = match d.protocol {
            6 => firewall::Protocol::Tcp,
            17 => firewall::Protocol::Udp,
            _ => firewall::Protocol::Any,
        };
        let notice = self
            .outstanding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .add(
                d.program(),
                &path,
                d.remote,
                d.port,
                protocol,
                std::time::Instant::now(),
            );
        self.server.send(&crate::prompt::Message::Notice(notice));
    }

    /// Sends a notice for a connection the hold keeps waiting (#60). `path` is the program's DOS path.
    fn offer_held(&self, path: &str, remote: std::net::SocketAddr) {
        let mut notice = self
            .outstanding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .add(
                firewall::file_name(path),
                path,
                remote.ip(),
                remote.port(),
                firewall::Protocol::Tcp,
                std::time::Instant::now(),
            );
        notice.held = true;
        self.server.send(&crate::prompt::Message::Notice(notice));
    }

    /// Applies one decision from the tray app: validated against the notices sent, then written down (permanent)
    /// or kept in memory (temporary), then applied by a reload. The tray app gets the outcome either way.
    fn decide(&self, decision: &crate::prompt::Decision) {
        let change = self
            .outstanding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .answer(decision, std::time::Instant::now(), SystemTime::now());
        let outcome = change.and_then(|change| {
            if change.permanent {
                append_rule(&change.rule)?;
            } else {
                TEMPORARY
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(change.rule.clone());
            }
            sys::control(RELOAD)?;
            Ok(format!("rule {} added", change.rule.id))
        });
        let (ok, message) = match outcome {
            Ok(m) => (true, m),
            Err(e) => (false, e),
        };
        log(&format!("prompt decision {}: {message}", decision.id));
        self.server.send(&crate::prompt::Message::Result {
            id: decision.id,
            ok,
            message,
        });
    }
}

/// Hold-and-ask (#60): with `[firewall] hold`, the SYN of each new TCP connection an `ask` filter covers waits while
/// the tray app asks, and goes on or is refused by what the rules say after the answer.
///
/// Fail closed throughout: the persistent `ask` filters keep blocking at connect, and only this module's dynamic WFP
/// session lets their TCP through, for as long as it holds. It is removed first on every way out.
#[cfg(windows)]
mod holding {
    use super::{PromptState, firewall, home, log, wfp};
    use crate::divert::{self, Address, Divert};
    use crate::hold::{self, Offer, Queue, Step, Syn};
    use firewall::{Filter, Protocol, RuleAction};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    /// Held connections at most; more are refused (fail closed).
    const QUEUE_MAX: usize = 256;
    /// How often timed-out connections are refused.
    const TICK: Duration = Duration::from_millis(250);

    fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What the running hold shares between its threads.
    struct Inner {
        divert: Divert,
        /// Held SYNs, with the address to send them on and the program that opened them.
        queue: Mutex<Queue<(Address, String)>>,
        /// The filters in force, which every SYN is classified against.
        filters: Mutex<Vec<Filter>>,
        prompt: Arc<PromptState>,
        stopping: AtomicBool,
    }

    struct Running {
        inner: Arc<Inner>,
        session: wfp::Session,
        threads: Vec<std::thread::JoinHandle<()>>,
    }

    /// The tray's prompt, once the service started it; holding asks through it.
    static PROMPT: Mutex<Option<Arc<PromptState>>> = Mutex::new(None);
    static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

    pub fn set_prompt(prompt: Arc<PromptState>) {
        *locked(&PROMPT) = Some(prompt);
    }

    /// After every refresh: start, update or stop holding to match the configuration and the new filters. Errors
    /// are logged and leave holding off, which is Phase 2's block-then-ask.
    pub fn sync(config: &crate::config::Firewall, filters: Vec<Filter>) {
        let mut running = locked(&RUNNING);
        let prompt = locked(&PROMPT).clone();
        match (config.hold, prompt, running.as_mut()) {
            (true, _, Some(r)) => {
                if let Err(err) = r.update(filters) {
                    log(&format!(
                        "error: {err}; holding stops, ask connections are blocked"
                    ));
                    if let Some(r) = running.take() {
                        r.stop();
                    }
                }
            }
            (true, Some(prompt), None) => {
                let timeout = Duration::from_secs(config.hold_timeout_secs);
                match Running::start(prompt, filters, timeout) {
                    Ok(r) => {
                        log("holding new connections that ask rules cover while the tray app asks");
                        *running = Some(r);
                    }
                    Err(err) => log(&format!(
                        "error: {err}; connections are not held, ask blocks"
                    )),
                }
            }
            (false, _, Some(_)) => {
                if let Some(r) = running.take() {
                    r.stop();
                    log("holding is off");
                }
            }
            _ => {}
        }
    }

    /// On service stop.
    pub fn stop() {
        if let Some(r) = locked(&RUNNING).take() {
            r.stop();
        }
    }

    impl Running {
        fn start(
            prompt: Arc<PromptState>,
            filters: Vec<Filter>,
            timeout: Duration,
        ) -> Result<Self, String> {
            let divert = Divert::open(&home(), divert::HOLD_FILTER, 0)?;
            let mut session = wfp::Session::open()?;
            session.replace(wfp::KEYS, &firewall::hold_permits(&filters))?;
            let inner = Arc::new(Inner {
                divert,
                queue: Mutex::new(Queue::new(QUEUE_MAX, timeout)),
                filters: Mutex::new(filters),
                prompt,
                stopping: AtomicBool::new(false),
            });
            let (recv, tick) = (inner.clone(), inner.clone());
            let threads = vec![
                std::thread::Builder::new()
                    .name("hold".into())
                    .spawn(move || recv.receive())
                    .map_err(|e| format!("[firewall] cannot start the hold: {e}"))?,
                std::thread::Builder::new()
                    .name("hold-timeouts".into())
                    .spawn(move || {
                        while !tick.stopping.load(Ordering::SeqCst) {
                            std::thread::sleep(TICK);
                            let expired = locked(&tick.queue).expired(Instant::now());
                            for held in expired {
                                tick.refuse(
                                    &held.syn,
                                    &held.address.0,
                                    &held.address.1,
                                    "nobody answered in time",
                                );
                            }
                        }
                    })
                    .map_err(|e| format!("[firewall] cannot start the hold: {e}"))?,
            ];
            Ok(Self {
                inner,
                session,
                threads,
            })
        }

        /// New filters after a refresh: new permits, and every held connection decided again. Those the rules
        /// now decide go on or are refused; those still asking keep waiting.
        fn update(&mut self, filters: Vec<Filter>) -> Result<(), String> {
            self.session
                .replace(wfp::KEYS, &firewall::hold_permits(&filters))?;
            *locked(&self.inner.filters) = filters;
            let filters = locked(&self.inner.filters).clone();
            let next = |h: &hold::Held<(Address, String)>| {
                hold::after_change(action(&filters, &h.address.1, &h.syn))
            };
            let decided = locked(&self.inner.queue).take(|h| next(h).is_some());
            for held in decided {
                match next(&held) {
                    Some(Step::Refuse(why)) => {
                        self.inner
                            .refuse(&held.syn, &held.address.0, &held.address.1, why)
                    }
                    _ => self.inner.release(
                        &held.packet,
                        &held.address.0,
                        &held.address.1,
                        &held.syn,
                    ),
                }
            }
            Ok(())
        }

        /// Permits first, so nothing passes unheld once holding ends; then every waiting connection is refused.
        fn stop(self) {
            let Self {
                inner,
                session,
                threads,
            } = self;
            drop(session);
            inner.stopping.store(true, Ordering::SeqCst);
            // Taken out first: refusing locks the queue again.
            let waiting = locked(&inner.queue).take(|_| true);
            for held in waiting {
                inner.refuse(
                    &held.syn,
                    &held.address.0,
                    &held.address.1,
                    "the service stopped",
                );
            }
            inner.divert.stop();
            for t in threads {
                let _ = t.join();
            }
        }
    }

    /// What the filters say about a TCP connection from `program`.
    fn action(filters: &[Filter], program: &str, syn: &Syn) -> Option<RuleAction> {
        firewall::classify(
            filters,
            program,
            syn.remote.ip(),
            syn.remote.port(),
            Protocol::Tcp,
        )
        .map(|f| f.action)
    }

    /// The DOS path of the program that opened the connection from `local`: its row in the TCP table, which lists
    /// a connection from its SYN on.
    fn owner(local: std::net::SocketAddr) -> Option<String> {
        let pid = crate::connections::tcp_rows()
            .ok()?
            .into_iter()
            .find(|r| r.local == local)?
            .pid;
        let start = crate::process::start_time(pid)?;
        match crate::process::describe_pid(pid, start) {
            crate::process::Process::Known { image, .. } => Some(image),
            crate::process::Process::Unknown(_) => None,
        }
    }

    impl Inner {
        fn receive(&self) {
            let mut buf = vec![0u8; divert::MTU_MAX];
            while let Some((len, address)) = self.divert.recv(&mut buf) {
                let packet = &buf[..len];
                let Some(syn) = hold::parse_syn(packet) else {
                    // The filter only takes SYNs; anything else goes on unchanged.
                    let _ = self.divert.send(packet, &address);
                    continue;
                };
                let settled = locked(&self.queue).settled(syn.key(), Instant::now());
                let filters = locked(&self.filters).clone();
                let could_ask = settled.is_none() && firewall::could_ask(&filters, syn.remote);
                // The program is looked up only when an ask filter could cover the connection.
                let program = if could_ask { owner(syn.local) } else { None };
                let facts = hold::Facts {
                    settled,
                    could_ask,
                    action: action(&filters, program.as_deref().unwrap_or(""), &syn),
                    program_known: program.is_some(),
                    can_ask: self.prompt.server.connected()
                        && !self.stopping.load(Ordering::SeqCst),
                };
                let program = program.unwrap_or_else(|| "unknown program".into());
                match hold::step(facts) {
                    Step::Pass => {
                        let _ = self.divert.send(packet, &address);
                    }
                    Step::Hold => self.ask(syn, packet, address, program),
                    Step::Refuse(why) => self.refuse(&syn, &address, &program, why),
                }
            }
        }

        fn ask(&self, syn: Syn, packet: &[u8], address: Address, program: String) {
            let offer = locked(&self.queue).offer(
                syn,
                packet.to_vec(),
                (address, program.clone()),
                Instant::now(),
            );
            match offer {
                Offer::Held => {
                    log(&format!(
                        "holding: {} -> {}",
                        firewall::file_name(&program),
                        syn.remote
                    ));
                    self.prompt.offer_held(&program, syn.remote);
                }
                // The held SYN answers for its retransmissions.
                Offer::Retransmit => {}
                Offer::Full => {
                    self.refuse(&syn, &address, &program, "too many connections waiting")
                }
            }
        }

        fn release(&self, packet: &[u8], address: &Address, program: &str, syn: &Syn) {
            locked(&self.queue).settle(syn.key(), true, Instant::now());
            match self.divert.send(packet, address) {
                Ok(()) => log(&format!(
                    "released: {} -> {}",
                    firewall::file_name(program),
                    syn.remote
                )),
                Err(err) => log(&format!(
                    "error: {err}; {} -> {} was not released",
                    firewall::file_name(program),
                    syn.remote
                )),
            }
        }

        /// Answers the SYN with a RST: the program's connect fails at once with "connection refused".
        fn refuse(&self, syn: &Syn, address: &Address, program: &str, why: &str) {
            locked(&self.queue).settle(syn.key(), false, Instant::now());
            let sent = self.divert.send(&hold::rst_for(syn), &address.reply());
            log(&format!(
                "refused ({why}): {} -> {}{}",
                firewall::file_name(program),
                syn.remote,
                match sent {
                    Ok(()) => String::new(),
                    Err(err) => format!("; {err}"),
                }
            ));
        }
    }
}

/// The pipe server and the thread that applies the tray app's decisions.
#[cfg(windows)]
struct Prompt {
    state: std::sync::Arc<PromptState>,
    thread: std::thread::JoinHandle<()>,
}

#[cfg(windows)]
fn start_prompt() -> Result<Prompt, String> {
    let (tx, rx) = std::sync::mpsc::channel::<crate::prompt::Decision>();
    // Who may open the pipe: crate::pipe::SDDL = "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)", a protected DACL
    // with SYSTEM full control, administrators and interactive users read/write, everyone else (network logons,
    // services) refused; remote clients are rejected too. Pinned by pipe::tests, enforced by the restricted-token
    // test. Opening the pipe still grants no rule: decisions only answer notices sent here (prompt::Outstanding).
    let server = crate::pipe::serve(crate::pipe::NAME, crate::pipe::SDDL, tx)?;
    let state = std::sync::Arc::new(PromptState {
        outstanding: std::sync::Mutex::new(crate::prompt::Outstanding::new(256)),
        server,
        drives: crate::pipe::drives(),
    });
    let worker = state.clone();
    let thread = std::thread::Builder::new()
        .name("decisions".into())
        .spawn(move || {
            // Ends when the pipe server stops and drops its sender.
            for decision in rx {
                worker.decide(&decision);
            }
        })
        .map_err(|e| format!("[firewall] cannot start the decision thread: {e}"))?;
    Ok(Prompt { state, thread })
}

#[cfg(windows)]
impl Prompt {
    /// Stops the pipe server, which drops its decision sender and so ends the decision thread.
    fn stop(self) {
        self.state.server.stop();
        let _ = self.thread.join();
    }
}

/// The log line for a blocked connection: program, destination and the program's full (device) path.
fn blocked_line(d: &wfp::Dropped) -> String {
    let protocol = match d.protocol {
        6 => "tcp",
        17 => "udp",
        _ => "ip",
    };
    let destination = match d.remote {
        IpAddr::V6(ip) => format!("[{ip}]:{}", d.port),
        IpAddr::V4(ip) => format!("{ip}:{}", d.port),
    };
    format!(
        "blocked: {} -> {destination} {protocol} ({})",
        d.program(),
        d.app
    )
}

/// The firewall service's process id while it runs. The tray app checks the prompt pipe's server against it, so
/// another program that created a pipe of the same name is never trusted.
#[cfg(windows)]
pub fn pid() -> Option<u32> {
    sys::pid()
}

/// `gatewizz firewall service`: the entry point Windows starts. Not for interactive use.
#[cfg(windows)]
pub fn run() -> Result<(), String> {
    sys::dispatch()
}

#[cfg(not(windows))]
fn install_windivert(_config: &Config) -> Result<Option<String>, String> {
    Err(UNSUPPORTED.into())
}

#[cfg(not(windows))]
pub fn install(_config_path: Option<&Path>) -> Result<String, String> {
    Err(UNSUPPORTED.into())
}

#[cfg(not(windows))]
pub fn uninstall() -> Result<String, String> {
    Err(UNSUPPORTED.into())
}

#[cfg(not(windows))]
pub fn run() -> Result<(), String> {
    Err(UNSUPPORTED.into())
}

#[cfg(not(windows))]
const UNSUPPORTED: &str = "[firewall] the connection firewall runs only on Windows";

#[cfg(not(windows))]
mod sys {
    pub fn state() -> Result<Option<&'static str>, String> {
        Err(super::UNSUPPORTED.into())
    }
    pub fn control(_code: u32) -> Result<(), String> {
        Err(super::UNSUPPORTED.into())
    }
}

#[cfg(windows)]
mod sys {
    use super::{NAME, REFRESH, RELOAD, log, refresh, watch_drops};
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::sync::Mutex;
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE, GetLastError, NO_ERROR,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
        OpenServiceW, QueryServiceStatus, RegisterServiceCtrlHandlerExW, SC_HANDLE,
        SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
        SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
        SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    fn last_error(what: &str) -> String {
        let code = unsafe { GetLastError() };
        match code {
            5 => format!(
                "[firewall] cannot {what}: access denied. Run `gatewizz firewall ...` from an elevated \
                 (Run as administrator) prompt"
            ),
            _ => format!("[firewall] cannot {what}: error {code}"),
        }
    }

    /// A service-control-manager handle, closed on drop.
    struct Handle(SC_HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    fn manager(access: u32) -> Result<Handle, String> {
        let h = unsafe { OpenSCManagerW(null(), null(), access) };
        if h.is_null() {
            return Err(last_error("open the service control manager"));
        }
        Ok(Handle(h))
    }

    /// The service, or `None` when it is not installed.
    fn open(access: u32) -> Result<Option<Handle>, String> {
        let scm = manager(SC_MANAGER_CONNECT)?;
        let h = unsafe { OpenServiceW(scm.0, wide(NAME).as_ptr(), access) };
        if h.is_null() {
            if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(None);
            }
            return Err(last_error(&format!("open the service {NAME}")));
        }
        Ok(Some(Handle(h)))
    }

    fn query(service: &Handle) -> Result<u32, String> {
        let mut status = SERVICE_STATUS::default();
        if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
            return Err(last_error(&format!("query the service {NAME}")));
        }
        Ok(status.dwCurrentState)
    }

    /// The running service's process id, `None` when it is not installed or not running. Needs only
    /// `SERVICE_QUERY_STATUS`, which every signed-in user has.
    pub fn pid() -> Option<u32> {
        use windows_sys::Win32::System::Services::{
            QueryServiceStatusEx, SC_STATUS_PROCESS_INFO, SERVICE_STATUS_PROCESS,
        };
        let service = open(SERVICE_QUERY_STATUS).ok()??;
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        let ok = unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        };
        (ok != 0 && status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0)
            .then_some(status.dwProcessId)
    }

    pub fn state() -> Result<Option<&'static str>, String> {
        let Some(service) = open(SERVICE_QUERY_STATUS)? else {
            return Ok(None);
        };
        Ok(Some(match query(&service)? {
            SERVICE_RUNNING => "running",
            SERVICE_STOPPED => "stopped",
            SERVICE_START_PENDING => "starting",
            SERVICE_STOP_PENDING => "stopping",
            _ => "in transition",
        }))
    }

    pub fn create(exe: &Path) -> Result<(), String> {
        let scm = manager(SC_MANAGER_ALL_ACCESS)?;
        let command = format!("\"{}\" firewall service", exe.display());
        let h = unsafe {
            CreateServiceW(
                scm.0,
                wide(NAME).as_ptr(),
                wide("Gatewizz connection firewall").as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                wide(&command).as_ptr(),
                null(),
                null_mut(),
                null(),
                // LocalSystem.
                null(),
                null(),
            )
        };
        if h.is_null() {
            return Err(last_error(&format!("create the service {NAME}")));
        }
        drop(Handle(h));
        Ok(())
    }

    fn wait_for(service: &Handle, state: u32) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while query(service)? != state {
            if Instant::now() > deadline {
                return Err(format!(
                    "[firewall] the service {NAME} did not reach state {state} in 30 s"
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    }

    pub fn start() -> Result<(), String> {
        let service = open(SERVICE_ALL_ACCESS)?
            .ok_or_else(|| format!("[firewall] the service {NAME} is gone"))?;
        if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
            return Err(last_error(&format!("start the service {NAME}")));
        }
        wait_for(&service, SERVICE_RUNNING)
    }

    pub fn stop() -> Result<(), String> {
        let Some(service) = open(SERVICE_ALL_ACCESS)? else {
            return Ok(());
        };
        let mut status = SERVICE_STATUS::default();
        if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0
            && unsafe { GetLastError() } != ERROR_SERVICE_NOT_ACTIVE
        {
            return Err(last_error(&format!("stop the service {NAME}")));
        }
        wait_for(&service, SERVICE_STOPPED)
    }

    /// Unloads the WinDivert driver (#60), if it is loaded and nothing uses it any more. Not an error otherwise.
    pub fn stop_windivert() {
        use windows_sys::Win32::System::Services::SERVICE_STOP;
        let Ok(scm) = manager(SC_MANAGER_CONNECT) else {
            return;
        };
        let h = unsafe {
            OpenServiceW(
                scm.0,
                wide("WinDivert").as_ptr(),
                SERVICE_STOP | SERVICE_QUERY_STATUS,
            )
        };
        if h.is_null() {
            return;
        }
        let driver = Handle(h);
        let mut status = SERVICE_STATUS::default();
        if unsafe { ControlService(driver.0, SERVICE_CONTROL_STOP, &mut status) } != 0 {
            let _ = wait_for(&driver, SERVICE_STOPPED);
        }
    }

    pub fn delete() -> Result<(), String> {
        let Some(service) = open(SERVICE_ALL_ACCESS)? else {
            return Ok(());
        };
        if unsafe { DeleteService(service.0) } == 0 {
            return Err(last_error(&format!("delete the service {NAME}")));
        }
        Ok(())
    }

    /// Sends a control code to the running service. A stopped service has nothing to reload: it reads the new
    /// configuration when it starts.
    pub fn control(code: u32) -> Result<(), String> {
        let Some(service) = open(SERVICE_ALL_ACCESS)? else {
            return Ok(());
        };
        let mut status = SERVICE_STATUS::default();
        if unsafe { ControlService(service.0, code, &mut status) } == 0
            && unsafe { GetLastError() } != ERROR_SERVICE_NOT_ACTIVE
        {
            return Err(last_error(&format!("signal the service {NAME}")));
        }
        Ok(())
    }

    enum Control {
        Stop,
        Reload,
    }

    /// The control handler runs on a thread Windows owns; it only forwards to the service loop.
    static CONTROL: Mutex<Option<Sender<Control>>> = Mutex::new(None);

    unsafe extern "system" fn handler(
        control: u32,
        _event: u32,
        _data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        let message = match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => Control::Stop,
            RELOAD => Control::Reload,
            SERVICE_CONTROL_INTERROGATE => return NO_ERROR,
            _ => return ERROR_CALL_NOT_IMPLEMENTED,
        };
        if let Some(tx) = CONTROL.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = tx.send(message);
        }
        NO_ERROR
    }

    fn report(handle: SERVICE_STATUS_HANDLE, state: u32, exit: u32) {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: exit,
            dwWaitHint: if state == SERVICE_RUNNING || state == SERVICE_STOPPED {
                0
            } else {
                10_000
            },
            ..Default::default()
        };
        unsafe { SetServiceStatus(handle, &status) };
    }

    fn refresh_and_log() {
        match refresh() {
            Ok(out) => log(&out),
            // Fail closed: the persistent filters from the last good apply stay in force.
            Err(err) => log(&format!("error: {err}; the previous filters stay in force")),
        }
    }

    /// Refreshes on every reload request and every [`REFRESH`] until told to stop. The first refresh already ran.
    fn serve(rx: &Receiver<Control>) {
        loop {
            match rx.recv_timeout(REFRESH) {
                Ok(Control::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                Ok(Control::Reload) | Err(RecvTimeoutError::Timeout) => refresh_and_log(),
            }
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
        let (tx, rx) = channel();
        *CONTROL.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let name = wide(NAME);
        let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), null()) };
        if handle.is_null() {
            log("error: cannot register the service control handler");
            return;
        }
        report(handle, SERVICE_START_PENDING, 0);
        log("starting");
        // Apply before reporting "running", so `firewall install` returns with the rules in force.
        refresh_and_log();
        // The prompt and the blocked-connection reports are extras: the firewall works without them.
        let prompt = super::start_prompt()
            .inspect_err(|err| log(&format!("error: {err}; the firewall prompt is off")))
            .ok();
        // Holding asks through the prompt, so it starts now, with a second refresh.
        if let Some(prompt) = &prompt {
            super::holding::set_prompt(prompt.state.clone());
            refresh_and_log();
        }
        let drops = watch_drops(prompt.as_ref().map(|p| p.state.clone()))
            .inspect_err(|err| {
                log(&format!(
                    "error: {err}; blocked connections are not reported"
                ))
            })
            .ok();
        report(handle, SERVICE_RUNNING, 0);
        serve(&rx);
        super::holding::stop();
        if let Some(drops) = drops {
            drops.stop();
        }
        if let Some(prompt) = prompt {
            prompt.stop();
        }
        log("stopped; the filters stay in force");
        report(handle, SERVICE_STOPPED, 0);
    }

    pub fn dispatch() -> Result<(), String> {
        let mut name = wide(NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            if unsafe { GetLastError() } == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                return Err(format!(
                    "[usage] `firewall service` is started by Windows as the service {NAME}; use `firewall install`"
                ));
            }
            return Err(last_error("run the service dispatcher"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_is_under_program_files() {
        let home = home();
        assert!(home.ends_with("Gatewizz"));
        assert_eq!(protected_exe().parent(), Some(home.as_path()));
        assert_eq!(protected_config().parent(), Some(home.as_path()));
    }

    #[test]
    fn wildcards_resolve_through_cached_names_and_ips_are_deduplicated() {
        let cached: Vec<String> = [
            "api.example.com",
            "cdn.example.com",
            "example.com",
            "other.org",
        ]
        .map(String::from)
        .to_vec();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let lookup = |host: &str| match host {
            "api.example.com" => vec![ip("192.0.2.2"), ip("192.0.2.1")],
            "cdn.example.com" => vec![ip("192.0.2.1")],
            "other.org" => vec![ip("198.51.100.1")],
            _ => Vec::new(),
        };
        // Only the names under the suffix (not example.com itself), each address once, sorted.
        assert_eq!(
            resolve_host("*.example.com", &cached, lookup),
            [ip("192.0.2.1"), ip("192.0.2.2")]
        );
        assert!(resolve_host("*.example.net", &cached, lookup).is_empty());
        assert_eq!(resolve_host("other.org", &[], lookup), [ip("198.51.100.1")]);
        let local = resolve_host("localhost", &[], super::lookup);
        let mut sorted = local.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(local, sorted);
    }

    #[test]
    fn self_paths_are_parsed_and_merged_once() {
        let protected = Path::new(r"C:\Program Files\Gatewizz\gatewizz.exe");
        let user = r"C:\Users\u\AppData\Local\Programs\Gatewizz\gatewizz.exe";
        let recorded = parse_self_paths(&format!("\n  {user}  \n\n"));
        assert_eq!(recorded, [user]);
        // The same copy again, in other letter case: not added twice.
        let again = merge_self_paths(recorded.clone(), &user.to_uppercase(), protected);
        assert_eq!(again, [user]);
        // The service's own copy is allowed anyway and never recorded.
        let own = merge_self_paths(
            recorded.clone(),
            r"c:\program files\gatewizz\GATEWIZZ.EXE",
            protected,
        );
        assert_eq!(own, [user]);
        // A second user copy (another install location) is added.
        let other = r"D:\tools\gatewizz.exe";
        assert_eq!(merge_self_paths(recorded, other, protected), [user, other]);
        assert!(parse_self_paths("").is_empty());
    }

    #[test]
    fn log_lines_are_single_and_the_log_rotates() {
        let dir = std::env::temp_dir().join(format!("gatewizz-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("service.log");
        log_to(&path, 64, "Applied 3 filter(s)\nwarning: x");
        let first = std::fs::read_to_string(&path).unwrap();
        assert_eq!(first.lines().count(), 1, "{first}");
        assert!(first.contains("Applied 3 filter(s) | warning: x"));
        // Past the limit the file moves to service.log.1 and a new one starts.
        log_to(&path, 64, &"y".repeat(80));
        log_to(&path, 64, "after rotation");
        let rotated = std::fs::read_to_string(dir.join("service.log.1")).unwrap();
        let current = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(rotated.contains("Applied") && rotated.contains("yyyy"));
        assert_eq!(current.lines().count(), 1);
        assert!(current.contains("after rotation"));
    }

    #[test]
    fn without_a_config_the_installed_rules_are_kept() {
        let rules = "[[connection_rules]]\nid = \"a\"\naction = \"block\"\n".to_string();
        // `--config` replaces the rules.
        assert_eq!(choose_rules(Some("new".into()), Some(rules.clone())), "new");
        // No `--config`: the installed rules stay, never an empty set.
        assert_eq!(choose_rules(None, Some(rules.clone())), rules);
        // Nothing installed and nothing given: the defaults.
        assert_eq!(choose_rules(None, None), "");
    }

    #[test]
    fn summary_names_the_default_and_every_unenforced_part() {
        use firewall::DefaultAction::{Allow, Ask, Block};
        let clean = wfp::Applied {
            filters: 5,
            skipped: Vec::new(),
        };
        let ok = summary(&clean, 2, Allow, &[], &[]);
        assert_eq!(
            ok,
            "Applied 5 Windows filter(s) for 2 connection rule(s); connections no rule matches are allowed."
        );
        assert!(summary(&clean, 2, Block, &[], &[]).ends_with("are blocked."));
        assert!(summary(&clean, 2, Ask, &[], &[]).contains("the tray app asks"));

        let partial = wfp::Applied {
            filters: 1,
            skipped: vec![r"C:\gone\app.exe".into()],
        };
        let text = summary(
            &partial,
            3,
            Allow,
            &["smartwizz.exe".into()],
            &["*.example.com", "nx.example"],
        );
        let warnings: Vec<&str> = text.lines().skip(1).collect();
        assert_eq!(warnings.len(), 4, "{text}");
        assert!(warnings[0].starts_with("warning: smartwizz.exe is neither on PATH nor running"));
        assert!(warnings[1].starts_with("warning: *.example.com has no IP address"));
        assert!(warnings[2].starts_with("warning: nx.example has no IP address"));
        assert!(warnings[3].contains(r"C:\gone\app.exe does not exist"));
    }

    #[test]
    fn write_atomic_replaces_the_file_and_leaves_no_temporary() {
        let dir = std::env::temp_dir().join(format!("gatewizz-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("firewall.toml");
        write_atomic(&path, "first").unwrap();
        write_atomic(&path, "second").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let tmp_left = path.with_extension("tmp").exists();
        // A directory where the file should go cannot be replaced: an error, not a silent success.
        std::fs::create_dir_all(dir.join("blocked.toml")).unwrap();
        let blocked = write_atomic(&dir.join("blocked.toml"), "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(content, "second");
        assert!(!tmp_left);
        assert!(blocked.unwrap_err().contains("blocked.toml"));
    }

    #[test]
    fn blocked_lines_name_program_destination_and_path() {
        let d = wfp::Dropped {
            app: r"\device\harddiskvolume3\tools\curl.exe".into(),
            remote: "93.184.215.14".parse().unwrap(),
            port: 443,
            protocol: 6,
            filter_id: 7,
        };
        assert_eq!(
            blocked_line(&d),
            r"blocked: curl.exe -> 93.184.215.14:443 tcp (\device\harddiskvolume3\tools\curl.exe)"
        );
        let v6 = wfp::Dropped {
            remote: "2001:db8::1".parse().unwrap(),
            protocol: 17,
            ..d
        };
        assert!(blocked_line(&v6).contains("-> [2001:db8::1]:443 udp"));
    }

    #[test]
    fn temporary_rules_expire_and_join_the_applied_rules() {
        let now = SystemTime::now();
        let rule = |id: &str, expires: Option<SystemTime>| firewall::Rule {
            id: id.into(),
            process: vec![r"C:\Tools\curl.exe".into()],
            host: Vec::new(),
            ip: Vec::new(),
            port: vec![443],
            protocol: firewall::Protocol::Tcp,
            action: firewall::RuleAction::Allow,
            expires,
        };
        let mut rules = vec![
            rule("once", Some(now + Duration::from_secs(120))),
            rule("gone", Some(now - Duration::from_secs(1))),
            rule("edge", Some(now)),
            rule("kept", None),
        ];
        keep_unexpired(&mut rules, now);
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["once", "kept"], "expired at or before now is gone");
        // Two minutes on, "once" is gone too.
        keep_unexpired(&mut rules, now + Duration::from_secs(120));
        assert_eq!(rules.len(), 1);

        // The applied set is the configured rules plus the temporary ones.
        let mut config =
            Config::parse("[[connection_rules]]\nid = \"cfg\"\nport = [80]\naction = \"block\"\n")
                .unwrap();
        config.connection_rules.extend(rules);
        let ids: Vec<&str> = config
            .connection_rules
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(ids, ["cfg", "kept"]);
    }

    #[test]
    fn prompt_rules_append_and_fall_back_to_a_rewrite() {
        let rule = firewall::Rule {
            id: "prompt-allow-curl.exe-1-1".into(),
            process: vec![r"C:\Tools\curl.exe".into()],
            host: Vec::new(),
            ip: Vec::new(),
            port: vec![443],
            protocol: firewall::Protocol::Tcp,
            action: firewall::RuleAction::Allow,
            expires: None,
        };
        // Usual files, ending in any table: appended, the user's text kept.
        for text in [
            "",
            "# mine\n[firewall]\ndefault = \"ask\"\n",
            "[[connection_rules]]\nid = \"a\"\naction = \"block\"\n[monitor]\nenabled = true",
        ] {
            let Added::Appended(new) = with_rule(text, &rule).unwrap() else {
                panic!("expected an append for {text:?}");
            };
            assert!(new.starts_with(text));
            let rules = Config::parse(&new).unwrap().connection_rules;
            assert_eq!(rules.last().unwrap().id, rule.id);
        }
        // An inline `connection_rules = [...]` cannot take a [[connection_rules]] table: rewritten instead, with
        // every rule kept.
        let inline = "connection_rules = [{ id = \"a\", action = \"block\" }]\n";
        let Added::Rewritten(new) = with_rule(inline, &rule).unwrap() else {
            panic!("expected a rewrite");
        };
        let ids: Vec<String> = Config::parse(&new)
            .unwrap()
            .connection_rules
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, ["a", rule.id.as_str()]);
        assert!(new.starts_with("# Rewritten by the firewall prompt"));
        // A broken protected configuration is refused, never overwritten.
        assert!(with_rule("[firewall\n", &rule).is_err());
    }

    #[test]
    fn only_valid_configs_reach_the_protected_copy() {
        let dir = std::env::temp_dir().join(format!("gatewizz-service-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.toml");
        let bad = dir.join("bad.toml");
        std::fs::write(&good, "[firewall]\ndefault = \"block\"\n").unwrap();
        std::fs::write(&bad, "[firewall]\ndefault = \"maybe\"\n").unwrap();
        let ok = read_valid(&good);
        let err = read_valid(&bad);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(ok.unwrap().contains("block"));
        assert!(err.unwrap_err().contains("bad.toml"));
    }
}
