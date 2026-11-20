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
    let rules = &config.connection_rules;
    let now = SystemTime::now();
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
    Ok(summary(
        &applied,
        rules.len(),
        config.firewall.default,
        &firewall::unresolved(rules, now, wfp::program_paths),
        &unresolved_hosts,
    ))
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
                "blocked (\"ask\" blocks until the approval prompt exists)",
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
            "\nwarning: {host} has no IP address now (wildcards never do), so its rules are not enforced. Use `ip` \
             for addresses that must be covered."
        ));
    }
    for path in &applied.skipped {
        out.push_str(&format!(
            "\nwarning: {path} does not exist; its filters were skipped."
        ));
    }
    out
}

/// The addresses a host name resolves to now. Wildcards name no single host and resolve to nothing.
fn resolve_host(host: &str) -> Vec<IpAddr> {
    if host.starts_with("*.") {
        return Vec::new();
    }
    let mut ips: Vec<IpAddr> = (host, 0)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip()).collect())
        .unwrap_or_default();
    ips.sort();
    ips.dedup();
    ips
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
    let config = Config::load(&protected_config())?;
    apply_config(&config, &service_self_paths())
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
        let mut all = service_self_paths();
        all.truncate(1);
        all.extend(self_paths);
        let out = apply_config(&config, &all)?;
        sys::control(RELOAD)?;
        Ok(out + "\nThe firewall service keeps these rules current.")
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
    if !existed {
        sys::create(&protected_exe())?;
    }
    sys::start()?;
    Ok(format!(
        "Installed the firewall service {NAME}, running from {}. It applies the connection rules now and keeps \
         them current every {} s; `gatewizz firewall apply --config <path>` changes them.",
        home().display(),
        REFRESH.as_secs()
    ))
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
// ponytail: the notices only reach the log so far; the pipe to the tray and the prompt are the next #59 step.
#[cfg(windows)]
fn watch_drops() -> Result<DropWatch, String> {
    let (tx, rx) = std::sync::mpsc::channel::<wfp::Dropped>();
    let subscription = wfp::subscribe_drops(tx)?;
    let thread = std::thread::Builder::new()
        .name("drops".into())
        .spawn(move || {
            let mut notices = firewall::Coalescer::new(NOTICE_WINDOW, 1024);
            let mut ids = wfp::filter_ids(wfp::KEYS).unwrap_or_default();
            let mut ids_read = std::time::Instant::now();
            for dropped in rx {
                if !ids.contains(&dropped.filter_id) && ids_read.elapsed() >= Duration::from_secs(1)
                {
                    ids = wfp::filter_ids(wfp::KEYS).unwrap_or_default();
                    ids_read = std::time::Instant::now();
                }
                if !ids.contains(&dropped.filter_id) {
                    continue;
                }
                let host = dropped.remote.to_string();
                if notices.push(
                    dropped.program(),
                    &host,
                    dropped.port,
                    std::time::Instant::now(),
                ) {
                    log(&blocked_line(&dropped));
                }
            }
        })
        .map_err(|e| format!("[firewall] cannot start the drop watcher: {e}"))?;
    Ok(DropWatch {
        subscription,
        thread,
    })
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

/// `gatewizz firewall service`: the entry point Windows starts. Not for interactive use.
#[cfg(windows)]
pub fn run() -> Result<(), String> {
    sys::dispatch()
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
        // Blocked connections are reported from here on; the firewall works without them.
        let drops = watch_drops()
            .inspect_err(|err| {
                log(&format!(
                    "error: {err}; blocked connections are not reported"
                ))
            })
            .ok();
        report(handle, SERVICE_RUNNING, 0);
        serve(&rx);
        if let Some(drops) = drops {
            drops.stop();
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
    fn wildcards_resolve_to_nothing_and_ips_are_deduplicated() {
        assert!(resolve_host("*.example.com").is_empty());
        let local = resolve_host("localhost");
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
        assert!(summary(&clean, 2, Ask, &[], &[]).contains("\"ask\" blocks"));

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
