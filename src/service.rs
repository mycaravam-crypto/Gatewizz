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

    let mut out = format!(
        "Applied {} Windows filter(s) for {} connection rule(s); connections no rule matches are {}.",
        applied.filters,
        rules.len(),
        match config.firewall.default {
            firewall::DefaultAction::Allow => "allowed",
            firewall::DefaultAction::Block => "blocked",
            firewall::DefaultAction::Ask =>
                "blocked (\"ask\" blocks until the approval prompt exists)",
        }
    );
    for program in firewall::unresolved(rules, now, wfp::program_paths) {
        out.push_str(&format!(
            "\nwarning: {program} is neither on PATH nor running, so its rules are not enforced yet. Use its full \
             path in `process`, or let the service find it once it runs."
        ));
    }
    let mut unresolved_hosts: Vec<&str> = rules
        .iter()
        .flat_map(|r| r.host.iter())
        .map(String::as_str)
        .filter(|h| resolve_host(h).is_empty())
        .collect();
    unresolved_hosts.sort_unstable();
    unresolved_hosts.dedup();
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
    Ok(out)
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
    let mut paths = vec![protected_exe().to_string_lossy().into_owned()];
    if let Ok(text) = std::fs::read_to_string(self_paths_file()) {
        paths.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from),
        );
    }
    paths
}

/// The self paths after this run: the recorded ones plus the executable running now (the user's copy).
fn merged_self_paths() -> Result<Vec<String>, String> {
    let mut paths = service_self_paths();
    paths.remove(0);
    let me = current_exe()?;
    if !same_file(Path::new(&me), &protected_exe())
        && !paths.iter().any(|p| p.eq_ignore_ascii_case(&me))
    {
        paths.push(me);
    }
    Ok(paths)
}

/// Appends a line to the service log, rotating it past [`LOG_MAX`]. Best effort: a failing log never stops the
/// service.
fn log(line: &str) {
    use std::io::Write;
    let path = home().join("service.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_MAX) {
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
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
    let config_text = match config_path {
        Some(p) => read_valid(p)?,
        None => String::new(),
    };
    let config = Config::parse(&config_text)?;
    if status()?.is_some() {
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
    let config_text = match config_path {
        Some(p) => read_valid(p)?,
        None => String::new(),
    };
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
    use super::{NAME, REFRESH, RELOAD, log, refresh};
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
        report(handle, SERVICE_RUNNING, 0);
        serve(&rx);
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
