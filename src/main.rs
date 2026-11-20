//! Gatewizz: a local HTTPS gate for code sent to AI models. See PLAN.md.

// Release builds run in the background with the tray and no console window of their own; output goes to the console
// they were started from, if any (see `attach_parent_console`).
#![cfg_attr(
    all(windows, not(debug_assertions), not(test)),
    windows_subsystem = "windows"
)]

mod approve;
mod ca;
mod config;
mod connections;
mod detect;
mod dns;
mod event;
mod firewall;
mod process;
mod proxy;
mod rules;
mod startup;
mod tls;
mod ui;
mod wfp;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use config::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit code for an execution failure, as in smartwizz.
const EXIT_FAILURE: u8 = 2;

/// Exit code after Ctrl+C or console close, as in smartwizz.
const EXIT_CANCELLED: u8 = 130;

/// Bounded so a stalled writer slows the proxy down instead of growing memory.
const EVENT_QUEUE: usize = 4096;

const USAGE: &str = "\
gatewizz: a local HTTPS gate for code sent to AI models

Usage:
  gatewizz [--config <path>]                  run the proxy and tray until Quit or Ctrl+C
  gatewizz [--config <path>] --check-config   validate the config and print the effective values
  gatewizz ca install                         create the local CA if missing and trust it for the current user
  gatewizz ca remove                          untrust every gatewizz CA and delete its files
  gatewizz startup install [--config <path>]   start Gatewizz automatically at user login
  gatewizz startup remove                     remove automatic startup
  gatewizz startup status                     show automatic startup configuration
  gatewizz firewall apply [--config <path>]   enforce [[connection_rules]] with Windows filters (elevated)
  gatewizz firewall remove                    remove every Gatewizz firewall filter (elevated)
  gatewizz firewall status                    show whether Gatewizz firewall filters are installed
  gatewizz --version | --help

Options:
  --config <path>   TOML configuration; without it every default applies
                    (see config/gatewizz.example.toml)
  --check-config    validate and print the configuration, then exit
  -V, --version     print the version
  -h, --help        print this help

The CA lives in %LOCALAPPDATA%\\gatewizz: ca.cer (public certificate) and ca.key (private key, encrypted with
DPAPI for the current user). It is trusted only by the current user (CurrentUser Root store), and gatewizz uses it
to sign certificates for hosts whose TLS it inspects. Windows asks for confirmation when it is added or removed.

Point tools at the proxy with HTTPS_PROXY=http://127.0.0.1:8899 (the default listen address).

Exit codes: 0 done, 2 failure ([usage], [configuration], [network], [events], [ca]), 130 stopped by Ctrl+C or console close.
";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Run(Option<PathBuf>),
    CheckConfig(Option<PathBuf>),
    CaInstall,
    CaRemove,
    StartupInstall(Option<PathBuf>),
    StartupRemove,
    StartupStatus,
    FirewallApply(Option<PathBuf>),
    FirewallRemove,
    FirewallStatus,
    Version,
    Help,
}

// Four flags do not justify an argument-parsing dependency (PLAN rule 4).
fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [ca, action] if ca == "ca" && action == "install" => return Ok(Command::CaInstall),
        [ca, action] if ca == "ca" && action == "remove" => return Ok(Command::CaRemove),
        [ca, ..] if ca == "ca" => return Err("[usage] ca needs install or remove".into()),
        [startup, action] if startup == "startup" && action == "remove" => {
            return Ok(Command::StartupRemove);
        }
        [startup, action] if startup == "startup" && action == "status" => {
            return Ok(Command::StartupStatus);
        }
        [startup, action] if startup == "startup" && action == "install" => {
            return Ok(Command::StartupInstall(None));
        }
        [startup, action, flag, path]
            if startup == "startup" && action == "install" && flag == "--config" =>
        {
            return Ok(Command::StartupInstall(Some(PathBuf::from(path))));
        }
        [startup, ..] if startup == "startup" => {
            return Err("[usage] startup needs install [--config <path>], remove or status".into());
        }
        [fw, action] if fw == "firewall" && action == "apply" => {
            return Ok(Command::FirewallApply(None));
        }
        [fw, action, flag, path] if fw == "firewall" && action == "apply" && flag == "--config" => {
            return Ok(Command::FirewallApply(Some(PathBuf::from(path))));
        }
        [fw, action] if fw == "firewall" && action == "remove" => {
            return Ok(Command::FirewallRemove);
        }
        [fw, action] if fw == "firewall" && action == "status" => {
            return Ok(Command::FirewallStatus);
        }
        [fw, ..] if fw == "firewall" => {
            return Err("[usage] firewall needs apply [--config <path>], remove or status".into());
        }
        _ => {}
    }
    let (mut config, mut check) = (None, false);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" if config.is_none() && !check && args.len() == 0 => {
                return Ok(Command::Version);
            }
            "--help" | "-h" if config.is_none() && !check && args.len() == 0 => {
                return Ok(Command::Help);
            }
            "--config" if config.is_none() => match args.next() {
                Some(path) => config = Some(PathBuf::from(path)),
                None => return Err("[usage] --config needs a path".into()),
            },
            "--check-config" if !check => check = true,
            other => {
                return Err(format!(
                    "[usage] unexpected argument {other:?}; see gatewizz --help"
                ));
            }
        }
    }
    Ok(if check {
        Command::CheckConfig(config)
    } else {
        Command::Run(config)
    })
}

fn load(path: Option<PathBuf>) -> Result<Config, String> {
    path.map_or_else(|| Ok(Config::default()), |p| Config::load(&p))
}

/// Resolves on Ctrl+C or, on Windows, when the console window is closed.
async fn cancelled() {
    #[cfg(windows)]
    {
        // ponytail: Windows ends the process about 5 s after a console close, so a longer shutdown_timeout is cut.
        if let Ok(mut close) = tokio::signal::windows::ctrl_close() {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = close.recv() => {}
            }
            return;
        }
    }
    // An error here means no handler could be installed; then only the process kill ends the proxy.
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// The proxy settings, with TLS interception when `[tls] intercept` is on. That needs the CA, so a missing CA is a
/// startup error rather than a silent fallback to blind tunnels.
fn proxy_settings(
    config: &Config,
    data_dir: Result<std::path::PathBuf, String>,
) -> Result<proxy::Settings, String> {
    let mut settings = config.settings();
    if config.tls.intercept {
        let ca = data_dir.and_then(|dir| ca::Ca::load(&dir)).map_err(|err| {
            format!("[configuration] tls.intercept needs the local CA; run `gatewizz ca install` ({err})")
        })?;
        let upstream = tls::platform_upstream().map_err(|err| format!("[configuration] {err}"))?;
        settings.tls = Some(std::sync::Arc::new(tls::Interceptor::new(
            tls::leaf_issuer(std::sync::Arc::new(ca)),
            upstream,
            config.tls.tunnel_hosts.clone(),
        )));
    }
    Ok(settings)
}

/// Runs until `stop` completes, then drains, flushes the events and returns.
fn run_proxy(
    config: &Config,
    approvals: Option<std::sync::Arc<approve::Approvals>>,
    live: std::sync::Arc<connections::Live>,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), String> {
    let mut settings = proxy_settings(config, config::data_dir())?;
    settings.approvals = approvals;
    let target = config.event_target()?;
    let (events, writer) = event::spawn(
        target,
        config.events.max_file_bytes,
        config.events.keep_files,
        EVENT_QUEUE,
    )?;
    // The monitor holds its own event sender, so it stops before the writer is joined.
    let monitor = if config.monitor.enabled {
        Some(connections::start(
            config.monitor.settings(),
            events.clone(),
            live,
        )?)
    } else {
        None
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("[configuration] cannot start runtime: {err}"))?;
    let listen = config.general.listen;
    let served = runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|err| format!("[network] cannot listen on {listen}: {err}"))?;
        eprintln!("gatewizz {VERSION} listening on {listen}");
        proxy::serve(listener, settings, events, stop)
            .await
            .map_err(|err| format!("[network] {err}"))
    });
    // Ending the runtime cancels what is left (tunnels), which drops the last event senders, so the writer drains
    // its queue and stops.
    runtime.shutdown_timeout(Duration::from_secs(1));
    let monitored = monitor.map_or(Ok(()), connections::Monitor::stop);
    let flushed = writer
        .join()
        .map_err(|_| "[events] writer panicked".to_string())
        .and_then(|result| result);
    served.and(monitored).and(flushed)
}

/// On Windows the tray and approval window own the main thread; Quit, Ctrl+C or console close stop the proxy.
#[cfg(windows)]
fn run_with_ui(config: Config) -> Result<(), String> {
    let approvals = std::sync::Arc::new(approve::Approvals::new(
        Duration::from_secs(config.approval.timeout_secs),
        config.approval.max_pending,
    ));
    let events_path = match config.event_target()? {
        config::EventTarget::File(path) => Some(path),
        config::EventTarget::Stdout => None,
    };
    let queue = approvals.clone();
    let live = std::sync::Arc::new(connections::Live::default());
    let network = config.monitor.enabled.then(|| live.clone());
    ui::run(
        config.general.listen,
        events_path,
        approvals,
        network,
        move |quit| {
            run_proxy(&config, Some(queue), live, async move {
                tokio::select! {
                    () = cancelled() => {}
                    _ = quit => {}
                }
            })
        },
    )
}

/// Elsewhere gatewizz is a console proxy that runs until Ctrl+C.
#[cfg(not(windows))]
fn run_with_ui(config: Config) -> Result<(), String> {
    // No approval window here, so `approve` rules block (fail closed).
    run_proxy(&config, None, Default::default(), cancelled())
}

fn run(command: Command) -> Result<ExitCode, String> {
    match command {
        Command::Version => println!("gatewizz {VERSION}"),
        Command::Help => print!("{USAGE}"),
        Command::CaInstall => println!("{}", ca::install(&config::data_dir()?)?),
        Command::CaRemove => println!("{}", ca::remove(&config::data_dir()?)?),
        Command::StartupInstall(path) => {
            let config = load(path.clone())?;
            config.event_target()?;
            proxy_settings(&config, config::data_dir())?;
            println!("{}", startup::install(path.as_deref())?);
        }
        Command::StartupRemove => println!("{}", startup::remove()?),
        Command::StartupStatus => match startup::status()? {
            Some(command) => println!("Gatewizz starts at user login: {command}"),
            None => println!("Gatewizz is not registered for automatic startup."),
        },
        Command::FirewallApply(path) => println!("{}", firewall_apply(&load(path)?)?),
        Command::FirewallRemove => {
            let removed = wfp::remove(wfp::KEYS)?;
            println!(
                "Removed {removed} Gatewizz firewall filter(s). Gatewizz no longer filters connections."
            );
        }
        Command::FirewallStatus => match wfp::installed(wfp::KEYS)? {
            Some(n) => println!("The Gatewizz firewall is installed with {n} filter(s)."),
            None => println!("The Gatewizz firewall is not installed."),
        },
        Command::CheckConfig(path) => {
            let config = load(path)?;
            config.event_target()?;
            print!("{}", config.effective());
        }
        Command::Run(path) => {
            #[cfg(windows)]
            let _instance = match startup::SingleInstance::acquire()? {
                Some(instance) => instance,
                None => {
                    eprintln!("gatewizz: already running in this Windows session");
                    return Ok(ExitCode::SUCCESS);
                }
            };
            let config = load(path)?;
            run_with_ui(config)?;
            eprintln!("gatewizz: stopped");
            return Ok(ExitCode::from(EXIT_CANCELLED));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Turns `[[connection_rules]]` into WFP filters and installs them, replacing the previous set. Host names are
/// resolved now, and program file names to the paths on `PATH` or of running processes; what cannot be resolved is
/// reported, since those parts of the rules are not enforced.
// ponytail: names are resolved once, at apply time. A program installed later or a host whose IPs change needs
// another `firewall apply` until the service (#59) keeps the filters current.
fn firewall_apply(config: &Config) -> Result<String, String> {
    use std::net::ToSocketAddrs;
    let rules = &config.connection_rules;
    let now = std::time::SystemTime::now();
    let own = std::env::current_exe()
        .map_err(|e| format!("[firewall] cannot locate gatewizz.exe: {e}"))?
        .to_string_lossy()
        .into_owned();
    let hosts = |host: &str| -> Vec<std::net::IpAddr> {
        if host.starts_with("*.") {
            return Vec::new();
        }
        let mut ips: Vec<_> = (host, 0)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect())
            .unwrap_or_default();
        ips.sort();
        ips.dedup();
        ips
    };
    let filters = firewall::plan(
        rules,
        config.firewall.default,
        &own,
        now,
        hosts,
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
            "\nwarning: {program} is neither on PATH nor running, so its rules are not enforced. Use its full path \
             in `process`, or run `firewall apply` again while it runs."
        ));
    }
    let mut unresolved_hosts: Vec<&str> = rules
        .iter()
        .flat_map(|r| r.host.iter())
        .map(String::as_str)
        .filter(|h| hosts(h).is_empty())
        .collect();
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

/// Without a console of its own, gatewizz writes to the console it was started from. Output that is already
/// redirected (a file or pipe) stays where it is. Returns whether there is anywhere to print to.
#[cfg(windows)]
fn attach_parent_console() -> bool {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE,
    };
    let err = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if !err.is_null() && err != INVALID_HANDLE_VALUE {
        return true;
    }
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) != 0 }
}

/// Started from Explorer there is no console, so an error that ends gatewizz is shown in a message box.
#[cfg(windows)]
fn show_error(text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (text, caption) = (wide(text), wide("gatewizz"));
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}

fn main() -> ExitCode {
    #[cfg(windows)]
    let console = attach_parent_console();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args).and_then(run) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("gatewizz: {err}");
            #[cfg(windows)]
            if !console {
                show_error(&err);
            }
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_commands() {
        assert_eq!(parse(&args(&[])), Ok(Command::Run(None)));
        assert_eq!(parse(&args(&["--version"])), Ok(Command::Version));
        assert_eq!(parse(&args(&["-V"])), Ok(Command::Version));
        assert_eq!(parse(&args(&["--help"])), Ok(Command::Help));
        assert_eq!(parse(&args(&["-h"])), Ok(Command::Help));
        assert_eq!(
            parse(&args(&["--config", "g.toml"])),
            Ok(Command::Run(Some("g.toml".into())))
        );
        assert_eq!(
            parse(&args(&["--config", "g.toml", "--check-config"])),
            Ok(Command::CheckConfig(Some("g.toml".into())))
        );
        assert_eq!(
            parse(&args(&["--check-config", "--config", "g.toml"])),
            Ok(Command::CheckConfig(Some("g.toml".into())))
        );
        assert_eq!(
            parse(&args(&["--check-config"])),
            Ok(Command::CheckConfig(None))
        );
        assert_eq!(parse(&args(&["ca", "install"])), Ok(Command::CaInstall));
        assert_eq!(parse(&args(&["ca", "remove"])), Ok(Command::CaRemove));
        assert_eq!(
            parse(&args(&["startup", "install"])),
            Ok(Command::StartupInstall(None))
        );
        assert_eq!(
            parse(&args(&["startup", "install", "--config", "gatewizz.toml"])),
            Ok(Command::StartupInstall(Some("gatewizz.toml".into())))
        );
        assert_eq!(
            parse(&args(&["startup", "remove"])),
            Ok(Command::StartupRemove)
        );
        assert_eq!(
            parse(&args(&["startup", "status"])),
            Ok(Command::StartupStatus)
        );
        assert_eq!(
            parse(&args(&["firewall", "apply"])),
            Ok(Command::FirewallApply(None))
        );
        assert_eq!(
            parse(&args(&["firewall", "apply", "--config", "g.toml"])),
            Ok(Command::FirewallApply(Some("g.toml".into())))
        );
        assert_eq!(
            parse(&args(&["firewall", "remove"])),
            Ok(Command::FirewallRemove)
        );
        assert_eq!(
            parse(&args(&["firewall", "status"])),
            Ok(Command::FirewallStatus)
        );
    }

    #[test]
    fn rejects_anything_else_as_usage_error() {
        for input in [
            &["--bogus"][..],
            &["--version", "x"][..],
            &["--config"][..],
            &["--config", "a", "--config", "b"][..],
            &["--check-config", "--version"][..],
            &["--help", "x"][..],
            &["ca"][..],
            &["ca", "bogus"][..],
            &["firewall"][..],
            &["firewall", "bogus"][..],
            &["firewall", "apply", "--config"][..],
            &["ca", "install", "x"][..],
            &["startup"][..],
            &["startup", "bogus"][..],
            &["startup", "install", "--config"][..],
            &["startup", "install", "--config", "a", "extra"][..],
            &["--config", "g.toml", "ca", "install"][..],
        ] {
            let err = parse(&args(input)).unwrap_err();
            assert!(err.starts_with("[usage]"), "{err}");
        }
    }

    #[test]
    fn help_names_every_flag() {
        for flag in [
            "--config",
            "--check-config",
            "--version",
            "--help",
            "HTTPS_PROXY",
            "ca install",
            "ca remove",
            "startup install",
            "startup remove",
            "startup status",
            "ca.key",
            "130",
        ] {
            assert!(USAGE.contains(flag), "{flag}");
        }
    }

    #[test]
    fn intercept_without_a_ca_is_a_startup_error() {
        let empty = std::env::temp_dir().join(format!("gatewizz-no-ca-{}", std::process::id()));
        let mut config = Config::default();
        assert!(
            proxy_settings(&config, Ok(empty.clone()))
                .unwrap()
                .tls
                .is_none()
        );
        config.tls.intercept = true;
        let err = proxy_settings(&config, Ok(empty)).unwrap_err();
        assert!(err.contains("gatewizz ca install"), "{err}");
    }

    #[test]
    fn check_config_validates_the_file() {
        let dir = std::env::temp_dir().join(format!("gatewizz-main-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "[general]\nlisten = \"0.0.0.0:1\"\n").unwrap();
        let err = run(Command::CheckConfig(Some(path))).unwrap_err();
        assert!(err.contains("general.listen"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
