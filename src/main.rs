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
mod detect;
mod event;
mod process;
mod proxy;
mod rules;
mod tls;
mod ui;

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
  gatewizz [--config <path>]                  run the proxy until Ctrl+C
  gatewizz [--config <path>] --check-config   validate the config and print the effective values
  gatewizz ca install                         create the local CA if missing and trust it for the current user
  gatewizz ca remove                          untrust every gatewizz CA and delete its files
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
    Version,
    Help,
}

// Four flags do not justify an argument-parsing dependency (PLAN rule 4).
fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [ca, action] if ca == "ca" && action == "install" => return Ok(Command::CaInstall),
        [ca, action] if ca == "ca" && action == "remove" => return Ok(Command::CaRemove),
        [ca, ..] if ca == "ca" => return Err("[usage] ca needs install or remove".into()),
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

/// How long a request waits for an answer, and how many may wait.
// ponytail: fixed until the [approval] config keys arrive with the approve action (#34).
#[cfg(windows)]
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(windows)]
const APPROVAL_QUEUE: usize = 16;

/// Runs until `stop` completes, then drains, flushes the events and returns.
fn run_proxy(config: &Config, stop: impl std::future::Future<Output = ()>) -> Result<(), String> {
    let settings = proxy_settings(config, config::data_dir())?;
    let target = config.event_target()?;
    let (events, writer) = event::spawn(
        target,
        config.events.max_file_bytes,
        config.events.keep_files,
        EVENT_QUEUE,
    )?;
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
    let flushed = writer
        .join()
        .map_err(|_| "[events] writer panicked".to_string())
        .and_then(|result| result);
    served.and(flushed)
}

/// On Windows the tray and approval window own the main thread; Quit, Ctrl+C or console close stop the proxy.
#[cfg(windows)]
fn run_with_ui(config: Config) -> Result<(), String> {
    let approvals = std::sync::Arc::new(approve::Approvals::new(APPROVAL_TIMEOUT, APPROVAL_QUEUE));
    let events_path = match config.event_target()? {
        config::EventTarget::File(path) => Some(path),
        config::EventTarget::Stdout => None,
    };
    ui::run(config.general.listen, events_path, approvals, move |quit| {
        run_proxy(&config, async move {
            tokio::select! {
                () = cancelled() => {}
                _ = quit => {}
            }
        })
    })
}

/// Elsewhere gatewizz is a console proxy that runs until Ctrl+C.
#[cfg(not(windows))]
fn run_with_ui(config: Config) -> Result<(), String> {
    run_proxy(&config, cancelled())
}

fn run(command: Command) -> Result<ExitCode, String> {
    match command {
        Command::Version => println!("gatewizz {VERSION}"),
        Command::Help => print!("{USAGE}"),
        Command::CaInstall => println!("{}", ca::install(&config::data_dir()?)?),
        Command::CaRemove => println!("{}", ca::remove(&config::data_dir()?)?),
        Command::CheckConfig(path) => {
            let config = load(path)?;
            config.event_target()?;
            print!("{}", config.effective());
        }
        Command::Run(path) => {
            let config = load(path)?;
            run_with_ui(config)?;
            eprintln!("gatewizz: stopped");
            return Ok(ExitCode::from(EXIT_CANCELLED));
        }
    }
    Ok(ExitCode::SUCCESS)
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
            &["ca", "install", "x"][..],
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
