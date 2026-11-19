//! Gatewizz: a local HTTPS gate for code sent to AI models. See PLAN.md.

mod ca;
mod castore;
mod config;
mod event;
mod process;
mod proxy;

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
  gatewizz ca remove                          untrust every gatewizz CA and delete the CA files
  gatewizz --version | --help

Options:
  --config <path>   TOML configuration; without it every default applies
                    (see config/gatewizz.example.toml)
  --check-config    validate and print the configuration, then exit
  -V, --version     print the version
  -h, --help        print this help

Point tools at the proxy with HTTPS_PROXY=http://127.0.0.1:8899 (the default listen address).

The local CA lives in %LOCALAPPDATA%\\gatewizz\\: ca.cer is the public certificate, ca.key its private key,
encrypted with DPAPI so only the current Windows user can read it. Trusted in the CurrentUser Root store, the CA can
sign a certificate for any host that this user's programs accept, which is what lets gatewizz inspect HTTPS. It is
created on this machine and never leaves it. Windows asks to confirm both install and remove.

Exit codes: 0 done, 2 failure ([usage], [configuration], [network], [events], [ca]), 130 stopped by Ctrl+C or
console close.
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
    if args.first().is_some_and(|a| a == "ca") {
        return match &args[1..] {
            [action] if action == "install" => Ok(Command::CaInstall),
            [action] if action == "remove" => Ok(Command::CaRemove),
            _ => Err("[usage] ca needs install or remove; see gatewizz --help".into()),
        };
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

/// Runs until cancelled, then drains, flushes the events and returns.
fn run_proxy(config: &Config) -> Result<(), String> {
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
        proxy::serve(listener, config.settings(), events, cancelled())
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

fn ca_err(err: String) -> String {
    format!("[ca] {err}")
}

fn ca_dir() -> Result<PathBuf, String> {
    ca::default_dir().map_err(ca_err)
}

fn run(command: Command) -> Result<ExitCode, String> {
    match command {
        Command::Version => println!("gatewizz {VERSION}"),
        Command::Help => print!("{USAGE}"),
        Command::CaInstall => println!(
            "gatewizz: {}",
            ca_dir().and_then(|d| castore::install(&d).map_err(ca_err))?
        ),
        Command::CaRemove => println!(
            "gatewizz: {}",
            ca_dir().and_then(|d| castore::remove(&d).map_err(ca_err))?
        ),
        Command::CheckConfig(path) => {
            let config = load(path)?;
            config.event_target()?;
            print!("{}", config.effective());
        }
        Command::Run(path) => {
            run_proxy(&load(path)?)?;
            eprintln!("gatewizz: stopped");
            return Ok(ExitCode::from(EXIT_CANCELLED));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args).and_then(run) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("gatewizz: {err}");
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
        assert_eq!(parse(&args(&["ca", "install"])), Ok(Command::CaInstall));
        assert_eq!(parse(&args(&["ca", "remove"])), Ok(Command::CaRemove));
        assert_eq!(
            parse(&args(&["--check-config"])),
            Ok(Command::CheckConfig(None))
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
            &["ca", "path"][..],
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
            "ca install",
            "ca remove",
            "ca.cer",
            "ca.key",
            "DPAPI",
            "HTTPS_PROXY",
            "130",
        ] {
            assert!(USAGE.contains(flag), "{flag}");
        }
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
