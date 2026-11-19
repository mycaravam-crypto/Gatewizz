//! Gatewizz: a local HTTPS gate for code sent to AI models. See PLAN.md.

mod proxy;

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit code for an execution failure, as in smartwizz.
const EXIT_FAILURE: u8 = 2;

// ponytail: fixed until the config file (#4) and the CLI (#6) make it configurable.
const LISTEN: &str = "127.0.0.1:8899";

/// Bounded so a stalled consumer slows the proxy down instead of growing memory.
const EVENT_QUEUE: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Run,
    Version,
}

// ponytail: hand-rolled until #6 needs real flags; replace with clap there.
fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [] => Ok(Command::Run),
        [flag] if flag == "--version" || flag == "-V" => Ok(Command::Version),
        _ => Err("[usage] gatewizz takes no arguments yet, except --version".into()),
    }
}

fn run_proxy() -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("[configuration] cannot start runtime: {err}"))?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(LISTEN)
            .await
            .map_err(|err| format!("[network] cannot listen on {LISTEN}: {err}"))?;
        eprintln!("gatewizz {VERSION} listening on {LISTEN}");
        let (events, mut received) = tokio::sync::mpsc::channel(EVENT_QUEUE);
        // ponytail: events go to stderr in Debug form until the JSON Lines writer (#4).
        tokio::spawn(async move {
            while let Some(event) = received.recv().await {
                eprintln!("{event:?}");
            }
        });
        proxy::serve(listener, proxy::Settings::default(), events)
            .await
            .map_err(|err| format!("[network] {err}"))
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match parse(&args) {
        Ok(Command::Version) => {
            println!("gatewizz {VERSION}");
            Ok(())
        }
        Ok(Command::Run) => run_proxy(),
        Err(err) => Err(err),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
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
        assert_eq!(parse(&args(&[])), Ok(Command::Run));
        assert_eq!(parse(&args(&["--version"])), Ok(Command::Version));
        assert_eq!(parse(&args(&["-V"])), Ok(Command::Version));
    }

    #[test]
    fn rejects_anything_else_as_usage_error() {
        for input in [&["--bogus"][..], &["--version", "x"][..]] {
            let err = parse(&args(input)).unwrap_err();
            assert!(err.starts_with("[usage]"), "{err}");
        }
    }
}
