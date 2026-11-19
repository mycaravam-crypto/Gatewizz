//! Gatewizz: a local HTTPS gate for code sent to AI models. See PLAN.md.

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit code for an execution failure, as in smartwizz.
const EXIT_FAILURE: u8 = 2;

// ponytail: hand-rolled until #6 needs real flags; replace with clap there.
fn run(args: &[String]) -> Result<String, String> {
    match args {
        [flag] if flag == "--version" || flag == "-V" => Ok(format!("gatewizz {VERSION}")),
        _ => Err("[usage] the proxy is not implemented yet; only --version is available".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
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
    fn prints_version() {
        assert_eq!(
            run(&args(&["--version"])),
            Ok(format!("gatewizz {VERSION}"))
        );
        assert_eq!(run(&args(&["-V"])), Ok(format!("gatewizz {VERSION}")));
    }

    #[test]
    fn rejects_anything_else_as_usage_error() {
        for input in [&[][..], &["--bogus"][..], &["--version", "x"][..]] {
            let err = run(&args(input)).unwrap_err();
            assert!(err.starts_with("[usage]"), "{err}");
        }
    }
}
