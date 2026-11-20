//! TOML configuration, logwizz style: every key optional with a safe default,
//! unknown keys rejected, and errors that name the key and the reason.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::proxy::Settings;

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub limits: Limits,
    pub events: Events,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    /// Loopback address the proxy listens on.
    pub listen: SocketAddr,
    /// Ports a CONNECT may target; anything else is blocked.
    pub allowed_connect_ports: Vec<u16>,
}

impl Default for General {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8899)),
            allowed_connect_ports: vec![443],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_connections: usize,
    /// Largest request head (start line plus headers); larger heads get 431.
    pub max_header_bytes: usize,
    pub connect_timeout_secs: u64,
    pub header_timeout_secs: u64,
    pub response_timeout_secs: u64,
    /// A tunnel idle this long is closed.
    pub idle_timeout_secs: u64,
    /// How long shutdown waits for in-flight requests before exiting.
    pub shutdown_timeout_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 512,
            max_header_bytes: 64 * 1024,
            connect_timeout_secs: 10,
            header_timeout_secs: 30,
            response_timeout_secs: 120,
            idle_timeout_secs: 300,
            shutdown_timeout_secs: 10,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Events {
    /// File for JSON Lines events. Empty means the default location,
    /// `%LOCALAPPDATA%\gatewizz\events.jsonl`; `-` means stdout.
    pub path: String,
    /// The file is rotated before a line would push it past this size.
    pub max_file_bytes: u64,
    /// Rotated files kept next to the live one (`events.jsonl.1` ..).
    pub keep_files: usize,
}

impl Default for Events {
    fn default() -> Self {
        Self {
            path: String::new(),
            max_file_bytes: 10 * 1024 * 1024,
            keep_files: 5,
        }
    }
}

/// Where events go once `[events].path` is resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventTarget {
    Stdout,
    File(PathBuf),
}

/// `%LOCALAPPDATA%\gatewizz`, home of the default event log and the CA.
pub fn data_dir() -> Result<PathBuf, String> {
    std::env::var_os("LOCALAPPDATA")
        .map(|dir| Path::new(&dir).join("gatewizz"))
        .ok_or_else(|| "LOCALAPPDATA is not set".into())
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("[config] cannot read {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("[config] {}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        let g = &self.general;
        // Fail closed: a proxy that terminates TLS must not be reachable
        // from the network.
        if !g.listen.ip().is_loopback() {
            return Err(format!(
                "general.listen: {} is not a loopback address",
                g.listen
            ));
        }
        if g.allowed_connect_ports.is_empty() {
            return Err("general.allowed_connect_ports: must not be empty".into());
        }
        if g.allowed_connect_ports.contains(&0) {
            return Err("general.allowed_connect_ports: port 0 is not a valid target".into());
        }
        let l = &self.limits;
        for (key, value) in [
            ("max_connections", l.max_connections as u64),
            ("max_header_bytes", l.max_header_bytes as u64),
            ("connect_timeout_secs", l.connect_timeout_secs),
            ("header_timeout_secs", l.header_timeout_secs),
            ("response_timeout_secs", l.response_timeout_secs),
            ("idle_timeout_secs", l.idle_timeout_secs),
            ("shutdown_timeout_secs", l.shutdown_timeout_secs),
        ] {
            if value == 0 {
                return Err(format!("limits.{key}: must be at least 1"));
            }
        }
        if l.max_connections > u32::MAX as usize {
            return Err("limits.max_connections: too large".into());
        }
        if self.events.max_file_bytes < 4096 {
            return Err("events.max_file_bytes: must be at least 4096".into());
        }
        Ok(())
    }

    /// Resolves `[events].path`. The default needs `%LOCALAPPDATA%`.
    pub fn event_target(&self) -> Result<EventTarget, String> {
        match self.events.path.as_str() {
            "-" => Ok(EventTarget::Stdout),
            "" => data_dir()
                .map(|dir| EventTarget::File(dir.join("events.jsonl")))
                .map_err(|e| format!("events.path: {e}; set the path")),
            path => Ok(EventTarget::File(PathBuf::from(path))),
        }
    }

    /// The proxy settings this configuration describes.
    pub fn settings(&self) -> Settings {
        let (g, l) = (&self.general, &self.limits);
        Settings {
            allowed_connect_ports: g.allowed_connect_ports.clone(),
            max_connections: l.max_connections,
            max_header_bytes: l.max_header_bytes,
            connect_timeout: Duration::from_secs(l.connect_timeout_secs),
            header_timeout: Duration::from_secs(l.header_timeout_secs),
            response_timeout: Duration::from_secs(l.response_timeout_secs),
            idle_timeout: Duration::from_secs(l.idle_timeout_secs),
            shutdown_timeout: Duration::from_secs(l.shutdown_timeout_secs),
            // Interception is wired to the CA by #18; until then every CONNECT stays a blind tunnel.
            tls: None,
        }
    }

    /// The effective configuration as TOML, for `--check-config`.
    pub fn effective(&self) -> String {
        toml::to_string(self).expect("config always serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_gives_defaults() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        Config::default().validate().unwrap();
    }

    #[test]
    fn partial_sections_keep_other_defaults() {
        let c = Config::parse("[limits]\nmax_connections = 8\n").unwrap();
        assert_eq!(c.limits.max_connections, 8);
        assert_eq!(
            c.limits.idle_timeout_secs,
            Limits::default().idle_timeout_secs
        );
        assert_eq!(c.general, General::default());
    }

    #[test]
    fn parses_every_key() {
        let c = Config::parse(
            r#"
            [general]
            listen = "127.0.0.1:9000"
            allowed_connect_ports = [443, 8443]
            [limits]
            max_connections = 1
            max_header_bytes = 8192
            connect_timeout_secs = 3
            header_timeout_secs = 4
            response_timeout_secs = 5
            idle_timeout_secs = 6
            shutdown_timeout_secs = 7
            [events]
            path = "-"
            max_file_bytes = 4096
            keep_files = 0
            "#,
        )
        .unwrap();
        assert_eq!(c.general.listen.port(), 9000);
        assert_eq!(c.general.allowed_connect_ports, [443, 8443]);
        assert_eq!(c.settings().response_timeout, Duration::from_secs(5));
        assert_eq!(c.settings().shutdown_timeout, Duration::from_secs(7));
        assert_eq!(c.events.keep_files, 0);
        assert_eq!(c.event_target(), Ok(EventTarget::Stdout));
    }

    #[test]
    fn rejects_unknown_keys_naming_them() {
        for (text, key) in [
            ("bogus = 1", "bogus"),
            ("[general]\nlisten_port = 1", "listen_port"),
            ("[rules]\nx = 1", "rules"),
        ] {
            let err = Config::parse(text).unwrap_err();
            assert!(err.contains(key), "{err}");
        }
    }

    #[test]
    fn type_errors_name_the_key() {
        let err = Config::parse("[limits]\nmax_connections = \"many\"").unwrap_err();
        assert!(err.contains("max_connections"), "{err}");
    }

    #[test]
    fn validation_errors_name_key_and_reason() {
        for (text, msg) in [
            (
                "[general]\nlisten = \"0.0.0.0:8899\"",
                "general.listen: 0.0.0.0:8899 is not a loopback address",
            ),
            (
                "[general]\nallowed_connect_ports = []",
                "general.allowed_connect_ports: must not be empty",
            ),
            (
                "[general]\nallowed_connect_ports = [0]",
                "general.allowed_connect_ports: port 0",
            ),
            (
                "[limits]\nidle_timeout_secs = 0",
                "limits.idle_timeout_secs: must be at least 1",
            ),
            (
                "[limits]\nmax_header_bytes = 0",
                "limits.max_header_bytes: must be at least 1",
            ),
            (
                "[events]\nmax_file_bytes = 10",
                "events.max_file_bytes: must be at least 4096",
            ),
        ] {
            let err = Config::parse(text).unwrap_err();
            assert!(err.starts_with(msg), "{err}");
        }
    }

    #[test]
    fn ipv6_loopback_is_allowed() {
        Config::parse("[general]\nlisten = \"[::1]:8899\"").unwrap();
    }

    #[test]
    fn explicit_event_path() {
        let c = Config::parse("[events]\npath = 'x/e.jsonl'").unwrap();
        assert_eq!(c.event_target(), Ok(EventTarget::File("x/e.jsonl".into())));
    }

    #[test]
    fn defaults_match_the_proxy() {
        assert_eq!(
            format!("{:?}", Config::default().settings()),
            format!("{:?}", Settings::default())
        );
    }

    #[test]
    fn effective_config_round_trips() {
        let c = Config::default();
        assert_eq!(Config::parse(&c.effective()).unwrap(), c);
    }

    #[test]
    fn example_file_matches_defaults() {
        let text = include_str!("../config/gatewizz.example.toml");
        let uncommented: String = text
            .lines()
            .map(|l| {
                l.strip_prefix("# ")
                    .filter(|r| r.contains(" = "))
                    .unwrap_or(l)
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(Config::parse(text).unwrap(), Config::default());
        assert_eq!(Config::parse(&uncommented).unwrap(), Config::default());
    }

    #[test]
    fn load_reports_missing_file() {
        let err = Config::load(Path::new("does/not/exist.toml")).unwrap_err();
        assert!(err.starts_with("[config] cannot read"), "{err}");
    }
}
