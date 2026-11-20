//! JSON Lines events, logwizz style: one object per request or tunnel, metadata only. There is deliberately no
//! field that could carry a header value, a query string or a body.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::mpsc;

use crate::config::EventTarget;
use crate::detect::Finding;
use crate::process::Process;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// The whole request, body included, was inspected before anything went upstream.
    Inspected,
    /// Headers were inspected, but the body only partly or not at all (over the limit, or compressed).
    PartiallyInspected,
    /// CONNECT passed through without decryption.
    Tunneled,
    /// Rejected by the proxy before anything was forwarded.
    Blocked,
}

/// One request or tunnel. Holds metadata only: never header values, query strings or bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    /// When the request arrived, RFC 3339 UTC with milliseconds.
    pub time: String,
    pub client: SocketAddr,
    pub process: Process,
    pub method: String,
    pub host: String,
    pub port: u16,
    /// Request path without the query string; empty for CONNECT.
    pub path: String,
    pub coverage: Coverage,
    /// Secret kinds found in the request, with counts; never the matched text.
    pub findings: Vec<Finding>,
    /// The model of an OpenAI-compatible request.
    pub model: Option<String>,
    pub status: u16,
    /// Why the proxy itself answered (rejection or upstream failure).
    pub reason: Option<&'static str>,
    /// Bytes client→upstream and upstream→client.
    // ponytail: bytes_down is counted for tunnels only; for plain HTTP it needs a counting response body.
    pub bytes_up: Option<u64>,
    pub bytes_down: Option<u64>,
}

/// The current time as RFC 3339 UTC with milliseconds.
pub fn now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339(d.as_secs(), d.subsec_millis())
}

/// Civil date from Unix seconds (Howard Hinnant's days-to-civil algorithm), so no date crate is needed for one
/// timestamp format.
fn rfc3339(secs: u64, millis: u32) -> String {
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// Writes lines to stdout or to a size-rotated file.
enum Out {
    Stdout,
    File {
        path: PathBuf,
        file: File,
        size: u64,
        max: u64,
        keep: usize,
    },
}

impl Out {
    fn open(target: EventTarget, max: u64, keep: usize) -> Result<Self, String> {
        let EventTarget::File(path) = target else {
            return Ok(Out::Stdout);
        };
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)
                .map_err(|e| format!("[events] cannot create {}: {e}", dir.display()))?;
        }
        let file =
            append(&path).map_err(|e| format!("[events] cannot open {}: {e}", path.display()))?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Out::File {
            path,
            file,
            size,
            max,
            keep,
        })
    }

    /// Writes one line, rotating first if it would push the file past `max`.
    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        match self {
            Out::Stdout => {
                let mut out = io::stdout().lock();
                out.write_all(line)?;
                out.flush()
            }
            Out::File {
                path,
                file,
                size,
                max,
                keep,
            } => {
                let len = line.len() as u64;
                if *size > 0 && *size + len > *max {
                    rotate(path, *keep)?;
                    *file = append(path)?;
                    *size = 0;
                }
                // ponytail: one unbuffered write per event keeps the file tail-able and loses nothing on a crash;
                // buffer if the powerwizz budget ever shows this.
                file.write_all(line)?;
                *size += len;
                Ok(())
            }
        }
    }
}

fn append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn numbered(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// `events.jsonl` becomes `.1`, `.1` becomes `.2`, ..., and the file past `keep` is deleted.
fn rotate(path: &Path, keep: usize) -> io::Result<()> {
    let remove = |p: &Path| match fs::remove_file(p) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    };
    if keep == 0 {
        return remove(path);
    }
    remove(&numbered(path, keep))?;
    for n in (1..keep).rev() {
        let from = numbered(path, n);
        if from.exists() {
            fs::rename(&from, numbered(path, n + 1))?;
        }
    }
    fs::rename(path, numbered(path, 1))
}

/// The writer thread; joining it returns the error that stopped it, if any.
pub type Writer = JoinHandle<Result<(), String>>;

/// Starts the writer on its own thread, since file I/O blocks anyway. The channel is bounded: when it is full,
/// `send().await` waits, so events are never dropped.
///
/// The writer stops after writing everything queued once every sender is dropped; join it to flush on shutdown.
/// If a write fails, the writer stops and returns the error, and later sends fail.
pub fn spawn(
    target: EventTarget,
    max_file_bytes: u64,
    keep_files: usize,
    capacity: usize,
) -> Result<(mpsc::Sender<Event>, Writer), String> {
    let mut out = Out::open(target, max_file_bytes, keep_files)?;
    let (tx, mut rx) = mpsc::channel::<Event>(capacity);
    let handle = std::thread::Builder::new()
        .name("events".into())
        .spawn(move || {
            while let Some(event) = rx.blocking_recv() {
                let mut line = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
                line.push(b'\n');
                out.write_line(&line)
                    .map_err(|e| format!("[events] write failed: {e}"))?;
            }
            Ok(())
        })
        .map_err(|e| format!("[events] cannot start writer: {e}"))?;
    Ok((tx, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gatewizz-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn event(path: &str) -> Event {
        Event {
            time: now(),
            client: "127.0.0.1:50000".parse().unwrap(),
            process: Process::Unknown("test"),
            method: "POST".into(),
            host: "api.example".into(),
            port: 443,
            path: path.into(),
            coverage: Coverage::PartiallyInspected,
            findings: Vec::new(),
            model: None,
            status: 200,
            reason: None,
            bytes_up: None,
            bytes_down: None,
        }
    }

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(rfc3339(1_795_121_328, 709), "2026-11-19T20:48:48.709Z");
        assert_eq!(rfc3339(4_107_542_399, 999), "2100-02-28T23:59:59.999Z");
        assert_eq!(now().len(), "2026-11-19T20:48:48.709Z".len());
    }

    #[test]
    fn serializes_metadata_fields_only() {
        let value = serde_json::to_value(event("/v1/chat")).unwrap();
        // Adding a field (a header map, a body) must be a deliberate change to this list, not a side effect.
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "bytes_down",
                "bytes_up",
                "client",
                "coverage",
                "findings",
                "host",
                "method",
                "model",
                "path",
                "port",
                "process",
                "reason",
                "status",
                "time"
            ]
        );
        assert_eq!(value["client"], "127.0.0.1:50000");
        assert_eq!(value["coverage"], "partially_inspected");
        assert_eq!(value["process"], serde_json::json!({"unknown": "test"}));
        assert_eq!(value["reason"], serde_json::Value::Null);
    }

    #[test]
    fn rotates_at_the_size_limit() {
        let dir = tempdir("rotate");
        let path = dir.join("events.jsonl");
        let mut out = Out::open(EventTarget::File(path.clone()), 10, 2).unwrap();
        for line in ["aaaaa\n", "bbb\n", "ccccc\n", "ddddd\n", "eeeee\n"] {
            out.write_line(line.as_bytes()).unwrap();
        }
        let read = |p: PathBuf| fs::read_to_string(p).unwrap();
        assert_eq!(read(path.clone()), "eeeee\n");
        assert_eq!(read(numbered(&path, 1)), "ddddd\n");
        assert_eq!(read(numbered(&path, 2)), "ccccc\n");
        // "aaaaa" and "bbb" shared the first file (exactly 10 bytes), which fell off the end.
        assert!(!numbered(&path, 3).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn keep_zero_truncates() {
        let dir = tempdir("keep0");
        let path = dir.join("e.jsonl");
        let mut out = Out::open(EventTarget::File(path.clone()), 4, 0).unwrap();
        out.write_line(b"one\n").unwrap();
        out.write_line(b"two\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two\n");
        assert!(!numbered(&path, 1).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writer_drains_the_queue_on_shutdown() {
        let dir = tempdir("writer");
        let path = dir.join("sub").join("events.jsonl");
        let (tx, handle) = spawn(EventTarget::File(path.clone()), 1 << 20, 1, 1).unwrap();
        for i in 0..20 {
            // Capacity 1: this waits for the writer instead of dropping.
            tx.blocking_send(event(&format!("/n{i}"))).unwrap();
        }
        drop(tx);
        handle.join().unwrap().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let paths: Vec<String> = text
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["path"].to_string())
            .collect();
        assert_eq!(paths.len(), 20);
        assert_eq!(paths[19], "\"/n19\"");
        fs::remove_dir_all(dir).unwrap();
    }
}
