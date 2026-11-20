//! Connection monitor (#57, firewall Phase 1): every TCP connection on the machine, attributed to its process and,
//! where possible, a hostname. Read-only: nothing is blocked, and it needs no admin rights.
//!
//! A sampler polls the IP Helper TCP tables (IPv4 and IPv6). [`Tracker`] diffs successive snapshots into opened and
//! closed connections, names their process and host, rate-limits the events and keeps the live list the Network tab
//! shows. Everything except the table read is pure and tested on every OS.
//!
//! ponytail: polling misses connections that open and close between two samples (default 1 s). The upgrade path is
//! WFP net events from the Phase 2 service (#59) or ETW `Microsoft-Windows-Kernel-Network`, which needs admin rights.
//! ponytail: UDP is not reported. The IP Helper UDP table lists local sockets only, with no remote address, so it
//! cannot show where datagrams go; WFP (#59) can.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::event::{ConnectionEvent, ConnectionState, Record};
use crate::process::Process;

/// TCP state `MIB_TCP_STATE_LISTEN`.
const LISTEN: u32 = 2;

/// One connection-table row, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u32,
    pub pid: u32,
}

/// A connection, keyed so a reused PID or port is a new connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    pub pid: u32,
    /// Process creation time (FILETIME ticks).
    pub start: u64,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Outbound,
    Inbound,
}

fn addr_v4(word: u32) -> Ipv4Addr {
    Ipv4Addr::from(word.to_ne_bytes())
}

fn port(word: u32) -> u16 {
    let b = word.to_ne_bytes();
    u16::from_be_bytes([b[0], b[1]])
}

/// `MIB_TCPTABLE_OWNER_PID` with all states: count, then rows of state, local addr, local port, remote addr, remote
/// port, pid. A count larger than the buffer is clamped.
pub fn parse_v4(buf: &[u32]) -> Vec<Row> {
    let Some((&n, rows)) = buf.split_first() else {
        return Vec::new();
    };
    rows.as_chunks::<6>()
        .0
        .iter()
        .take(n as usize)
        .map(|r| Row {
            state: r[0],
            local: SocketAddr::from((addr_v4(r[1]), port(r[2]))),
            remote: SocketAddr::from((addr_v4(r[3]), port(r[4]))),
            pid: r[5],
        })
        .collect()
}

/// `MIB_TCP6TABLE_OWNER_PID`: count, then 14-word rows of local addr (16 bytes), scope, port, remote addr, scope,
/// port, state, pid.
pub fn parse_v6(buf: &[u32]) -> Vec<Row> {
    let Some((&n, rows)) = buf.split_first() else {
        return Vec::new();
    };
    let v6 = |w: &[u32]| {
        let mut b = [0u8; 16];
        for (i, word) in w.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        Ipv6Addr::from(b)
    };
    rows.as_chunks::<14>()
        .0
        .iter()
        .take(n as usize)
        .map(|r| Row {
            local: SocketAddr::from((v6(&r[0..4]), port(r[5]))),
            remote: SocketAddr::from((v6(&r[6..10]), port(r[11]))),
            state: r[12],
            pid: r[13],
        })
        .collect()
}

/// Whether a remote address leaves the machine. Loopback (the proxy itself, local model servers) and unconnected
/// rows are not network connections.
fn is_remote(addr: SocketAddr) -> bool {
    let ip = match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    addr.port() != 0 && !ip.is_loopback() && !ip.is_unspecified()
}

/// Splits rows into network connections and the listening `(pid, port)` pairs that mark inbound ones. Rows without
/// an owner (PID 0: TIME_WAIT and the like) are dropped.
pub fn connections(rows: &[Row]) -> (Vec<Row>, HashSet<(u32, u16)>) {
    let listeners = rows
        .iter()
        .filter(|r| r.state == LISTEN)
        .map(|r| (r.pid, r.local.port()))
        .collect();
    let open = rows
        .iter()
        .filter(|r| r.state != LISTEN && r.pid != 0 && is_remote(r.remote))
        .copied()
        .collect();
    (open, listeners)
}

/// A connection is inbound when its process listens on its local port; anything else was dialled out.
pub fn direction(row: &Row, listeners: &HashSet<(u32, u16)>) -> Direction {
    if listeners.contains(&(row.pid, row.local.port())) {
        Direction::Inbound
    } else {
        Direction::Outbound
    }
}

/// Connections in `next` but not in `prev` (opened) and the other way round (closed).
pub fn diff(prev: &HashSet<Key>, next: &HashSet<Key>) -> (Vec<Key>, Vec<Key>) {
    (
        next.difference(prev).copied().collect(),
        prev.difference(next).copied().collect(),
    )
}

/// (pid, process start, remote IP, remote port, state): what the limiter counts per.
type LimitKey = (u32, u64, IpAddr, u16, ConnectionState);

/// At most one event per (process, remote IP, port, state) per window; the rest are counted and the count rides on
/// the next event that is let through. Chatty apps cannot flood the log.
pub struct Limiter {
    window: Duration,
    max_keys: usize,
    last: HashMap<LimitKey, (Instant, u32)>,
}

impl Limiter {
    pub fn new(window: Duration, max_keys: usize) -> Self {
        Self {
            window,
            max_keys: max_keys.max(1),
            last: HashMap::new(),
        }
    }

    /// `Some(suppressed since the last logged one)` to log this event, `None` to drop it.
    pub fn check(&mut self, key: &Key, state: ConnectionState, now: Instant) -> Option<u32> {
        let k = (
            key.pid,
            key.start,
            key.remote.ip(),
            key.remote.port(),
            state,
        );
        if let Some((at, suppressed)) = self.last.get_mut(&k) {
            if now.duration_since(*at) < self.window {
                *suppressed += 1;
                return None;
            }
            let n = std::mem::take(suppressed);
            *at = now;
            return Some(n);
        }
        if self.last.len() >= self.max_keys {
            let window = self.window;
            // ponytail: counts suppressed under a pruned key are lost; they only ever lowered the noise.
            self.last
                .retain(|_, (at, _)| now.duration_since(*at) < window);
            if self.last.len() >= self.max_keys {
                self.last.clear();
            }
        }
        self.last.insert(k, (now, 0));
        Some(0)
    }
}

/// One connection as the Network tab shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveConnection {
    pub process: Process,
    pub remote: SocketAddr,
    pub hostname: Option<String>,
    pub direction: Direction,
    /// The first connection from this program to this host since Gatewizz started.
    pub first_seen: bool,
    pub opened: Instant,
}

/// What the sampler last saw, shared with the UI.
#[derive(Default)]
pub struct Live(Mutex<LiveState>);

#[derive(Clone, Default)]
pub struct LiveState {
    pub connections: Vec<LiveConnection>,
    /// Why the last sample failed, if it did.
    pub error: Option<String>,
    /// Why the last DNS cache read failed, if it did; hostnames are then missing, connections are not.
    pub dns_error: Option<String>,
    pub sampled: Option<Instant>,
}

impl Live {
    pub fn snapshot(&self) -> LiveState {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set(
        &self,
        connections: Vec<LiveConnection>,
        error: Option<String>,
        dns_error: Option<String>,
        now: Instant,
    ) {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if error.is_none() {
            s.connections = connections;
        }
        s.error = error;
        s.dns_error = dns_error;
        s.sampled = Some(now);
    }
}

/// The program's lower-case file name, the "process" in "process + host" pairs.
fn program(process: &Process) -> Option<String> {
    match process {
        Process::Known { image, .. } => Some(
            image
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(image)
                .to_ascii_lowercase(),
        ),
        Process::Unknown(_) => None,
    }
}

/// Bound on the remembered (program, host) pairs; past it the set starts over and pairs are "new" once more.
const MAX_PAIRS: usize = 20_000;

/// Turns successive table snapshots into events and the live list.
pub struct Tracker {
    current: HashMap<Key, LiveConnection>,
    limiter: Limiter,
    pairs: HashSet<(String, String)>,
}

impl Tracker {
    pub fn new(window: Duration) -> Self {
        Self {
            current: HashMap::new(),
            limiter: Limiter::new(window, 4096),
            pairs: HashSet::new(),
        }
    }

    /// Takes one snapshot of `(key, direction)` pairs. `describe` names a new connection's process and `hostname`
    /// its remote host; both run once per opened connection. Returns the events to log, in order.
    pub fn update(
        &mut self,
        snapshot: Vec<(Key, Direction)>,
        mut describe: impl FnMut(u32, u64) -> Process,
        mut hostname: impl FnMut(IpAddr, u32) -> Option<String>,
        now: Instant,
        time: &str,
    ) -> Vec<ConnectionEvent> {
        let next: HashMap<Key, Direction> = snapshot.into_iter().collect();
        let prev: HashSet<Key> = self.current.keys().copied().collect();
        let (opened, closed) = diff(&prev, &next.keys().copied().collect());
        let mut events = Vec::new();
        for key in closed {
            let Some(conn) = self.current.remove(&key) else {
                continue;
            };
            if let Some(suppressed) = self.limiter.check(&key, ConnectionState::Closed, now) {
                events.push(event(&conn, ConnectionState::Closed, suppressed, time));
            }
        }
        let mut opened = opened;
        // Stable order for the log: by process, then remote address.
        opened.sort_by_key(|k| (k.pid, k.remote, k.local));
        for key in opened {
            let process = describe(key.pid, key.start);
            let hostname = hostname(key.remote.ip(), key.pid);
            let first_seen = match program(&process) {
                Some(name) => {
                    let host = hostname
                        .clone()
                        .unwrap_or_else(|| key.remote.ip().to_string());
                    if self.pairs.len() >= MAX_PAIRS {
                        self.pairs.clear();
                    }
                    self.pairs.insert((name, host))
                }
                None => false,
            };
            let conn = LiveConnection {
                process,
                remote: key.remote,
                hostname,
                direction: next[&key],
                first_seen,
                opened: now,
            };
            if let Some(suppressed) = self.limiter.check(&key, ConnectionState::Opened, now) {
                events.push(event(&conn, ConnectionState::Opened, suppressed, time));
            }
            self.current.insert(key, conn);
        }
        events
    }

    /// The current connections, grouped by program and then by host.
    pub fn live(&self) -> Vec<LiveConnection> {
        let mut list: Vec<LiveConnection> = self.current.values().cloned().collect();
        list.sort_by(|a, b| {
            (program(&a.process), &a.hostname, a.remote).cmp(&(
                program(&b.process),
                &b.hostname,
                b.remote,
            ))
        });
        list
    }
}

fn event(
    conn: &LiveConnection,
    state: ConnectionState,
    suppressed: u32,
    time: &str,
) -> ConnectionEvent {
    ConnectionEvent {
        kind: "connection",
        time: time.to_string(),
        state,
        process: conn.process.clone(),
        protocol: "tcp",
        direction: conn.direction,
        remote_ip: conn.remote.ip(),
        port: conn.remote.port(),
        hostname: conn.hostname.clone(),
        first_seen: state == ConnectionState::Opened && conn.first_seen,
        suppressed,
    }
}

/// Settings from `[monitor]`.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub poll: Duration,
    pub dns_cache_size: usize,
}

/// The running sampler; [`Monitor::stop`] ends it and drops its event sender.
pub struct Monitor {
    stop: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl Monitor {
    /// Stops sampling and waits for the thread. An `Err` means the monitor thread panicked.
    pub fn stop(self) -> Result<(), String> {
        // A failed send only means the thread already returned (its event writer closed); join tells the rest.
        let _ = self.stop.send(());
        self.thread
            .join()
            .map_err(|_| "[monitor] the connection monitor panicked".to_string())
    }
}

/// One event per process, remote address and state per this window (see [`Limiter`]).
const RATE_WINDOW: Duration = Duration::from_secs(10);

/// How often the DNS cache may be re-read while connections to unknown addresses keep appearing.
const DNS_REFRESH: Duration = Duration::from_secs(1);

/// Starts sampling on its own thread. Events go to `events`; the live list to `live`.
pub fn start(
    settings: Settings,
    events: tokio::sync::mpsc::Sender<Record>,
    live: Arc<Live>,
) -> Result<Monitor, String> {
    if !cfg!(windows) {
        return Err(
            "[configuration] monitor.enabled: the connection monitor runs only on Windows".into(),
        );
    }
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::Builder::new()
        .name("monitor".into())
        .spawn(move || {
            let mut tracker = Tracker::new(RATE_WINDOW);
            let mut dns = crate::dns::Cache::new(settings.dns_cache_size);
            let mut dns_read: Option<Instant> = None;
            // The last refresh's outcome, shown in the Network tab until a later refresh succeeds.
            let mut dns_error: Option<String> = None;
            loop {
                let now = Instant::now();
                let sample = sys::rows().map(|rows| {
                    let (open, listeners) = connections(&rows);
                    let mut starts: HashMap<u32, Option<u64>> = HashMap::new();
                    open.iter()
                        .filter_map(|row| {
                            let start = *starts
                                .entry(row.pid)
                                .or_insert_with(|| crate::process::start_time(row.pid));
                            // A process that exited between the table read and here is gone; its row is stale.
                            start.map(|start| {
                                let key = Key {
                                    pid: row.pid,
                                    start,
                                    local: row.local,
                                    remote: row.remote,
                                };
                                (key, direction(row, &listeners))
                            })
                        })
                        .collect::<Vec<_>>()
                });
                match sample {
                    Ok(snapshot) => {
                        let time = crate::event::now();
                        let records = tracker.update(
                            snapshot,
                            crate::process::describe_pid,
                            |ip, pid| {
                                let refresh_allowed = match dns_read {
                                    None => true,
                                    Some(at) => now.duration_since(at) >= DNS_REFRESH,
                                };
                                if dns.lookup(ip, pid, now).is_none() && refresh_allowed {
                                    dns_read = Some(now);
                                    // A failed read leaves addresses unnamed until a later refresh works; the
                                    // Network tab says why meanwhile.
                                    dns_error = crate::dns::refresh(&mut dns, now).err();
                                }
                                dns.lookup(ip, pid, now).map(str::to_string)
                            },
                            now,
                            &time,
                        );
                        for record in records {
                            // A closed writer means shutdown; stop quietly.
                            if events.blocking_send(Record::Connection(record)).is_err() {
                                return;
                            }
                        }
                        live.set(tracker.live(), None, dns_error.clone(), now);
                    }
                    Err(err) => live.set(Vec::new(), Some(err), dns_error.clone(), now),
                }
                match stopped.recv_timeout(settings.poll) {
                    Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        })
        .map_err(|e| format!("[configuration] cannot start the connection monitor: {e}"))?;
    Ok(Monitor { stop, thread })
}

#[cfg(not(windows))]
mod sys {
    pub fn rows() -> Result<Vec<super::Row>, String> {
        Err("[monitor] unsupported".into())
    }
}

#[cfg(windows)]
mod sys {
    use super::{Row, parse_v4, parse_v6};
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    fn table(family: u16) -> Result<Vec<u32>, String> {
        let mut size = 0u32;
        // The table can grow between the size query and the read, so retry.
        for _ in 0..4 {
            // u32 elements keep the buffer aligned for the row structs.
            let mut buf = vec![0u32; (size as usize).div_ceil(4)];
            let rc = unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr().cast::<c_void>(),
                    &mut size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            match rc {
                NO_ERROR => return Ok(buf),
                ERROR_INSUFFICIENT_BUFFER => continue,
                rc => return Err(format!("[monitor] GetExtendedTcpTable failed ({rc})")),
            }
        }
        Err("[monitor] the TCP table kept growing".into())
    }

    pub fn rows() -> Result<Vec<Row>, String> {
        let mut rows = parse_v4(&table(AF_INET)?);
        rows.extend(parse_v6(&table(AF_INET6)?));
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn known(pid: u32, image: &str) -> Process {
        Process::Known {
            pid,
            start: 1,
            image: image.into(),
            user: r"D\u".into(),
        }
    }

    fn key(pid: u32, start: u64, local: &str, remote: &str) -> Key {
        Key {
            pid,
            start,
            local: sa(local),
            remote: sa(remote),
        }
    }

    /// Encodes rows the way IP Helper lays them out in memory (ports in network order in the low two bytes).
    fn v4_table(rows: &[(u32, &str, &str, u32)]) -> Vec<u32> {
        let enc = |a: SocketAddr| {
            let SocketAddr::V4(a) = a else { unreachable!() };
            let p = a.port().to_be_bytes();
            (
                u32::from_ne_bytes(a.ip().octets()),
                u32::from_ne_bytes([p[0], p[1], 0xAB, 0xCD]),
            )
        };
        let mut buf = vec![rows.len() as u32];
        for &(state, l, r, pid) in rows {
            let ((la, lp), (ra, rp)) = (enc(sa(l)), enc(sa(r)));
            buf.extend([state, la, lp, ra, rp, pid]);
        }
        buf
    }

    #[test]
    fn decodes_v4_rows_and_clamps_the_count() {
        let mut buf = v4_table(&[(5, "192.168.1.5:50000", "93.184.215.14:443", 42)]);
        assert_eq!(
            parse_v4(&buf),
            vec![Row {
                local: sa("192.168.1.5:50000"),
                remote: sa("93.184.215.14:443"),
                state: 5,
                pid: 42
            }]
        );
        buf[0] = 1000;
        assert_eq!(parse_v4(&buf).len(), 1);
        assert!(parse_v4(&[]).is_empty());
    }

    #[test]
    fn decodes_v6_rows() {
        let words = |ip: Ipv6Addr| {
            let o = ip.octets();
            [0, 4, 8, 12].map(|i| u32::from_ne_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]]))
        };
        let p = |n: u16| u32::from_ne_bytes([n.to_be_bytes()[0], n.to_be_bytes()[1], 0, 0]);
        let (local, remote): (Ipv6Addr, Ipv6Addr) = (
            "2001:db8::5".parse().unwrap(),
            "2606:2800:21f:cb07::1".parse().unwrap(),
        );
        let mut buf = vec![1];
        buf.extend(words(local));
        buf.extend([0, p(50000)]);
        buf.extend(words(remote));
        buf.extend([0, p(443), 5, 77]);
        assert_eq!(
            parse_v6(&buf),
            vec![Row {
                local: SocketAddr::from((local, 50000)),
                remote: SocketAddr::from((remote, 443)),
                state: 5,
                pid: 77
            }]
        );
    }

    #[test]
    fn keeps_network_connections_and_finds_listeners() {
        let row = |state, local: &str, remote: &str, pid| Row {
            local: sa(local),
            remote: sa(remote),
            state,
            pid,
        };
        let rows = [
            row(LISTEN, "0.0.0.0:22", "0.0.0.0:0", 10),
            row(5, "192.168.1.5:22", "192.168.1.9:51000", 10),
            row(5, "192.168.1.5:50000", "93.184.215.14:443", 42),
            row(5, "127.0.0.1:50001", "127.0.0.1:8899", 42),
            row(5, "[::1]:50002", "[::1]:8899", 42),
            row(5, "[::ffff:127.0.0.1]:50003", "[::ffff:127.0.0.1]:8899", 42),
            row(11, "192.168.1.5:50004", "93.184.215.14:443", 0),
        ];
        let (open, listeners) = connections(&rows);
        assert_eq!(open.len(), 2, "{open:?}");
        assert_eq!(direction(&open[0], &listeners), Direction::Inbound);
        assert_eq!(direction(&open[1], &listeners), Direction::Outbound);
    }

    #[test]
    fn diff_reports_new_and_closed_and_pid_reuse() {
        let a = key(42, 1, "10.0.0.5:50000", "1.2.3.4:443");
        let b = key(43, 1, "10.0.0.5:50001", "1.2.3.4:443");
        // Same PID and endpoints, different process start: a different connection.
        let reused = key(42, 2, "10.0.0.5:50000", "1.2.3.4:443");
        let prev: HashSet<Key> = [a, b].into();
        let next: HashSet<Key> = [b, reused].into();
        let (opened, closed) = diff(&prev, &next);
        assert_eq!(opened, vec![reused]);
        assert_eq!(closed, vec![a]);
    }

    #[test]
    fn limiter_lets_one_event_through_per_window_and_counts_the_rest() {
        let now = Instant::now();
        let mut l = Limiter::new(Duration::from_secs(10), 16);
        let k = key(42, 1, "10.0.0.5:50000", "1.2.3.4:443");
        let k2 = key(42, 1, "10.0.0.5:50001", "1.2.3.4:443"); // same process and remote
        assert_eq!(l.check(&k, ConnectionState::Opened, now), Some(0));
        assert_eq!(
            l.check(&k2, ConnectionState::Opened, now + Duration::from_secs(1)),
            None
        );
        assert_eq!(
            l.check(&k2, ConnectionState::Opened, now + Duration::from_secs(2)),
            None
        );
        // Another state or another remote is not limited by this key.
        assert_eq!(l.check(&k, ConnectionState::Closed, now), Some(0));
        let other = key(42, 1, "10.0.0.5:50002", "5.6.7.8:443");
        assert_eq!(l.check(&other, ConnectionState::Opened, now), Some(0));
        // After the window the next one passes and carries the count.
        assert_eq!(
            l.check(&k2, ConnectionState::Opened, now + Duration::from_secs(10)),
            Some(2)
        );
    }

    #[test]
    fn limiter_is_bounded() {
        let now = Instant::now();
        let mut l = Limiter::new(Duration::from_secs(10), 4);
        for i in 0..100u16 {
            let k = key(1, 1, "10.0.0.5:1", &format!("1.2.3.4:{}", i + 1));
            assert_eq!(l.check(&k, ConnectionState::Opened, now), Some(0));
            assert!(l.last.len() <= 4);
        }
    }

    #[test]
    fn tracker_logs_opened_and_closed_with_process_host_and_first_seen() {
        let now = Instant::now();
        let mut t = Tracker::new(Duration::from_secs(10));
        let k = key(42, 1, "10.0.0.5:50000", "93.184.215.14:443");
        let describe = |pid, _| known(pid, r"C:\Tools\curl.exe");
        let host = |_ip, _pid| Some("example.com".to_string());

        let events = t.update(vec![(k, Direction::Outbound)], describe, host, now, "t1");
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(
            (e.state, e.port, e.hostname.as_deref()),
            (ConnectionState::Opened, 443, Some("example.com"))
        );
        assert!(e.first_seen);
        assert_eq!(t.live().len(), 1);

        // Unchanged snapshot: nothing new.
        assert!(
            t.update(vec![(k, Direction::Outbound)], describe, host, now, "t2")
                .is_empty()
        );

        // Closed: reported with the process and host it had, even if the process is gone now.
        let gone = |_, _| Process::Unknown("process exited or access denied");
        let events = t.update(Vec::new(), gone, |_, _| None, now, "t3");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].state, ConnectionState::Closed);
        assert_eq!(events[0].process, known(42, r"C:\Tools\curl.exe"));
        assert_eq!(events[0].hostname.as_deref(), Some("example.com"));
        assert!(!events[0].first_seen);
        assert!(t.live().is_empty());

        // The same program to the same host again, after the rate window: logged, but no longer first seen.
        let k2 = key(42, 1, "10.0.0.5:50001", "93.184.215.14:443");
        let later = now + Duration::from_secs(11);
        let events = t.update(vec![(k2, Direction::Outbound)], describe, host, later, "t4");
        assert_eq!(events.len(), 1);
        assert!(!events[0].first_seen);
    }

    #[test]
    fn tracker_without_hostname_uses_the_ip_for_first_seen() {
        let now = Instant::now();
        let mut t = Tracker::new(Duration::from_secs(10));
        let describe = |pid, _| known(pid, r"C:\Tools\app.exe");
        let a = key(1, 1, "10.0.0.5:1", "1.1.1.1:443");
        let b = key(1, 1, "10.0.0.5:2", "8.8.8.8:443");
        let events = t.update(
            vec![(a, Direction::Outbound), (b, Direction::Outbound)],
            describe,
            |_, _| None,
            now,
            "t",
        );
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.first_seen && e.hostname.is_none()));
    }

    #[test]
    fn connection_events_serialize_as_metadata_only() {
        let now = Instant::now();
        let mut t = Tracker::new(Duration::from_secs(10));
        let k = key(42, 1, "10.0.0.5:50000", "93.184.215.14:443");
        let events = t.update(
            vec![(k, Direction::Outbound)],
            |pid, _| known(pid, r"C:\x.exe"),
            |_, _| Some("example.com".into()),
            now,
            "2026-11-20T12:00:00.000Z",
        );
        let json = serde_json::to_string(&Record::Connection(events[0].clone())).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"connection","time":"2026-11-20T12:00:00.000Z","state":"opened","process":{"known":{"pid":42,"start":1,"image":"C:\\x.exe","user":"D\\u"}},"protocol":"tcp","direction":"outbound","remote_ip":"93.184.215.14","port":443,"hostname":"example.com","first_seen":true}"#
        );
    }

    /// The real sampler sees a connection a child process holds open to a local listener, with the child's PID.
    /// Loopback is filtered from the monitor's view, so this checks the raw rows.
    #[cfg(windows)]
    #[test]
    fn sampler_sees_a_child_process_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut child = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$c = New-Object Net.Sockets.TcpClient('127.0.0.1', {port}); Start-Sleep 10"
                ),
            ])
            .spawn()
            .unwrap();
        let (_sock, _) = listener.accept().unwrap();
        let pid = child.id();
        let seen = sys::rows()
            .unwrap()
            .into_iter()
            .any(|r| r.pid == pid && r.remote.port() == port && r.state != LISTEN);
        let _ = child.kill();
        let _ = child.wait();
        // Windows closes the dead process's sockets right after it exits; give the table a moment.
        std::thread::sleep(Duration::from_millis(500));
        assert!(seen, "no row for child {pid} to port {port}");
        let still = sys::rows()
            .unwrap()
            .into_iter()
            .any(|r| r.pid == pid && r.remote.port() == port && r.state == 5);
        assert!(
            !still,
            "connection still established after the child exited"
        );
    }
}
