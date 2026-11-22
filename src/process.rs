//! Which local process opened a loopback connection to the proxy.
//!
//! In explicit-proxy mode the client connects over loopback, so the accepted
//! socket's peer address is the client's local endpoint. The IP Helper TCP
//! table maps that endpoint to a PID. Processes are keyed by `(pid, start)`
//! so a reused PID is never mistaken for the process that held it before.
//!
//! A failed lookup never fails the connection: it yields `Process::Unknown`.

// The decoders are reached only from the Windows lookup and the tests.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The client process behind a connection.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Process {
    Known {
        pid: u32,
        /// Creation time as a Windows FILETIME (100 ns ticks since 1601).
        start: u64,
        image: String,
        /// `DOMAIN\user`, or empty if the token could not be read.
        user: String,
    },
    Unknown(&'static str),
}

/// The reason when the client is not a Windows process, e.g. WSL in mirrored networking mode.
pub const OUTSIDE_WINDOWS: &str = "WSL or VM";

/// One row of `TCP_TABLE_OWNER_PID_CONNECTIONS`, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Row {
    local: SocketAddrV4,
    remote: SocketAddrV4,
    pid: u32,
}

/// `MIB_TCPROW_OWNER_PID`: state, local addr, local port, remote addr,
/// remote port, owning pid. All `u32`.
const ROW_WORDS: usize = 6;

/// Addresses are stored in network byte order, so the in-memory bytes are
/// the octets in order.
fn row_addr(dw: u32) -> Ipv4Addr {
    Ipv4Addr::from(dw.to_ne_bytes())
}

/// Ports are in network byte order in the first two bytes; the upper two
/// bytes are undefined and ignored.
fn row_port(dw: u32) -> u16 {
    let b = dw.to_ne_bytes();
    u16::from_be_bytes([b[0], b[1]])
}

/// Decodes a `MIB_TCPTABLE_OWNER_PID` buffer: `dwNumEntries` then the rows.
/// A count larger than the buffer is clamped, never trusted.
fn parse_table(buf: &[u32]) -> Vec<Row> {
    let Some((&n, rows)) = buf.split_first() else {
        return Vec::new();
    };
    rows.as_chunks::<ROW_WORDS>()
        .0
        .iter()
        .take(n as usize)
        .map(|r| Row {
            local: SocketAddrV4::new(row_addr(r[1]), row_port(r[2])),
            remote: SocketAddrV4::new(row_addr(r[3]), row_port(r[4])),
            pid: r[5],
        })
        .collect()
}

/// The client's row has the accepted socket's peer as its local endpoint and
/// the listener as its remote endpoint. The proxy's own row is the mirror
/// image, so it never matches.
fn find_client_pid(rows: &[Row], peer: SocketAddrV4, listener: SocketAddrV4) -> Option<u32> {
    rows.iter()
        .find(|r| r.local == peer && r.remote == listener)
        .map(|r| r.pid)
}

const CACHE_TTL: Duration = Duration::from_secs(300);
const CACHE_MAX: usize = 512;

/// Caches image and user per `(pid, start)`. The PID lookup itself always
/// runs, because ports are reused far faster than a TTL could track.
#[derive(Default)]
struct Cache(Mutex<HashMap<(u32, u64), (Instant, Process)>>);

fn cache() -> &'static Cache {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    CACHE.get_or_init(Cache::default)
}

/// Identifies the process on the other end of an accepted connection.
/// `peer` is the accepted socket's peer address, `local` its local
/// (listener) address.
pub fn client_process(peer: SocketAddr, local: SocketAddr) -> Process {
    let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (peer, local) else {
        // ponytail: the listener binds 127.0.0.1 only (#1), so IPv6 needs
        // no TCP6 table until a [::1] listener exists.
        return Process::Unknown("ipv6");
    };
    if !cfg!(windows) {
        return Process::Unknown("unsupported");
    }
    let Some(rows) = sys::tcp_table() else {
        return Process::Unknown("tcp table unavailable");
    };
    // Loopback from WSL (mirrored networking) or another VM has no Windows socket, so no row.
    let Some(pid) = find_client_pid(&rows, peer, local) else {
        return Process::Unknown(OUTSIDE_WINDOWS);
    };
    let Some(start) = sys::start_time(pid) else {
        return Process::Unknown("process exited or access denied");
    };
    cache().lookup(pid, start, Instant::now(), || sys::describe(pid, start))
}

/// The creation time of `pid` (FILETIME ticks), or `None` if it exited or cannot be opened.
pub fn start_time(pid: u32) -> Option<u64> {
    sys::start_time(pid)
}

/// Names the process `(pid, start)`, through the same cache the proxy uses.
pub fn describe_pid(pid: u32, start: u64) -> Process {
    cache().lookup(pid, start, Instant::now(), || sys::describe(pid, start))
}

impl Cache {
    fn lookup(
        &self,
        pid: u32,
        start: u64,
        now: Instant,
        describe: impl FnOnce() -> Process,
    ) -> Process {
        let mut cache = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, p)) = cache.get(&(pid, start))
            && now.duration_since(*at) < CACHE_TTL
        {
            return p.clone();
        }
        let p = describe();
        if cache.len() >= CACHE_MAX {
            cache.retain(|_, (at, _)| now.duration_since(*at) < CACHE_TTL);
            if cache.len() >= CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert((pid, start), (now, p.clone()));
        p
    }
}

#[cfg(not(windows))]
mod sys {
    use super::{Process, Row};

    pub fn tcp_table() -> Option<Vec<Row>> {
        None
    }
    pub fn start_time(_pid: u32) -> Option<u64> {
        None
    }
    pub fn describe(_pid: u32, _start: u64) -> Process {
        Process::Unknown("unsupported")
    }
}

#[cfg(windows)]
mod sys {
    use super::{Process, Row, parse_table};
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_CONNECTIONS,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::Security::{
        GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    /// Closes the handle on drop.
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn open(pid: u32) -> Option<Handle> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        (!h.is_null()).then_some(Handle(h))
    }

    pub fn tcp_table() -> Option<Vec<Row>> {
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
                    AF_INET as u32,
                    TCP_TABLE_OWNER_PID_CONNECTIONS,
                    0,
                )
            };
            match rc {
                NO_ERROR => return Some(parse_table(&buf)),
                ERROR_INSUFFICIENT_BUFFER => continue,
                _ => return None,
            }
        }
        None
    }

    pub fn start_time(pid: u32) -> Option<u64> {
        let h = open(pid)?;
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        let ok = unsafe { GetProcessTimes(h.0, &mut created, &mut exited, &mut kernel, &mut user) };
        (ok != 0)
            .then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    pub fn describe(pid: u32, start: u64) -> Process {
        let Some(h) = open(pid) else {
            return Process::Unknown("process exited or access denied");
        };
        // A PID reused between start_time and here would carry another
        // creation time; report it as unknown rather than misattribute.
        if start_time(pid) != Some(start) {
            return Process::Unknown("pid reused");
        }
        let Some(image) = image(&h) else {
            return Process::Unknown("image path unavailable");
        };
        Process::Known {
            pid,
            start,
            image,
            user: user(&h).unwrap_or_default(),
        }
    }

    fn image(h: &Handle) -> Option<String> {
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        let ok = unsafe {
            QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
        };
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn user(h: &Handle) -> Option<String> {
        let mut token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(h.0, TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let token = Handle(token);
        let mut size = 0u32;
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size) };
        if size == 0 {
            return None;
        }
        // u64 elements keep the buffer aligned for TOKEN_USER.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let ok = unsafe {
            GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), size, &mut size)
        };
        if ok == 0 {
            return None;
        }
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let (mut name, mut domain) = (vec![0u16; 256], vec![0u16; 256]);
        let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
        let mut kind: SID_NAME_USE = 0;
        let ok = unsafe {
            LookupAccountSidW(
                null_mut(),
                sid,
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        };
        (ok != 0).then(|| {
            format!(
                "{}\\{}",
                String::from_utf16_lossy(&domain[..domain_len as usize]),
                String::from_utf16_lossy(&name[..name_len as usize])
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes an endpoint the way IP Helper lays it out in memory.
    fn enc(a: SocketAddrV4) -> (u32, u32) {
        let p = a.port().to_be_bytes();
        (
            u32::from_ne_bytes(a.ip().octets()),
            u32::from_ne_bytes([p[0], p[1], 0xAB, 0xCD]), // upper bytes are junk
        )
    }

    fn table(rows: &[(SocketAddrV4, SocketAddrV4, u32)]) -> Vec<u32> {
        let mut buf = vec![rows.len() as u32];
        for &(l, r, pid) in rows {
            let ((la, lp), (ra, rp)) = (enc(l), enc(r));
            buf.extend([5, la, lp, ra, rp, pid]);
        }
        buf
    }

    fn v4(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn decodes_raw_windows_words() {
        // 127.0.0.1 is bytes 7F 00 00 01; port 8080 is 1F 90.
        assert_eq!(row_addr(0x0100_007F), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(row_port(0x0000_901F), 8080);
        assert_eq!(row_port(0xFFFF_901F), 8080);
    }

    #[test]
    fn parses_rows() {
        let buf = table(&[(v4("127.0.0.1:50000"), v4("127.0.0.1:8080"), 42)]);
        assert_eq!(
            parse_table(&buf),
            vec![Row {
                local: v4("127.0.0.1:50000"),
                remote: v4("127.0.0.1:8080"),
                pid: 42
            }]
        );
    }

    #[test]
    fn clamps_count_to_buffer() {
        let mut buf = table(&[(v4("127.0.0.1:1"), v4("127.0.0.1:2"), 1)]);
        buf[0] = 1000;
        assert_eq!(parse_table(&buf).len(), 1);
        buf.pop(); // truncated row is dropped
        assert!(parse_table(&buf).is_empty());
        assert!(parse_table(&[]).is_empty());
    }

    #[test]
    fn matches_client_side_not_proxy_side() {
        let (peer, listener) = (v4("127.0.0.1:50000"), v4("127.0.0.1:8080"));
        let rows = parse_table(&table(&[
            (listener, peer, 7),                  // proxy's accepted socket
            (v4("127.0.0.1:50001"), listener, 9), // another client
            (peer, v4("127.0.0.1:9999"), 11),     // same port, other remote
            (peer, listener, 13),                 // the client
        ]));
        assert_eq!(find_client_pid(&rows, peer, listener), Some(13));
        assert_eq!(find_client_pid(&rows, v4("127.0.0.1:1"), listener), None);
    }

    #[test]
    fn cache_keys_on_pid_and_start() {
        let a = Cache::default();
        let now = Instant::now();
        let known = |start| Process::Known {
            pid: 1,
            start,
            image: format!("img{start}"),
            user: String::new(),
        };
        assert_eq!(a.lookup(1, 100, now, || known(100)), known(100));
        // Cached: describe is not called again.
        assert_eq!(a.lookup(1, 100, now, || unreachable!()), known(100));
        // Same PID, new start time: a reused PID is looked up afresh.
        assert_eq!(a.lookup(1, 200, now, || known(200)), known(200));
        // Expired entries are refreshed.
        let later = now + CACHE_TTL;
        assert_eq!(
            a.lookup(1, 100, later, || Process::Unknown("x")),
            Process::Unknown("x")
        );
    }

    #[test]
    fn cache_is_bounded() {
        let a = Cache::default();
        let now = Instant::now();
        for pid in 0..(CACHE_MAX as u32 * 2) {
            a.lookup(pid, 0, now, || Process::Unknown("x"));
        }
        assert!(a.0.lock().unwrap().len() <= CACHE_MAX);
    }

    #[test]
    fn ipv6_is_unknown() {
        let p: SocketAddr = "[::1]:1".parse().unwrap();
        assert_eq!(client_process(p, p), Process::Unknown("ipv6"));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_is_unsupported() {
        let p: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(client_process(p, p), Process::Unknown("unsupported"));
    }

    #[test]
    fn serializes_for_events() {
        let known = Process::Known {
            pid: 4,
            start: 9,
            image: r"C:\x.exe".into(),
            user: r"D\u".into(),
        };
        assert_eq!(
            serde_json::to_string(&known).unwrap(),
            r#"{"known":{"pid":4,"start":9,"image":"C:\\x.exe","user":"D\\u"}}"#
        );
        assert_eq!(
            serde_json::to_string(&Process::Unknown("ipv6")).unwrap(),
            r#"{"unknown":"ipv6"}"#
        );
    }

    /// Connects to ourselves and checks the lookup finds this process.
    #[cfg(windows)]
    #[test]
    fn attributes_own_loopback_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (sock, peer) = listener.accept().unwrap();
        let p = client_process(peer, sock.local_addr().unwrap());
        let Process::Known {
            pid, image, user, ..
        } = p
        else {
            panic!("expected a known process, got {p:?}");
        };
        assert_eq!(pid, std::process::id());
        let exe = std::env::current_exe().unwrap();
        assert!(
            image.eq_ignore_ascii_case(&exe.to_string_lossy()),
            "{image} vs {exe:?}"
        );
        assert!(user.contains('\\'), "user {user:?}");
    }
}
