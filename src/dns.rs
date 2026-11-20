//! Remote IP → hostname for the connection monitor (#57).
//!
//! The pure part is a bounded cache with TTL expiry. Each IP keeps the few names it was most recently resolved for;
//! a lookup prefers the name the same process asked for and otherwise takes the most recent one. On Windows the cache
//! is filled from the DNS Client service's cache, which a normal user can read.
//!
//! ponytail: the Windows source is `DnsGetCacheDataTable`, which is undocumented, gives no process ID and misses
//! lookups done outside the DNS Client (DoH inside a browser, `hosts` overrides read by apps themselves). The ETW
//! provider `Microsoft-Windows-DNS-Client` would add the PID, but a real-time ETW session needs admin rights or
//! Performance Log Users membership. Revisit with the Phase 2 service (#59), which runs elevated anyway.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Names kept per IP. Shared CDN addresses serve many names; the most recent few are enough to label a connection.
const NAMES_PER_IP: usize = 4;

/// Answers with a TTL of zero or a missing TTL still label connections opened right after the lookup.
const MIN_TTL: Duration = Duration::from_secs(60);

/// A name keeps labelling connections this long past its TTL: apps reuse a connection long after the record
/// expired, and the address rarely changes owner that fast.
const GRACE: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    name: String,
    /// The process that asked, when the source knows it.
    pid: Option<u32>,
    seen: Instant,
    expires: Instant,
}

/// IP → recent hostnames, bounded by `capacity` entries in total.
#[derive(Debug)]
pub struct Cache {
    capacity: usize,
    len: usize,
    map: HashMap<IpAddr, Vec<Entry>>,
}

impl Cache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            len: 0,
            map: HashMap::new(),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len
    }

    /// Records that `name` resolved to `ip`, asked by `pid` if known.
    pub fn insert(
        &mut self,
        ip: IpAddr,
        name: &str,
        pid: Option<u32>,
        ttl: Duration,
        now: Instant,
    ) {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            return;
        }
        let expires = now + ttl.max(MIN_TTL) + GRACE;
        let entries = self.map.entry(ip).or_default();
        if let Some(e) = entries.iter_mut().find(|e| e.name == name && e.pid == pid) {
            e.seen = now;
            e.expires = e.expires.max(expires);
            return;
        }
        if entries.len() >= NAMES_PER_IP {
            // Drop this IP's least recently seen name.
            let oldest = (0..entries.len())
                .min_by_key(|&i| entries[i].seen)
                .unwrap_or(0);
            entries.swap_remove(oldest);
            self.len -= 1;
        }
        entries.push(Entry {
            name,
            pid,
            seen: now,
            expires,
        });
        self.len += 1;
        if self.len > self.capacity {
            self.evict(now);
        }
    }

    /// The hostname for a connection from `pid` to `ip`: the same process's most recent answer, else anyone's.
    pub fn lookup(&self, ip: IpAddr, pid: u32, now: Instant) -> Option<&str> {
        let live = self.map.get(&ip)?.iter().filter(|e| e.expires > now);
        let (own, any) = live.fold((None::<&Entry>, None::<&Entry>), |(own, any), e| {
            let newer = |best: Option<&Entry>| best.is_none_or(|b| e.seen >= b.seen);
            (
                if e.pid == Some(pid) && newer(own) {
                    Some(e)
                } else {
                    own
                },
                if newer(any) { Some(e) } else { any },
            )
        });
        own.or(any).map(|e| e.name.as_str())
    }

    /// Removes expired entries; if that is not enough, the least recently seen ones.
    fn evict(&mut self, now: Instant) {
        self.map.retain(|_, entries| {
            entries.retain(|e| e.expires > now);
            !entries.is_empty()
        });
        self.len = self.map.values().map(Vec::len).sum();
        if self.len <= self.capacity {
            return;
        }
        let mut seen: Vec<Instant> = self.map.values().flatten().map(|e| e.seen).collect();
        seen.sort_unstable();
        // Keep the newest 3/4 of capacity so eviction does not run on every insert.
        let drop = self.len - self.capacity * 3 / 4;
        let cutoff = seen[drop.min(seen.len()) - 1];
        self.map.retain(|_, entries| {
            entries.retain(|e| e.seen > cutoff);
            !entries.is_empty()
        });
        self.len = self.map.values().map(Vec::len).sum();
    }
}

/// One answer read from the system: `name` resolved to `ip` with `ttl` left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub name: String,
    pub ip: IpAddr,
    pub ttl: Duration,
}

/// Every A and AAAA answer currently in the Windows DNS Client cache.
#[cfg(windows)]
pub fn system_answers() -> Result<Vec<Answer>, String> {
    sys::answers()
}

#[cfg(not(windows))]
pub fn system_answers() -> Result<Vec<Answer>, String> {
    Err("[monitor] the DNS cache is read only on Windows".into())
}

#[cfg(windows)]
mod sys {
    use super::Answer;
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr::null_mut;
    use std::time::Duration;
    use windows_sys::Win32::NetworkManagement::Dns::{
        DNS_QUERY_NO_WIRE_QUERY, DNS_RECORDW, DNS_TYPE_A, DNS_TYPE_AAAA, DnsFree, DnsFreeFlat,
        DnsFreeRecordList, DnsQuery_W,
    };
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };

    /// `DNS_CACHE_ENTRY` as dnsapi.dll returns it from `DnsGetCacheDataTable` (undocumented, stable since XP).
    #[repr(C)]
    struct CacheEntry {
        next: *mut CacheEntry,
        name: *mut u16,
        kind: u16,
        data_length: u16,
        flags: u32,
    }

    type GetCacheDataTable = unsafe extern "system" fn(*mut *mut CacheEntry) -> i32;

    /// Resolved once: the function pointer, or None when this Windows has no such export.
    fn get_cache_data_table() -> Option<GetCacheDataTable> {
        static FN: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
        let addr = *FN.get_or_init(|| {
            let dll: Vec<u16> = "dnsapi.dll".encode_utf16().chain([0]).collect();
            let module =
                unsafe { LoadLibraryExW(dll.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
            if module.is_null() {
                return None;
            }
            unsafe { GetProcAddress(module, c"DnsGetCacheDataTable".as_ptr().cast()) }
                .map(|f| f as usize)
        });
        // SAFETY: the address came from GetProcAddress for this export, whose signature is the one above.
        addr.map(|a| unsafe { std::mem::transmute::<usize, GetCacheDataTable>(a) })
    }

    pub fn answers() -> Result<Vec<Answer>, String> {
        let table =
            get_cache_data_table().ok_or("[monitor] dnsapi.dll has no DnsGetCacheDataTable")?;
        let mut head: *mut CacheEntry = null_mut();
        if unsafe { table(&mut head) } == 0 {
            // An empty cache also reports failure.
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        let mut entry = head;
        while !entry.is_null() {
            let e = unsafe { &*entry };
            if (e.kind == DNS_TYPE_A || e.kind == DNS_TYPE_AAAA) && !e.name.is_null() {
                names.push((wide_to_vec(e.name), e.kind));
            }
            let next = e.next;
            unsafe {
                if !e.name.is_null() {
                    DnsFree(e.name as *const c_void, DnsFreeFlat);
                }
                DnsFree(entry as *const c_void, DnsFreeFlat);
            }
            entry = next;
        }
        let mut out = Vec::new();
        for (name, kind) in names {
            query_cache(&name, kind, &mut out);
        }
        Ok(out)
    }

    /// Copies a NUL-terminated UTF-16 string, NUL included.
    fn wide_to_vec(p: *const u16) -> Vec<u16> {
        let mut len = 0;
        // Bounded: DNS names are at most 255 characters.
        while len < 1024 && unsafe { *p.add(len) } != 0 {
            len += 1;
        }
        let mut v = unsafe { std::slice::from_raw_parts(p, len) }.to_vec();
        v.push(0);
        v
    }

    /// Looks `name` up in the cache only (never on the wire) and appends its addresses.
    fn query_cache(name: &[u16], kind: u16, out: &mut Vec<Answer>) {
        let mut records = null_mut();
        let rc = unsafe {
            DnsQuery_W(
                name.as_ptr(),
                kind,
                DNS_QUERY_NO_WIRE_QUERY,
                null_mut(),
                &mut records,
                null_mut(),
            )
        };
        if rc != 0 || records.is_null() {
            return;
        }
        let text = String::from_utf16_lossy(&name[..name.len() - 1]);
        let mut r = records.cast::<DNS_RECORDW>();
        while !r.is_null() {
            let rec = unsafe { &*r };
            let ip = match rec.wType {
                DNS_TYPE_A => Some(IpAddr::V4(Ipv4Addr::from(
                    unsafe { rec.Data.A.IpAddress }.to_ne_bytes(),
                ))),
                DNS_TYPE_AAAA => Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                    rec.Data.AAAA.Ip6Address.IP6Byte
                }))),
                // CNAME links of the chain; the addresses follow.
                _ => None,
            };
            if let Some(ip) = ip {
                out.push(Answer {
                    name: text.clone(),
                    ip,
                    ttl: Duration::from_secs(rec.dwTtl.into()),
                });
            }
            r = rec.pNext;
        }
        unsafe { DnsFree(records as *const c_void, DnsFreeRecordList) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const TTL: Duration = Duration::from_secs(300);

    #[test]
    fn lookup_finds_the_name_and_normalizes_it() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        c.insert(ip("93.184.215.14"), "Example.COM.", None, TTL, now);
        assert_eq!(c.lookup(ip("93.184.215.14"), 7, now), Some("example.com"));
        assert_eq!(c.lookup(ip("1.1.1.1"), 7, now), None);
    }

    #[test]
    fn entries_expire_after_ttl_and_grace() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        c.insert(ip("10.0.0.1"), "short.example", None, Duration::ZERO, now);
        let edge = now + MIN_TTL + GRACE;
        assert_eq!(
            c.lookup(ip("10.0.0.1"), 1, edge - Duration::from_secs(1)),
            Some("short.example")
        );
        assert_eq!(c.lookup(ip("10.0.0.1"), 1, edge), None);
    }

    #[test]
    fn the_same_process_answer_wins_over_a_newer_one() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        let cdn = ip("151.101.1.1");
        c.insert(cdn, "mine.example", Some(42), TTL, now);
        c.insert(
            cdn,
            "other.example",
            Some(7),
            TTL,
            now + Duration::from_secs(1),
        );
        assert_eq!(
            c.lookup(cdn, 42, now + Duration::from_secs(2)),
            Some("mine.example")
        );
        // A third process gets the most recent answer.
        assert_eq!(
            c.lookup(cdn, 99, now + Duration::from_secs(2)),
            Some("other.example")
        );
    }

    #[test]
    fn most_recent_answer_wins_without_a_pid() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        let cdn = ip("151.101.1.1");
        c.insert(cdn, "a.example", None, TTL, now);
        c.insert(cdn, "b.example", None, TTL, now + Duration::from_secs(1));
        assert_eq!(
            c.lookup(cdn, 1, now + Duration::from_secs(1)),
            Some("b.example")
        );
        // Seeing a.example again makes it the most recent.
        c.insert(cdn, "a.example", None, TTL, now + Duration::from_secs(2));
        assert_eq!(
            c.lookup(cdn, 1, now + Duration::from_secs(2)),
            Some("a.example")
        );
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn names_per_ip_are_bounded() {
        let now = Instant::now();
        let mut c = Cache::new(100);
        let cdn = ip("151.101.1.1");
        for i in 0..10u64 {
            c.insert(
                cdn,
                &format!("n{i}.example"),
                None,
                TTL,
                now + Duration::from_secs(i),
            );
        }
        assert_eq!(c.len(), NAMES_PER_IP);
        assert_eq!(
            c.lookup(cdn, 1, now + Duration::from_secs(10)),
            Some("n9.example")
        );
    }

    #[test]
    fn total_size_is_bounded_and_keeps_the_newest() {
        let now = Instant::now();
        let mut c = Cache::new(8);
        for i in 0..50u8 {
            c.insert(
                IpAddr::from([10, 0, 0, i]),
                &format!("h{i}.example"),
                None,
                TTL,
                now + Duration::from_secs(u64::from(i)),
            );
            assert!(c.len() <= 8, "len {} after {i}", c.len());
        }
        let later = now + Duration::from_secs(60);
        assert_eq!(
            c.lookup(IpAddr::from([10, 0, 0, 49]), 1, later),
            Some("h49.example")
        );
        assert_eq!(c.lookup(IpAddr::from([10, 0, 0, 0]), 1, later), None);
    }

    #[test]
    fn empty_names_are_ignored() {
        let mut c = Cache::new(4);
        c.insert(ip("10.0.0.1"), ".", None, TTL, Instant::now());
        assert_eq!(c.len(), 0);
    }

    /// The real DNS Client cache holds a name right after the system resolver looked it up.
    #[cfg(windows)]
    #[test]
    fn system_cache_contains_a_fresh_lookup() {
        use std::net::ToSocketAddrs;
        let Ok(addrs) = ("example.com", 443).to_socket_addrs() else {
            eprintln!("no DNS on this machine; skipped");
            return;
        };
        let addrs: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
        let answers = system_answers().unwrap();
        assert!(
            answers
                .iter()
                .any(|a| a.name.eq_ignore_ascii_case("example.com") && addrs.contains(&a.ip)),
            "example.com {addrs:?} not in {} cached answers",
            answers.len()
        );
    }
}
