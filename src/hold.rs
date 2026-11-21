//! Hold-and-ask (#60, Phase 3 of #56): the pure core, tested on every OS.
//!
//! A new outbound TCP connection starts with a SYN. The firewall service, with WinDivert, takes that SYN off the wire
//! and holds it while the user decides. On allow, the original SYN is sent on and the connection completes as if
//! nothing happened. On deny or timeout, a RST goes back to the app, whose `connect()` then fails at once with
//! "connection refused". Retransmitted SYNs of a held connection are dropped while it waits.
//!
//! This module parses SYNs, builds the RSTs (with checksums) and keeps the bounded, expiring queue of held
//! connections. It never touches the network itself.
// ponytail: TCP only. UDP has no connection setup to hold, so `ask` UDP flows keep Phase 2's block-then-ask.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

const TCP: u8 = 6;
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// The opening packet of an outbound TCP connection, from the app at `local` to `remote`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Syn {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// The SYN's sequence number; the RST acknowledges it.
    pub seq: u32,
}

impl Syn {
    /// Identifies the connection: retransmissions of the same SYN have the same key.
    pub fn key(&self) -> (SocketAddr, SocketAddr) {
        (self.local, self.remote)
    }
}

/// Reads an outbound IPv4 or IPv6 packet. `Some` only for a TCP SYN without ACK, i.e. a connection being opened.
/// IPv6 extension headers and IPv4 fragments are not parsed: such packets are not SYNs worth holding.
pub fn parse_syn(packet: &[u8]) -> Option<Syn> {
    let version = packet.first()? >> 4;
    let (src, dst, tcp) = match version {
        4 => {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            let frag = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
            if ihl < 20 || *packet.get(9)? != TCP || frag & 0x3fff != 0 {
                return None;
            }
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?);
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(16..20)?).ok()?);
            (IpAddr::V4(src), IpAddr::V4(dst), packet.get(ihl..)?)
        }
        6 => {
            if *packet.get(6)? != TCP {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
            (IpAddr::V6(src), IpAddr::V6(dst), packet.get(40..)?)
        }
        _ => return None,
    };
    if tcp.len() < 20 {
        return None;
    }
    let flags = tcp[13];
    if flags & (SYN | ACK | RST | FIN) != SYN {
        return None;
    }
    let port = |at: usize| u16::from_be_bytes([tcp[at], tcp[at + 1]]);
    Some(Syn {
        local: SocketAddr::new(src, port(0)),
        remote: SocketAddr::new(dst, port(2)),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
    })
}

/// The inbound RST|ACK that refuses `syn`'s connection, as the remote host would send it, with valid checksums.
pub fn rst_for(syn: &Syn) -> Vec<u8> {
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&syn.remote.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&syn.local.port().to_be_bytes());
    // seq 0; ack = the SYN's sequence + 1, as RFC 9293 requires for a RST answering a SYN.
    tcp[8..12].copy_from_slice(&syn.seq.wrapping_add(1).to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = RST | ACK;
    match (syn.remote.ip(), syn.local.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut ip = [0u8; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&40u16.to_be_bytes());
            ip[6] = 0x40; // don't fragment
            ip[8] = 64;
            ip[9] = TCP;
            ip[12..16].copy_from_slice(&src.octets());
            ip[16..20].copy_from_slice(&dst.octets());
            let sum = checksum(&[&ip]);
            ip[10..12].copy_from_slice(&sum.to_be_bytes());
            let pseudo = [&src.octets()[..], &dst.octets()[..], &[0, TCP, 0, 20]].concat();
            let sum = checksum(&[&pseudo, &tcp]);
            tcp[16..18].copy_from_slice(&sum.to_be_bytes());
            [&ip[..], &tcp[..]].concat()
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut ip = [0u8; 40];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&20u16.to_be_bytes());
            ip[6] = TCP;
            ip[7] = 64;
            ip[8..24].copy_from_slice(&src.octets());
            ip[24..40].copy_from_slice(&dst.octets());
            let pseudo = [
                &src.octets()[..],
                &dst.octets()[..],
                &[0, 0, 0, 20, 0, 0, 0, TCP],
            ]
            .concat();
            let sum = checksum(&[&pseudo, &tcp]);
            tcp[16..18].copy_from_slice(&sum.to_be_bytes());
            [&ip[..], &tcp[..]].concat()
        }
        // A SYN's two ends are always the same family; parse_syn never builds anything else.
        _ => unreachable!("mixed address families"),
    }
}

/// The Internet checksum (RFC 1071) over the concatenation of `parts`, each of even length but the last.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let (pairs, rest) = part.as_chunks::<2>();
        for pair in pairs {
            sum += u32::from(u16::from_be_bytes(*pair));
        }
        if let [last] = rest {
            sum += u32::from(*last) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One held connection: its SYN, the packet and address to send it on with, and since when it waits.
#[derive(Debug)]
pub struct Held<A> {
    pub syn: Syn,
    pub packet: Vec<u8>,
    pub address: A,
    pub since: Instant,
}

/// What became of an offered SYN.
#[derive(Debug, PartialEq, Eq)]
pub enum Offer {
    /// Now held; the caller asks the user.
    Held,
    /// A retransmission of a connection already held: drop it, the held one answers for both.
    Retransmit,
    /// The queue is full: refuse the connection (fail closed).
    Full,
}

/// How long a connection is held when nobody answers: under Windows' 21 s connect timeout, so the app still gets a
/// clean "refused" rather than a timeout of its own.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// The held connections, bounded and expiring. `A` is the platform's packet address (WinDivert's).
pub struct Queue<A> {
    max: usize,
    timeout: Duration,
    held: Vec<Held<A>>,
}

impl<A> Queue<A> {
    pub fn new(max: usize, timeout: Duration) -> Self {
        Self {
            max: max.max(1),
            timeout,
            held: Vec::new(),
        }
    }

    pub fn offer(&mut self, syn: Syn, packet: Vec<u8>, address: A, now: Instant) -> Offer {
        if self.held.iter().any(|h| h.syn.key() == syn.key()) {
            return Offer::Retransmit;
        }
        if self.held.len() >= self.max {
            return Offer::Full;
        }
        self.held.push(Held {
            syn,
            packet,
            address,
            since: now,
        });
        Offer::Held
    }

    /// Takes out the connections that waited `timeout`: the caller refuses them.
    pub fn expired(&mut self, now: Instant) -> Vec<Held<A>> {
        let timeout = self.timeout;
        self.take(|h| now.duration_since(h.since) >= timeout)
    }

    /// Takes out the held connections `pick` selects, e.g. those a new rule decides.
    pub fn take(&mut self, mut pick: impl FnMut(&Held<A>) -> bool) -> Vec<Held<A>> {
        let (taken, kept) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|h| pick(h));
        self.held = kept;
        taken
    }

    #[cfg(test)]
    /// When the next held connection times out, if any: the caller wakes up then.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.held.iter().map(|h| h.since + self.timeout).min()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An outbound IPv4 TCP packet from `src` to `dst` with `flags`, checksums left zero.
    fn v4_packet(src: &str, dst: &str, sport: u16, dport: u16, seq: u32, flags: u8) -> Vec<u8> {
        let (s, d): (Ipv4Addr, Ipv4Addr) = (src.parse().unwrap(), dst.parse().unwrap());
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[6] = 0x40;
        p[8] = 128;
        p[9] = TCP;
        p[12..16].copy_from_slice(&s.octets());
        p[16..20].copy_from_slice(&d.octets());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = flags;
        p
    }

    fn v6_packet(src: &str, dst: &str, sport: u16, dport: u16, seq: u32, flags: u8) -> Vec<u8> {
        let (s, d): (Ipv6Addr, Ipv6Addr) = (src.parse().unwrap(), dst.parse().unwrap());
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = TCP;
        p[7] = 64;
        p[8..24].copy_from_slice(&s.octets());
        p[24..40].copy_from_slice(&d.octets());
        p[40..42].copy_from_slice(&sport.to_be_bytes());
        p[42..44].copy_from_slice(&dport.to_be_bytes());
        p[44..48].copy_from_slice(&seq.to_be_bytes());
        p[52] = 5 << 4;
        p[53] = flags;
        p
    }

    #[test]
    fn only_opening_syns_are_parsed() {
        let syn = parse_syn(&v4_packet("192.0.2.10", "198.51.100.7", 50000, 443, 7, SYN)).unwrap();
        assert_eq!(syn.local, "192.0.2.10:50000".parse().unwrap());
        assert_eq!(syn.remote, "198.51.100.7:443".parse().unwrap());
        assert_eq!(syn.seq, 7);
        let v6 = parse_syn(&v6_packet("2001:db8::1", "2001:db8::2", 50001, 80, 9, SYN)).unwrap();
        assert_eq!(v6.remote, "[2001:db8::2]:80".parse().unwrap());

        for flags in [SYN | ACK, ACK, RST, SYN | RST, FIN | SYN] {
            assert!(
                parse_syn(&v4_packet("192.0.2.10", "198.51.100.7", 1, 2, 0, flags)).is_none(),
                "{flags:#x}"
            );
        }
        let mut udp = v4_packet("192.0.2.10", "198.51.100.7", 1, 2, 0, SYN);
        udp[9] = 17;
        assert!(parse_syn(&udp).is_none());
        let mut fragment = v4_packet("192.0.2.10", "198.51.100.7", 1, 2, 0, SYN);
        fragment[6] = 0x20; // more fragments
        assert!(parse_syn(&fragment).is_none());
        assert!(parse_syn(&v4_packet("192.0.2.10", "198.51.100.7", 1, 2, 0, SYN)[..30]).is_none());
        assert!(parse_syn(&[]).is_none());
        assert!(parse_syn(&[0x45]).is_none());
    }

    #[test]
    fn rsts_answer_the_syn_with_valid_checksums() {
        for packet in [
            v4_packet("192.0.2.10", "198.51.100.7", 50000, 443, u32::MAX, SYN),
            v6_packet("2001:db8::1", "2001:db8::2", 50001, 80, 41, SYN),
        ] {
            let syn = parse_syn(&packet).unwrap();
            let rst = rst_for(&syn);
            let v4 = syn.local.is_ipv4();
            let (ip, tcp) = rst.split_at(if v4 { 20 } else { 40 });
            // Back from the remote end to the app.
            assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]), syn.remote.port());
            assert_eq!(u16::from_be_bytes([tcp[2], tcp[3]]), syn.local.port());
            assert_eq!(
                u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
                syn.seq.wrapping_add(1)
            );
            assert_eq!(tcp[13], RST | ACK);
            // A correct checksum makes the sum over the covered bytes, checksum included, come out as zero.
            let pseudo = if v4 {
                assert_eq!(checksum(&[ip]), 0, "IPv4 header checksum");
                [&ip[12..16], &ip[16..20], &[0, TCP, 0, 20][..]].concat()
            } else {
                [&ip[8..24], &ip[24..40], &[0, 0, 0, 20, 0, 0, 0, TCP][..]].concat()
            };
            assert_eq!(checksum(&[&pseudo, tcp]), 0, "TCP checksum");
            // And it reads back as the reverse connection.
            assert!(parse_syn(&rst).is_none(), "a RST is never taken for a SYN");
        }
    }

    #[test]
    fn checksum_matches_rfc_1071_example() {
        // RFC 1071, section 3: the sum of these words is 0xddf2 with carries folded, so the checksum is !0xddf2.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&[&data]), !0xddf2);
        // Odd lengths pad with a zero byte.
        assert_eq!(checksum(&[&[0x12]]), !0x1200);
    }

    #[test]
    fn the_queue_holds_once_bounds_and_expires() {
        let start = Instant::now();
        let syn =
            |port| parse_syn(&v4_packet("192.0.2.10", "198.51.100.7", port, 443, 1, SYN)).unwrap();
        let mut q: Queue<u8> = Queue::new(2, Duration::from_secs(20));
        assert_eq!(q.offer(syn(1), vec![1], 0, start), Offer::Held);
        assert_eq!(
            q.offer(syn(1), vec![1], 0, start + Duration::from_secs(3)),
            Offer::Retransmit
        );
        assert_eq!(
            q.offer(syn(2), vec![2], 0, start + Duration::from_secs(5)),
            Offer::Held
        );
        assert_eq!(q.offer(syn(3), vec![3], 0, start), Offer::Full);
        assert_eq!(q.len(), 2);
        assert_eq!(q.next_deadline(), Some(start + Duration::from_secs(20)));

        assert!(q.expired(start + Duration::from_secs(19)).is_empty());
        let gone = q.expired(start + Duration::from_secs(20));
        assert_eq!(
            gone.iter().map(|h| h.syn.local.port()).collect::<Vec<_>>(),
            [1]
        );
        assert_eq!(q.next_deadline(), Some(start + Duration::from_secs(25)));

        let taken = q.take(|h| h.syn.local.port() == 2);
        assert_eq!(taken[0].packet, [2]);
        assert!(q.is_empty() && q.next_deadline().is_none());
        // Room again once the queue drained.
        assert_eq!(q.offer(syn(3), vec![3], 0, start), Offer::Held);
    }
}
