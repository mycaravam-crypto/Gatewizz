//! Connection rules for the firewall (#59, Phase 2 of #56): the pure core, tested on every OS.
//!
//! A rule names who connects (program), where (host name or IP prefix, port) and how (protocol), and allows or
//! blocks it. [`decide`] picks the rule for one connection; [`plan`] turns the rules into the IP-level filters the
//! Windows Filtering Platform enforces; [`Coalescer`] keeps a burst of blocked attempts to one prompt.
//!
//! Precedence: the most specific matching rule wins; between equally specific rules `block` and `ask` beat `allow`;
//! otherwise the first one in the list wins. "Most specific" compares, in order, how many of program,
//! address, port and protocol a rule pins down, then how narrow its address is. So "smartwizz.exe may reach
//! 127.0.0.1:8899" (program, address, port) beats "smartwizz.exe is blocked" (program only): that pair is the
//! proxy-enforcement preset.
//!
//! Gatewizz itself is always allowed ([`SELF_RULE`]); no rule can block the update and configuration path.
//!
//! `gatewizz firewall apply` uses [`plan`] to install the filters (see `wfp.rs`). Connections blocked by an `ask`
//! rule or an `ask` default become prompts in the tray app (see `prompt.rs`); [`Coalescer`] folds repeats.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::tls::host_matches;

/// The id of the built-in rule that always allows Gatewizz's own process.
pub const SELF_RULE: &str = "gatewizz-self";

/// What happens to a connection no rule matches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    #[default]
    Allow,
    /// Block, and ask the user whether to add a rule. Without a window attached this behaves as `block`.
    Ask,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Block,
    /// Block, and ask the user (through the tray app's prompt) whether to add a rule. Without the tray app this is
    /// `block`.
    Ask,
}

impl RuleAction {
    /// Whether WFP blocks the connection: `ask` blocks until a rule from the prompt allows it.
    pub fn blocks(self) -> bool {
        self != RuleAction::Allow
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Any,
    Tcp,
    Udp,
}

/// An IP prefix: `10.0.0.0/8`, `2001:db8::/32`, or a single address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Net {
    pub addr: IpAddr,
    pub len: u8,
}

impl Net {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (addr, len) = match text.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (text, None),
        };
        let addr: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("{text:?} is not an IP address or prefix"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            None => max,
            Some(len) => len
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|&l| l <= max)
                .ok_or_else(|| format!("{text:?}: prefix length must be 0..={max}"))?,
        };
        Ok(Self { addr, len })
    }

    pub fn single(addr: IpAddr) -> Self {
        Self {
            addr,
            len: if addr.is_ipv4() { 32 } else { 128 },
        }
    }

    #[cfg_attr(
        not(any(test, windows)),
        expect(dead_code, reason = "the hold service runs on Windows only")
    )]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let bits = |a: IpAddr| match a {
            IpAddr::V4(v4) => u128::from(u32::from(v4)) << 96,
            IpAddr::V6(v6) => u128::from(v6),
        };
        if self.addr.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let mask = if self.len == 0 {
            0
        } else {
            // IPv4 sits in the top 32 bits, so its prefix length applies as is.
            u128::MAX << (128 - u32::from(self.len))
        };
        bits(self.addr) & mask == bits(ip) & mask
    }

    /// The prefix length on a 128-bit scale, so IPv4 and IPv6 prefixes compare by narrowness.
    fn effective_len(&self) -> u8 {
        if self.addr.is_ipv4() {
            self.len + 96
        } else {
            self.len
        }
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let max = if self.addr.is_ipv4() { 32 } else { 128 };
        if self.len == max {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.len)
        }
    }
}

impl Serialize for Net {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Net {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Net::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// One connection rule. Every key except `id` and `action` is optional; an omitted key matches anything.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    /// Programs: a file name (`smartwizz.exe`) or a full path (`C:\Tools\smartwizz.exe`), case-insensitive. WFP
    /// matches full paths, so a file name is enforced for the paths it resolves to (see [`plan`]). An unknown
    /// process matches no rule with programs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process: Vec<String>,
    /// Host names: exact or `*.suffix`. Enforced through the IPs these names were seen to resolve to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
    /// IP addresses or prefixes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<Net>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    #[serde(default)]
    pub protocol: Protocol,
    pub action: RuleAction,
    /// When the rule stops applying; set by "Allow for N minutes" and "Allow once". Never set from the file yet.
    #[serde(skip)]
    pub expires: Option<SystemTime>,
}

impl Rule {
    fn active(&self, now: SystemTime) -> bool {
        self.expires.is_none_or(|at| now < at)
    }

    /// (constrained dimensions, address narrowness): bigger is more specific.
    fn specificity(&self) -> (u8, u16) {
        let addressed = !self.host.is_empty() || !self.ip.is_empty();
        let dims = [
            !self.process.is_empty(),
            addressed,
            !self.port.is_empty(),
            self.protocol != Protocol::Any,
        ]
        .iter()
        .filter(|&&b| b)
        .count() as u8;
        // The widest address the rule allows decides how narrow it is, on a 128-bit prefix scale (IPv4 /n counts
        // as n + 96). An exact host counts as one address (128); a wildcard host as 124: wider than one name, but
        // narrower than any IP prefix wider than a /28, since it names one organization's hosts.
        let hosts = self
            .host
            .iter()
            .map(|h| if h.starts_with("*.") { 124 } else { 128 });
        let ips = self.ip.iter().map(|n| u16::from(n.effective_len()));
        let narrow = hosts.chain(ips).min().unwrap_or(0);
        (dims, narrow)
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "for the approval prompt, next in #59")
    )]
    fn matches(&self, c: &Connection<'_>) -> bool {
        let program_ok = self.process.is_empty()
            || c.program.is_some_and(|p| {
                self.process
                    .iter()
                    .any(|q| file_name(q).eq_ignore_ascii_case(file_name(p)))
            });
        let address_ok = (self.host.is_empty() && self.ip.is_empty())
            || self
                .host
                .iter()
                .any(|pattern| c.host.is_some_and(|h| host_matches(pattern, h)))
            || self.ip.iter().any(|net| net.contains(c.ip));
        let port_ok = self.port.is_empty() || self.port.contains(&c.port);
        let protocol_ok = self.protocol == Protocol::Any || self.protocol == c.protocol;
        program_ok && address_ok && port_ok && protocol_ok
    }
}

/// The file name of a program entry: `smartwizz.exe` for both `smartwizz.exe` and `C:\Tools\smartwizz.exe`.
pub fn file_name(program: &str) -> &str {
    program.rsplit(['\\', '/']).next().unwrap_or(program)
}

/// Whether a program entry is a full Windows path (`C:\...` or `\\server\...`) rather than a file name.
pub fn is_full_path(program: &str) -> bool {
    let b = program.as_bytes();
    (b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || program.starts_with("\\\\")
}

/// Checks a rule list read from the config. `index` names the entry in errors, as `rules::validate` does.
pub fn validate(rules: &[Rule]) -> Result<(), String> {
    for (i, rule) in rules.iter().enumerate() {
        let at = format!("connection_rules[{i}]");
        if rule.id.trim().is_empty() || rule.id == SELF_RULE {
            return Err(format!(
                "{at}.id: must be non-empty and not \"{SELF_RULE}\""
            ));
        }
        if rules[..i].iter().any(|r| r.id == rule.id) {
            return Err(format!("{at}.id: duplicate id \"{}\"", rule.id));
        }
        if rule.port.contains(&0) {
            return Err(format!("{at}.port: 0 is not a port"));
        }
        if let Some(bad) = rule.host.iter().find(|h| {
            let name = h.strip_prefix("*.").unwrap_or(h);
            name.is_empty() || name.contains(['*', '/', ':', ' '])
        }) {
            return Err(format!("{at}.host: {bad:?} is not a host name or *.suffix"));
        }
        if let Some(bad) = rule.process.iter().find(|p| {
            p.is_empty() || file_name(p).is_empty() || (p.contains(['\\', '/']) && !is_full_path(p))
        }) {
            return Err(format!(
                "{at}.process: {bad:?} must be a file name such as \"smartwizz.exe\" or a full path"
            ));
        }
    }
    Ok(())
}

/// One connection attempt, as the service sees it.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "for the approval prompt, next in #59")
)]
#[derive(Clone, Copy, Debug)]
pub struct Connection<'a> {
    /// The program's file name, if known.
    pub program: Option<&'a str>,
    pub ip: IpAddr,
    /// The host name the IP was resolved from, if known.
    pub host: Option<&'a str>,
    pub port: u16,
    pub protocol: Protocol,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "for the approval prompt, next in #59")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
    /// Block now and ask whether to add a rule.
    Ask,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "for the approval prompt, next in #59")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// The deciding rule's id, [`SELF_RULE`], or `default`.
    pub rule: String,
}

/// The rule for one connection. `own_program` is Gatewizz's file name, always allowed. `attached` says whether an
/// approval window can ask: without one, `ask` blocks (fail closed).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "for the approval prompt, next in #59")
)]
pub fn decide(
    c: &Connection<'_>,
    rules: &[Rule],
    default: DefaultAction,
    own_program: &str,
    attached: bool,
    now: SystemTime,
) -> Decision {
    if c.program
        .is_some_and(|p| p.eq_ignore_ascii_case(own_program))
    {
        return Decision {
            verdict: Verdict::Allow,
            rule: SELF_RULE.into(),
        };
    }
    let best = rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r.active(now) && r.matches(c))
        .max_by(|(i, a), (j, b)| {
            a.specificity()
                .cmp(&b.specificity())
                .then(a.action.blocks().cmp(&b.action.blocks()))
                // Earlier rules win ties: compare indexes reversed.
                .then(j.cmp(i))
        });
    match best {
        Some((_, rule)) => Decision {
            verdict: match rule.action {
                RuleAction::Allow => Verdict::Allow,
                RuleAction::Block => Verdict::Block,
                RuleAction::Ask if attached => Verdict::Ask,
                RuleAction::Ask => Verdict::Block,
            },
            rule: rule.id.clone(),
        },
        None => Decision {
            verdict: match default {
                DefaultAction::Allow => Verdict::Allow,
                DefaultAction::Block => Verdict::Block,
                DefaultAction::Ask if attached => Verdict::Ask,
                DefaultAction::Ask => Verdict::Block,
            },
            rule: "default".into(),
        },
    }
}

/// One IP-level filter for WFP's ALE connect layer. `None` fields match anything.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Filter {
    pub rule: String,
    pub program: Option<String>,
    pub remote: Option<Net>,
    pub port: Option<u16>,
    pub protocol: Protocol,
    pub action: RuleAction,
    /// Higher weight is evaluated first, which gives WFP the same precedence as [`decide`].
    pub weight: u64,
}

/// Turns the active rules into filters. WFP matches programs by full path and addresses by IP, so:
/// - a program given as a file name becomes one filter per path `programs` resolves it to; a full path is used as is.
///   A file name that resolves to nothing yields no filter for that rule, which [`unresolved`] reports.
/// - a host becomes one filter per IP `resolved` reports for it (from the DNS cache); a host with no known IP yet
///   yields no filter, and the default filter decides until the name is seen.
///
/// Gatewizz's own executables (`own_paths`: the service's copy and the user's) get the top-weight allow; a
/// `block`/`ask` default gets a bottom-weight block.
pub fn plan(
    rules: &[Rule],
    default: DefaultAction,
    own_paths: &[String],
    now: SystemTime,
    resolved: impl Fn(&str) -> Vec<IpAddr>,
    programs: impl Fn(&str) -> Vec<String>,
) -> Vec<Filter> {
    let mut out: Vec<Filter> = Vec::new();
    for path in own_paths {
        if !out.iter().any(|f| {
            f.program
                .as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case(path))
        }) {
            out.push(Filter {
                rule: SELF_RULE.into(),
                program: Some(path.clone()),
                remote: None,
                port: None,
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                weight: u64::MAX,
            });
        }
    }
    let count = rules.len() as u64;
    for (i, rule) in rules.iter().enumerate().filter(|(_, r)| r.active(now)) {
        let (dims, narrow) = rule.specificity();
        // Specificity first, then block or ask over allow, then list order; the self rule and the default stay outside.
        // Rule weights are odd: the even weight just above each one is free for its hold permit (see `hold_permits`).
        let weight = 1
            + (u64::from(dims) << 48)
            + (u64::from(narrow) << 32)
            + (u64::from(rule.action.blocks()) << 31)
            + 2 * (count - i as u64);
        let mut remotes: Vec<Option<Net>> = rule.ip.iter().copied().map(Some).collect();
        for host in &rule.host {
            remotes.extend(resolved(host).into_iter().map(|ip| Some(Net::single(ip))));
        }
        if rule.host.is_empty() && rule.ip.is_empty() {
            remotes.push(None);
        }
        let programs: Vec<Option<String>> = if rule.process.is_empty() {
            vec![None]
        } else {
            rule.process
                .iter()
                .flat_map(|p| {
                    if is_full_path(p) {
                        vec![p.clone()]
                    } else {
                        programs(p)
                    }
                })
                .map(Some)
                .collect()
        };
        let ports: Vec<Option<u16>> = if rule.port.is_empty() {
            vec![None]
        } else {
            rule.port.iter().copied().map(Some).collect()
        };
        for program in &programs {
            for remote in &remotes {
                for port in &ports {
                    let filter = Filter {
                        rule: rule.id.clone(),
                        program: program.clone(),
                        remote: *remote,
                        port: *port,
                        protocol: rule.protocol,
                        action: rule.action,
                        weight,
                    };
                    if !out.contains(&filter) {
                        out.push(filter);
                    }
                }
            }
        }
    }
    if default != DefaultAction::Allow {
        out.push(Filter {
            rule: "default".into(),
            program: None,
            remote: None,
            port: None,
            protocol: Protocol::Any,
            action: if default == DefaultAction::Ask {
                RuleAction::Ask
            } else {
                RuleAction::Block
            },
            weight: 0,
        });
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.weight));
    out
}

/// The filter WFP applies to a connection: the highest-weight filter whose conditions all match, as WFP picks it
/// within Gatewizz's sublayer. `None` means no Gatewizz filter matches, so the connection is allowed. `program` is the
/// connecting program's full path.
#[cfg_attr(
    not(any(test, windows)),
    expect(dead_code, reason = "the hold service runs on Windows only")
)]
pub fn classify<'a>(
    filters: &'a [Filter],
    program: &str,
    remote: IpAddr,
    port: u16,
    protocol: Protocol,
) -> Option<&'a Filter> {
    filters
        .iter()
        .filter(|f| {
            f.program
                .as_deref()
                .is_none_or(|p| p.eq_ignore_ascii_case(program))
                && f.remote.is_none_or(|net| net.contains(remote))
                && f.port.is_none_or(|p| p == port)
                && (f.protocol == Protocol::Any || f.protocol == protocol)
        })
        .max_by_key(|f| f.weight)
}

/// The permits that let `ask` connections through WFP while the service holds them (#60): one per `ask` filter,
/// same conditions, weight one above it. They live in a dynamic WFP session only, so WFP drops them when the service
/// exits, and the `ask` filters block again (fail closed).
///
/// TCP only: holding works on the TCP SYN, so an `ask` filter for any protocol gets a TCP permit, and one for UDP
/// none. UDP keeps being blocked and asked about afterwards, as without holding.
#[cfg_attr(
    not(any(test, windows)),
    expect(dead_code, reason = "the hold service runs on Windows only")
)]
pub fn hold_permits(filters: &[Filter]) -> Vec<Filter> {
    filters
        .iter()
        .filter(|f| f.action == RuleAction::Ask && f.protocol != Protocol::Udp)
        .map(|f| Filter {
            rule: format!("hold:{}", f.rule),
            protocol: Protocol::Tcp,
            action: RuleAction::Allow,
            weight: f.weight + 1,
            ..f.clone()
        })
        .collect()
}

/// Program file names in active rules that `programs` resolves to no path: those parts of the rules are not
/// enforced until the program is found, so `firewall apply` says so.
pub fn unresolved(
    rules: &[Rule],
    now: SystemTime,
    programs: impl Fn(&str) -> Vec<String>,
) -> Vec<String> {
    let mut out: Vec<String> = rules
        .iter()
        .filter(|r| r.active(now))
        .flat_map(|r| r.process.iter())
        .filter(|p| !is_full_path(p) && programs(p).is_empty())
        .map(|p| p.to_ascii_lowercase())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A blocked attempt the user may be asked about.
#[cfg_attr(
    not(any(test, windows)),
    expect(dead_code, reason = "used by the Windows firewall service (#59)")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub program: String,
    /// Host name if known, else the IP as text.
    pub host: String,
    pub port: u16,
    /// Attempts folded into this notice.
    pub count: u32,
    pub first: Instant,
}

/// Folds repeated attempts by one program to one host and port into a single notice per window, so a retrying app
/// produces one prompt, not dozens. Bounded: past `max` keys the oldest are forgotten.
#[cfg_attr(
    not(any(test, windows)),
    expect(dead_code, reason = "used by the Windows firewall service (#59)")
)]
pub struct Coalescer {
    window: Duration,
    max: usize,
    notices: HashMap<(String, String, u16), Notice>,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "for the approval prompt, next in #59")
)]
impl Coalescer {
    pub fn new(window: Duration, max: usize) -> Self {
        Self {
            window,
            max: max.max(1),
            notices: HashMap::new(),
        }
    }

    /// Records an attempt. `true` means it opens a new notice (prompt the user); `false` means it was folded into an
    /// open one.
    pub fn push(&mut self, program: &str, host: &str, port: u16, now: Instant) -> bool {
        let key = (
            program.to_ascii_lowercase(),
            host.to_ascii_lowercase(),
            port,
        );
        if let Some(n) = self.notices.get_mut(&key)
            && now.duration_since(n.first) < self.window
        {
            n.count += 1;
            return false;
        }
        if self.notices.len() >= self.max {
            let window = self.window;
            self.notices
                .retain(|_, n| now.duration_since(n.first) < window);
            while self.notices.len() >= self.max {
                let oldest = self
                    .notices
                    .iter()
                    .min_by_key(|(_, n)| n.first)
                    .map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => {
                        self.notices.remove(&k);
                    }
                    None => break,
                }
            }
        }
        self.notices.insert(
            key,
            Notice {
                program: program.to_string(),
                host: host.to_string(),
                port,
                count: 1,
                first: now,
            },
        );
        true
    }

    pub fn get(&self, program: &str, host: &str, port: u16) -> Option<&Notice> {
        self.notices.get(&(
            program.to_ascii_lowercase(),
            host.to_ascii_lowercase(),
            port,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rules(toml: &str) -> Vec<Rule> {
        #[derive(Deserialize)]
        struct File {
            connection_rules: Vec<Rule>,
        }
        let rules = toml::from_str::<File>(toml).unwrap().connection_rules;
        validate(&rules).unwrap();
        rules
    }

    fn conn<'a>(program: &'a str, host: Option<&'a str>, addr: &str, port: u16) -> Connection<'a> {
        Connection {
            program: Some(program),
            ip: ip(addr),
            host,
            port,
            protocol: Protocol::Tcp,
        }
    }

    const OWN: &str = "gatewizz.exe";
    const OWN_PATH: &str = r"C:\Users\u\AppData\Local\Programs\Gatewizz\gatewizz.exe";

    fn own_paths() -> Vec<String> {
        vec![OWN_PATH.to_string()]
    }

    fn no_paths(_: &str) -> Vec<String> {
        Vec::new()
    }

    fn decide_now(c: &Connection<'_>, rules: &[Rule], default: DefaultAction) -> Decision {
        decide(c, rules, default, OWN, true, SystemTime::now())
    }

    #[test]
    fn nets_parse_and_contain() {
        let n = Net::parse("10.0.0.0/8").unwrap();
        assert!(n.contains(ip("10.1.2.3")));
        assert!(!n.contains(ip("11.0.0.1")));
        assert!(!n.contains(ip("::ffff:10.1.2.3")), "families never mix");
        assert!(Net::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        // Prefix edges: the mask is the prefix length, not the 128-bit ranking scale.
        let lan = Net::parse("192.168.1.0/24").unwrap();
        assert!(lan.contains(ip("192.168.1.0")) && lan.contains(ip("192.168.1.255")));
        assert!(!lan.contains(ip("192.168.2.0")) && !lan.contains(ip("192.168.0.255")));
        assert!(Net::parse("1.2.3.4/32").unwrap().contains(ip("1.2.3.4")));
        assert!(!Net::parse("1.2.3.4/32").unwrap().contains(ip("1.2.3.5")));
        assert!(Net::parse("::/0").unwrap().contains(ip("2001:db8::1")));
        let v6 = Net::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8:1::5")));
        assert!(!v6.contains(ip("2001:db9::1")));
        assert_eq!(Net::parse("1.2.3.4").unwrap().len, 32);
        assert!(Net::parse("10.0.0.0/33").unwrap_err().contains("0..=32"));
        assert!(Net::parse("example.com").is_err());
    }

    #[test]
    fn rules_parse_and_reject_mistakes() {
        let ok = rules(
            r#"
            [[connection_rules]]
            id = "a"
            process = ["curl.exe"]
            host = ["*.example.com"]
            ip = ["10.0.0.0/8"]
            port = [443]
            protocol = "tcp"
            action = "allow"
            "#,
        );
        assert_eq!(ok[0].ip[0], Net::parse("10.0.0.0/8").unwrap());
        assert_eq!(ok[0].protocol, Protocol::Tcp);

        #[derive(Deserialize)]
        struct File {
            connection_rules: Vec<Rule>,
        }
        let parse = |t: &str| toml::from_str::<File>(t).map(|f| f.connection_rules);
        assert!(
            parse("[[connection_rules]]\nid = \"a\"\nhots = []\naction = \"allow\"\n").is_err()
        );
        assert_eq!(
            parse("[[connection_rules]]\nid = \"a\"\naction = \"ask\"\n").unwrap()[0].action,
            RuleAction::Ask
        );
        assert!(parse("[[connection_rules]]\nid = \"a\"\naction = \"maybe\"\n").is_err());
        assert!(
            parse("[[connection_rules]]\nid = \"a\"\nip = [\"1.2.3\"]\naction = \"allow\"\n")
                .is_err()
        );

        let bad = |t: &str| validate(&parse(t).unwrap()).unwrap_err();
        assert!(
            bad("[[connection_rules]]\nid = \"gatewizz-self\"\naction = \"block\"\n")
                .contains(".id")
        );
        assert!(
            bad("[[connection_rules]]\nid = \"a\"\naction = \"block\"\n[[connection_rules]]\nid = \"a\"\naction = \"allow\"\n")
                .contains("duplicate")
        );
        assert!(
            bad("[[connection_rules]]\nid = \"a\"\nport = [0]\naction = \"block\"\n")
                .contains(".port")
        );
        assert!(
            bad("[[connection_rules]]\nid = \"a\"\nhost = [\"a.*.com\"]\naction = \"block\"\n")
                .contains(".host")
        );
        assert!(
            bad("[[connection_rules]]\nid = \"a\"\nprocess = [\"tools\\\\a.exe\"]\naction = \"block\"\n")
                .contains("file name")
        );
        // A full path is fine: WFP enforces it as is.
        validate(
            &parse("[[connection_rules]]\nid = \"a\"\nprocess = [\"C:\\\\Tools\\\\a.exe\"]\naction = \"block\"\n")
                .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn program_entries_are_names_or_full_paths() {
        assert_eq!(file_name(r"C:\Tools\SmartWizz.exe"), "SmartWizz.exe");
        assert_eq!(file_name("curl.exe"), "curl.exe");
        assert!(is_full_path(r"C:\Tools\a.exe") && is_full_path(r"\\server\share\a.exe"));
        assert!(
            !is_full_path("a.exe") && !is_full_path(r"tools\a.exe") && !is_full_path("C:a.exe")
        );
        // A rule naming a full path matches the connection's program by file name.
        let r = rules(
            "[[connection_rules]]\nid = \"p\"\nprocess = [\"C:\\\\Tools\\\\curl.exe\"]\naction = \"block\"\n",
        );
        assert_eq!(
            decide_now(
                &conn("curl.exe", None, "1.1.1.1", 443),
                &r,
                DefaultAction::Allow
            )
            .rule,
            "p"
        );
    }

    #[test]
    fn rules_round_trip_through_toml() {
        #[derive(Deserialize, Serialize)]
        struct File {
            connection_rules: Vec<Rule>,
        }
        let text = r#"
            [[connection_rules]]
            id = "a"
            process = ["curl.exe"]
            ip = ["10.0.0.0/8", "1.2.3.4"]
            port = [443]
            protocol = "tcp"
            action = "block"
        "#;
        let file: File = toml::from_str(text).unwrap();
        let again: File = toml::from_str(&toml::to_string(&file).unwrap()).unwrap();
        assert_eq!(again.connection_rules, file.connection_rules);
        assert!(toml::to_string(&file).unwrap().contains("\"1.2.3.4\""));
    }

    #[test]
    fn matching_uses_every_given_key() {
        let r = rules(
            r#"
            [[connection_rules]]
            id = "curl-example"
            process = ["CURL.exe"]
            host = ["*.example.com"]
            port = [443]
            protocol = "tcp"
            action = "block"
            "#,
        );
        let d = |c: Connection<'_>| decide_now(&c, &r, DefaultAction::Allow).rule;
        assert_eq!(
            d(conn("curl.exe", Some("api.example.com"), "1.1.1.1", 443)),
            "curl-example"
        );
        assert_eq!(
            d(conn("curl.exe", Some("api.example.com"), "1.1.1.1", 80)),
            "default"
        );
        assert_eq!(
            d(conn("curl.exe", Some("example.org"), "1.1.1.1", 443)),
            "default"
        );
        assert_eq!(
            d(conn("wget.exe", Some("api.example.com"), "1.1.1.1", 443)),
            "default"
        );
        assert_eq!(
            d(conn("curl.exe", None, "1.1.1.1", 443)),
            "default",
            "no host name, no host match"
        );
        let udp = Connection {
            protocol: Protocol::Udp,
            ..conn("curl.exe", Some("api.example.com"), "1.1.1.1", 443)
        };
        assert_eq!(d(udp), "default");
        // An unknown program never matches a rule that names programs.
        let unknown = Connection {
            program: None,
            ..conn("x", Some("api.example.com"), "1.1.1.1", 443)
        };
        assert_eq!(d(unknown), "default");
    }

    #[test]
    fn most_specific_wins_then_block_then_order() {
        let r = rules(
            r#"
            [[connection_rules]]
            id = "wizz-blocked"
            process = ["smartwizz.exe"]
            action = "block"

            [[connection_rules]]
            id = "wizz-to-proxy"
            process = ["smartwizz.exe"]
            ip = ["127.0.0.1"]
            port = [8899]
            action = "allow"

            [[connection_rules]]
            id = "lan-allowed"
            ip = ["192.168.0.0/16"]
            action = "allow"

            [[connection_rules]]
            id = "printer-blocked"
            ip = ["192.168.1.50"]
            action = "block"

            [[connection_rules]]
            id = "lan-blocked-too"
            ip = ["192.168.0.0/16"]
            action = "block"

            [[connection_rules]]
            id = "first-allow"
            host = ["a.example"]
            action = "allow"

            [[connection_rules]]
            id = "second-allow"
            host = ["a.example"]
            action = "allow"
            "#,
        );
        let d = |c: Connection<'_>| decide_now(&c, &r, DefaultAction::Allow);
        // The proxy-enforcement preset: the narrow allow beats the program-wide block.
        assert_eq!(
            d(conn("smartwizz.exe", None, "127.0.0.1", 8899)).rule,
            "wizz-to-proxy"
        );
        let direct = d(conn(
            "smartwizz.exe",
            Some("api.openai.com"),
            "1.2.3.4",
            443,
        ));
        assert_eq!(
            (direct.verdict, direct.rule.as_str()),
            (Verdict::Block, "wizz-blocked")
        );
        // A single address is narrower than a /16.
        assert_eq!(
            d(conn("app.exe", None, "192.168.1.50", 80)).rule,
            "printer-blocked"
        );
        // Equally specific: block beats allow, whatever the order.
        assert_eq!(
            d(conn("app.exe", None, "192.168.7.7", 80)).rule,
            "lan-blocked-too"
        );
        // Equally specific and the same action: the first one wins.
        assert_eq!(
            d(conn("app.exe", Some("a.example"), "9.9.9.9", 80)).rule,
            "first-allow"
        );
    }

    #[test]
    fn exact_hosts_beat_wildcards_and_wildcards_beat_wide_prefixes() {
        let r = rules(
            r#"
            [[connection_rules]]
            id = "wide"
            ip = ["0.0.0.0/0"]
            action = "block"

            [[connection_rules]]
            id = "wild"
            host = ["*.example.com"]
            action = "allow"

            [[connection_rules]]
            id = "exact"
            host = ["bad.example.com"]
            action = "block"
            "#,
        );
        let d = |host| {
            decide_now(
                &conn("app.exe", Some(host), "5.5.5.5", 443),
                &r,
                DefaultAction::Allow,
            )
            .rule
        };
        assert_eq!(d("good.example.com"), "wild");
        assert_eq!(d("bad.example.com"), "exact");
        assert_eq!(d("example.org"), "wide");
    }

    #[test]
    fn defaults_and_fail_closed_ask() {
        let c = conn("app.exe", None, "8.8.8.8", 53);
        let now = SystemTime::now();
        assert_eq!(
            decide(&c, &[], DefaultAction::Allow, OWN, false, now).verdict,
            Verdict::Allow
        );
        assert_eq!(
            decide(&c, &[], DefaultAction::Block, OWN, true, now).verdict,
            Verdict::Block
        );
        assert_eq!(
            decide(&c, &[], DefaultAction::Ask, OWN, true, now).verdict,
            Verdict::Ask
        );
        // No approval window attached: asking is impossible, so block.
        assert_eq!(
            decide(&c, &[], DefaultAction::Ask, OWN, false, now).verdict,
            Verdict::Block
        );
    }

    #[test]
    fn ask_rules_block_and_ask_and_beat_allows() {
        let r = rules(
            r#"
            [[connection_rules]]
            id = "allow-curl"
            process = ["curl.exe"]
            action = "allow"

            [[connection_rules]]
            id = "ask-curl"
            process = ["curl.exe"]
            action = "ask"
            "#,
        );
        let c = conn("curl.exe", None, "8.8.8.8", 443);
        let now = SystemTime::now();
        let d = decide(&c, &r, DefaultAction::Allow, OWN, true, now);
        assert_eq!((d.verdict, d.rule.as_str()), (Verdict::Ask, "ask-curl"));
        // Without the tray app, asking is impossible, so it blocks.
        assert_eq!(
            decide(&c, &r, DefaultAction::Allow, OWN, false, now).verdict,
            Verdict::Block
        );
        let p = plan(
            &r,
            DefaultAction::Block,
            &[],
            now,
            |_| Vec::new(),
            |_| vec![r"C:\tools\curl.exe".to_string()],
        );
        let weight = |id: &str| p.iter().find(|f| f.rule == id).unwrap().weight;
        assert!(weight("ask-curl") > weight("allow-curl"));
        let last = p.last().unwrap();
        assert_eq!(
            (last.rule.as_str(), last.action),
            ("default", RuleAction::Block)
        );
        assert!(
            RuleAction::Ask.blocks() && RuleAction::Block.blocks() && !RuleAction::Allow.blocks()
        );
    }

    #[test]
    fn gatewizz_itself_is_always_allowed() {
        let r = rules("[[connection_rules]]\nid = \"all\"\naction = \"block\"\n");
        let d = decide_now(
            &conn("GATEWIZZ.EXE", None, "1.1.1.1", 443),
            &r,
            DefaultAction::Block,
        );
        assert_eq!((d.verdict, d.rule.as_str()), (Verdict::Allow, SELF_RULE));
    }

    #[test]
    fn expired_rules_stop_applying() {
        let mut r =
            rules("[[connection_rules]]\nid = \"once\"\nip = [\"1.1.1.1\"]\naction = \"allow\"\n");
        let now = SystemTime::now();
        r[0].expires = Some(now + Duration::from_secs(60));
        let c = conn("app.exe", None, "1.1.1.1", 443);
        assert_eq!(
            decide(&c, &r, DefaultAction::Block, OWN, true, now).rule,
            "once"
        );
        let later = now + Duration::from_secs(60);
        assert_eq!(
            decide(&c, &r, DefaultAction::Block, OWN, true, later).rule,
            "default"
        );
        assert!(
            plan(
                &r,
                DefaultAction::Block,
                &own_paths(),
                later,
                |_| Vec::new(),
                no_paths
            )
            .iter()
            .all(|f| f.rule != "once")
        );
    }

    #[test]
    fn plan_expands_rules_and_orders_them_like_decide() {
        let r = rules(
            r#"
            [[connection_rules]]
            id = "wizz-blocked"
            process = ["SmartWizz.exe"]
            action = "block"

            [[connection_rules]]
            id = "wizz-to-proxy"
            process = ["smartwizz.exe", "testwizz.exe"]
            ip = ["127.0.0.1"]
            port = [8899]
            action = "allow"

            [[connection_rules]]
            id = "api"
            host = ["api.example.com", "unseen.example.com"]
            port = [443, 8443]
            action = "allow"
            "#,
        );
        let resolved = |h: &str| match h {
            "api.example.com" => vec![ip("93.184.215.14"), ip("2606:2800::1")],
            _ => Vec::new(),
        };
        let paths = |name: &str| match name {
            "SmartWizz.exe" | "smartwizz.exe" => vec![
                r"C:\Users\u\.dotnet\tools\smartwizz.exe".to_string(),
                r"D:\wizz\smartwizz.exe".to_string(),
            ],
            "testwizz.exe" => vec![r"C:\Users\u\.dotnet\tools\testwizz.exe".to_string()],
            _ => Vec::new(),
        };
        let p = plan(
            &r,
            DefaultAction::Ask,
            &own_paths(),
            SystemTime::now(),
            resolved,
            paths,
        );
        // Self first, default last; every own path is allowed once.
        let two = [
            OWN_PATH.to_string(),
            r"C:\Program Files\Gatewizz\gatewizz.exe".to_string(),
            OWN_PATH.to_ascii_uppercase(),
        ];
        let selfs = plan(
            &r,
            DefaultAction::Allow,
            &two,
            SystemTime::now(),
            |_| Vec::new(),
            no_paths,
        )
        .into_iter()
        .filter(|f| f.rule == SELF_RULE)
        .count();
        assert_eq!(selfs, 2);
        assert_eq!(p.first().unwrap().rule, SELF_RULE);
        assert_eq!(p.first().unwrap().program.as_deref(), Some(OWN_PATH));
        let last = p.last().unwrap();
        assert_eq!(
            (last.rule.as_str(), last.action, last.weight),
            ("default", RuleAction::Ask, 0)
        );
        // 3 program paths × 1 address × 1 port, 2 resolved IPs × 2 ports, 2 smartwizz paths.
        let count = |id: &str| p.iter().filter(|f| f.rule == id).count();
        assert_eq!(
            (count("wizz-to-proxy"), count("api"), count("wizz-blocked")),
            (3, 4, 2)
        );
        // The unseen host has no IP yet, so it adds no filter: "api" has 4, all from the resolved name.
        assert!(
            p.iter()
                .filter(|f| f.rule == "api")
                .all(|f| f.remote.is_some())
        );
        // File names become the full paths WFP's app ID needs.
        assert!(
            p.iter().any(|f| f.rule == "wizz-blocked"
                && f.program.as_deref() == Some(r"D:\wizz\smartwizz.exe"))
        );
        // Weights mirror decide(): the narrow allow outranks the program-wide block.
        let weight = |id: &str| p.iter().find(|f| f.rule == id).unwrap().weight;
        assert!(weight("wizz-to-proxy") > weight("wizz-blocked"));
        assert!(p.windows(2).all(|w| w[0].weight >= w[1].weight));
        // An allow default needs no catch-all filter.
        assert!(
            plan(
                &r,
                DefaultAction::Allow,
                &own_paths(),
                SystemTime::now(),
                |_| Vec::new(),
                no_paths
            )
            .iter()
            .all(|f| f.rule != "default")
        );
    }

    #[test]
    fn unresolved_programs_are_reported_and_add_no_filter() {
        let r = rules(
            r#"
            [[connection_rules]]
            id = "a"
            process = ["missing.exe", "C:\\Tools\\full.exe", "found.exe"]
            action = "block"
            "#,
        );
        let paths = |name: &str| {
            if name == "found.exe" {
                vec![r"C:\x\found.exe".to_string()]
            } else {
                Vec::new()
            }
        };
        assert_eq!(unresolved(&r, SystemTime::now(), paths), ["missing.exe"]);
        let p = plan(
            &r,
            DefaultAction::Allow,
            &own_paths(),
            SystemTime::now(),
            |_| Vec::new(),
            paths,
        );
        let progs: Vec<_> = p
            .iter()
            .filter(|f| f.rule == "a")
            .filter_map(|f| f.program.as_deref())
            .collect();
        assert_eq!(progs, [r"C:\Tools\full.exe", r"C:\x\found.exe"]);
    }

    #[test]
    fn coalescer_folds_retries_into_one_notice_per_window() {
        let now = Instant::now();
        let mut c = Coalescer::new(Duration::from_secs(30), 16);
        assert!(c.push("App.exe", "Example.com", 443, now));
        assert!(!c.push("app.exe", "example.com", 443, now + Duration::from_secs(1)));
        assert!(!c.push("app.exe", "example.com", 443, now + Duration::from_secs(2)));
        assert_eq!(c.get("app.exe", "example.com", 443).unwrap().count, 3);
        // Another port or host is its own notice.
        assert!(c.push("app.exe", "example.com", 80, now));
        assert!(c.push("app.exe", "example.net", 443, now));
        // After the window the same attempt prompts again.
        assert!(c.push("app.exe", "example.com", 443, now + Duration::from_secs(30)));
        assert_eq!(c.get("app.exe", "example.com", 443).unwrap().count, 1);
    }

    #[test]
    fn coalescer_is_bounded() {
        let now = Instant::now();
        let mut c = Coalescer::new(Duration::from_secs(30), 4);
        for i in 0..20u16 {
            assert!(c.push(
                "app.exe",
                "h.example",
                i + 1,
                now + Duration::from_millis(u64::from(i))
            ));
            assert!(c.notices.len() <= 4);
        }
        // The newest survive.
        assert!(c.get("app.exe", "h.example", 20).is_some());
        assert!(c.get("app.exe", "h.example", 1).is_none());
    }

    #[test]
    fn classify_picks_what_wfp_picks_and_hold_permits_sit_just_above_asks() {
        let r = rules(
            r#"
            [[connection_rules]]
            id = "ask-curl"
            process = ['C:\tools\curl.exe']
            action = "ask"

            [[connection_rules]]
            id = "allow-curl-https"
            process = ['C:\tools\curl.exe']
            ip = ["192.0.2.0/24"]
            port = [443]
            protocol = "tcp"
            action = "allow"

            [[connection_rules]]
            id = "block-lan"
            ip = ["10.0.0.0/8"]
            action = "block"
            "#,
        );
        let now = SystemTime::now();
        let p = plan(
            &r,
            DefaultAction::Ask,
            &own_paths(),
            now,
            |_| Vec::new(),
            no_paths,
        );
        let curl = r"C:\Tools\CURL.exe";
        let c = |ip: &str, port, proto| {
            classify(&p, curl, ip.parse().unwrap(), port, proto).map(|f| f.rule.as_str())
        };
        assert_eq!(c("192.0.2.9", 443, Protocol::Tcp), Some("allow-curl-https"));
        assert_eq!(c("192.0.2.9", 80, Protocol::Tcp), Some("ask-curl"));
        // One pinned dimension each: the address-only block is narrower than the program-only ask, so it wins.
        assert_eq!(c("10.1.1.1", 80, Protocol::Tcp), Some("block-lan"));
        let other = classify(
            &p,
            r"C:\other.exe",
            "10.1.1.1".parse().unwrap(),
            80,
            Protocol::Tcp,
        );
        assert_eq!(other.map(|f| f.rule.as_str()), Some("block-lan"));
        let unmatched = classify(
            &p,
            r"C:\other.exe",
            "8.8.8.8".parse().unwrap(),
            53,
            Protocol::Udp,
        );
        assert_eq!(unmatched.map(|f| f.rule.as_str()), Some("default"));
        assert_eq!(
            classify(&p, OWN_PATH, "10.1.1.1".parse().unwrap(), 80, Protocol::Tcp)
                .map(|f| f.rule.as_str()),
            Some(SELF_RULE)
        );

        // Every rule weight is odd, so a permit at weight + 1 never ties with another filter.
        assert!(
            p.iter()
                .filter(|f| f.rule != SELF_RULE && f.rule != "default")
                .all(|f| f.weight % 2 == 1)
        );
        let permits = hold_permits(&p);
        assert_eq!(
            permits.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>(),
            ["hold:ask-curl", "hold:default"]
        );
        let mut all = p.clone();
        all.extend(permits);
        assert!(all.iter().all(
            |f| all.iter().filter(|g| g.weight == f.weight).count() == 1 || f.rule == SELF_RULE
        ));
        // With the permits in place, what asked is now allowed (held by the service), and nothing else changed.
        let c2 = |ip: &str, port, proto| {
            classify(&all, curl, ip.parse().unwrap(), port, proto).map(|f| f.rule.as_str())
        };
        assert_eq!(c2("192.0.2.9", 80, Protocol::Tcp), Some("hold:ask-curl"));
        assert_eq!(
            c2("192.0.2.9", 443, Protocol::Tcp),
            Some("allow-curl-https")
        );
        let other = classify(
            &all,
            r"C:\other.exe",
            "10.1.1.1".parse().unwrap(),
            80,
            Protocol::Tcp,
        );
        assert_eq!(other.map(|f| f.rule.as_str()), Some("block-lan"));
        // UDP is never let through: it cannot be held, so it keeps being blocked and asked about.
        assert_eq!(c2("192.0.2.9", 53, Protocol::Udp), Some("ask-curl"));
        assert!(
            all.iter()
                .filter(|f| f.rule.starts_with("hold:"))
                .all(|f| f.protocol == Protocol::Tcp)
        );
        let udp_only = rules(
            "[[connection_rules]]\nid = \"ask-dns\"\nport = [53]\nprotocol = \"udp\"\naction = \"ask\"\n",
        );
        let p = plan(
            &udp_only,
            DefaultAction::Allow,
            &[],
            now,
            |_| Vec::new(),
            no_paths,
        );
        assert!(hold_permits(&p).is_empty());
    }
}
