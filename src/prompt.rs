//! The firewall prompt's protocol and its validation (#59): the service tells the tray app about a blocked
//! connection, and the user's answer comes back as a new connection rule. Pure, tested on every OS.
//!
//! Trust boundary: the service runs as SYSTEM and the tray app as the user, so the service never trusts a decision
//! to name arbitrary rules. A [`Decision`] only answers a [`Notice`] the service itself sent and still remembers.
//! The program, address and port always come from that notice. The tray may only widen to "any host" or
//! "any port", choose allow or block, and pick one of the fixed durations. A forged or stale id is refused.
//!
//! Wire format: JSON, one message per line, both directions. Messages carry metadata only.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::firewall::{Net, Protocol, Rule, RuleAction};

/// A blocked connection, as the service reports it to the tray app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    pub id: u64,
    /// The program's file name, for display.
    pub program: String,
    /// The program's full path, which the rule will name.
    pub path: String,
    pub remote: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    /// Attempts folded into this notice so far.
    pub count: u32,
    /// The connection is held while the user decides (#60): it completes on allow instead of having failed.
    #[serde(default)]
    pub held: bool,
}

/// How long an allow or block from the prompt lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lasting {
    /// A short-lived rule, long enough for the app's retry: [`ONCE`].
    Once,
    /// One of the prompt's presets: 5, 15, 60 or 480 minutes.
    Minutes(u32),
    /// Written to the protected configuration; survives restarts.
    Always,
}

/// "Allow once" is a rule that lives this long: the app retries within seconds.
pub const ONCE: Duration = Duration::from_secs(120);

/// The durations the prompt offers, in minutes. Anything else is refused, so a decision cannot plant a rule that
/// lasts years without being written down.
pub const PRESETS: [u32; 4] = [5, 15, 60, 480];

/// The user's answer to one notice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub id: u64,
    pub action: RuleAction,
    pub lasting: Lasting,
    /// Widen the rule from the notice's address to any address.
    #[serde(default)]
    pub any_host: bool,
    /// Widen the rule from the notice's port to any port.
    #[serde(default)]
    pub any_port: bool,
}

/// One line on the pipe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// Service to tray.
    Notice(Notice),
    /// Tray to service.
    Decision(Decision),
    /// Service to tray: what became of a decision.
    Result { id: u64, ok: bool, message: String },
}

/// A message as one line of the wire format.
pub fn encode(message: &Message) -> String {
    let mut line = serde_json::to_string(message).expect("messages always serialize");
    line.push('\n');
    line
}

/// The longest line accepted from a client, so a client cannot make the service buffer without bound.
pub const MAX_LINE: usize = 4096;

pub fn decode(line: &str) -> Result<Message, String> {
    if line.len() > MAX_LINE {
        return Err(format!("message longer than {MAX_LINE} bytes"));
    }
    serde_json::from_str(line.trim_end()).map_err(|e| format!("bad message: {e}"))
}

/// The rule a valid decision produces: `expires` is set for everything but [`Lasting::Always`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub rule: Rule,
    pub permanent: bool,
}

/// How long the service remembers a notice it sent; an answer after that is refused as stale.
pub const NOTICE_TTL: Duration = Duration::from_secs(600);

/// The notices the service has sent and not yet seen answered, bounded and expiring.
pub struct Outstanding {
    next_id: u64,
    max: usize,
    sent: VecDeque<(Instant, Notice)>,
}

impl Outstanding {
    pub fn new(max: usize) -> Self {
        Self {
            next_id: 1,
            max: max.max(1),
            sent: VecDeque::new(),
        }
    }

    /// Records a new notice and returns it with its id.
    pub fn add(
        &mut self,
        program: &str,
        path: &str,
        remote: IpAddr,
        port: u16,
        protocol: Protocol,
        now: Instant,
    ) -> Notice {
        self.expire(now);
        while self.sent.len() >= self.max {
            self.sent.pop_front();
        }
        let notice = Notice {
            id: self.next_id,
            program: program.to_string(),
            path: path.to_string(),
            remote,
            port,
            protocol,
            count: 1,
            held: false,
        };
        self.next_id += 1;
        self.sent.push_back((now, notice.clone()));
        notice
    }

    fn expire(&mut self, now: Instant) {
        while self
            .sent
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) >= NOTICE_TTL)
        {
            self.sent.pop_front();
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sent.len()
    }

    /// Turns a decision into the rule it stands for, and forgets the notice. Refuses ids it never sent or no longer
    /// remembers, and durations the prompt does not offer.
    pub fn answer(
        &mut self,
        decision: &Decision,
        now: Instant,
        wall: SystemTime,
    ) -> Result<Change, String> {
        self.expire(now);
        let at = self
            .sent
            .iter()
            .position(|(_, n)| n.id == decision.id)
            .ok_or_else(|| format!("notice {} is unknown or expired", decision.id))?;
        let expires = match decision.lasting {
            Lasting::Once => Some(wall + ONCE),
            Lasting::Minutes(m) if PRESETS.contains(&m) => {
                Some(wall + Duration::from_secs(u64::from(m) * 60))
            }
            Lasting::Minutes(m) => {
                return Err(format!(
                    "{m} minutes is not one of the offered durations {PRESETS:?}"
                ));
            }
            Lasting::Always => None,
        };
        let verb = match decision.action {
            RuleAction::Allow => "allow",
            RuleAction::Block => "block",
            // The answer to a prompt cannot be another prompt.
            RuleAction::Ask => return Err("a decision allows or blocks; it cannot ask".into()),
        };
        let (_, notice) = self.sent.remove(at).expect("position is in range");
        // Notice ids restart with the service; the wall-clock second keeps ids unique in the written configuration.
        let stamp = wall
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let rule = Rule {
            id: format!(
                "prompt-{verb}-{}-{stamp}-{}",
                crate::firewall::file_name(&notice.program).to_ascii_lowercase(),
                notice.id
            ),
            process: vec![notice.path.clone()],
            host: Vec::new(),
            ip: if decision.any_host {
                Vec::new()
            } else {
                vec![Net::single(notice.remote)]
            },
            port: if decision.any_port {
                Vec::new()
            } else {
                vec![notice.port]
            },
            protocol: notice.protocol,
            action: decision.action,
            expires,
        };
        Ok(Change {
            rule,
            permanent: expires.is_none(),
        })
    }
}

/// The text a permanent rule adds to the protected configuration: one `[[connection_rules]]` table, appended so
/// the user's own text and comments stay as they are.
pub fn rule_toml(rule: &Rule) -> String {
    #[derive(Serialize)]
    struct File<'a> {
        connection_rules: [&'a Rule; 1],
    }
    let body = toml::to_string(&File {
        connection_rules: [rule],
    })
    .expect("rules always serialize");
    format!("\n# Added from the firewall prompt.\n{body}")
}

/// The tray app forgets a notice this much before the service does, so an answer never arrives just too late.
pub const INBOX_TTL: Duration = Duration::from_secs(NOTICE_TTL.as_secs() - 60);

/// The tray app's side: the notices waiting for an answer, newest last. Notices for the same program path,
/// address, port and protocol fold into one, which answers with the newest id and adds up the attempts.
pub struct Inbox {
    max: usize,
    waiting: Vec<(Instant, Notice)>,
}

impl Inbox {
    pub fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            waiting: Vec::new(),
        }
    }

    /// Adds a notice; `true` when it is new rather than folded into one already waiting.
    pub fn add(&mut self, notice: Notice, now: Instant) -> bool {
        self.expire(now);
        let same = |n: &Notice| {
            n.path.eq_ignore_ascii_case(&notice.path)
                && n.remote == notice.remote
                && n.port == notice.port
                && n.protocol == notice.protocol
        };
        if let Some(at) = self.waiting.iter().position(|(_, n)| same(n)) {
            let (_, old) = self.waiting.remove(at);
            let count = old.count.saturating_add(notice.count);
            self.waiting.push((now, Notice { count, ..notice }));
            return false;
        }
        if self.waiting.len() >= self.max {
            self.waiting.remove(0);
        }
        self.waiting.push((now, notice));
        true
    }

    /// Forgets the notices the service no longer remembers.
    pub fn expire(&mut self, now: Instant) {
        self.waiting
            .retain(|(at, _)| now.duration_since(*at) < INBOX_TTL);
    }

    /// Takes a notice out to answer it.
    pub fn take(&mut self, id: u64) -> Option<Notice> {
        let at = self.waiting.iter().position(|(_, n)| n.id == id)?;
        Some(self.waiting.remove(at).1)
    }

    pub fn get(&self, id: u64) -> Option<&Notice> {
        self.notices().find(|n| n.id == id)
    }

    /// Oldest first.
    pub fn notices(&self) -> impl Iterator<Item = &Notice> {
        self.waiting.iter().map(|(_, n)| n)
    }

    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// Forgets everything: the service went away, and a restarted one does not know these ids.
    pub fn clear(&mut self) {
        self.waiting.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const PATH: &str = r"C:\Tools\curl.exe";

    fn sent() -> (Outstanding, Notice, Instant) {
        let now = Instant::now();
        let mut o = Outstanding::new(8);
        let n = o.add(
            "curl.exe",
            PATH,
            ip("93.184.215.14"),
            443,
            Protocol::Tcp,
            now,
        );
        (o, n, now)
    }

    fn decision(id: u64, lasting: Lasting) -> Decision {
        Decision {
            id,
            action: RuleAction::Allow,
            lasting,
            any_host: false,
            any_port: false,
        }
    }

    #[test]
    fn messages_round_trip_as_single_lines() {
        let (_, n, _) = sent();
        for m in [
            Message::Notice(n),
            Message::Decision(decision(1, Lasting::Minutes(15))),
            Message::Result {
                id: 1,
                ok: true,
                message: "allowed".into(),
            },
        ] {
            let line = encode(&m);
            assert!(
                line.ends_with('\n') && line.matches('\n').count() == 1,
                "{line}"
            );
            assert_eq!(decode(&line).unwrap(), m);
        }
        assert!(
            decode(r#"{"type":"decision","id":1,"action":"allow","lasting":"once","rule":"x"}"#)
                .is_err()
        );
        assert!(
            decode(&"x".repeat(MAX_LINE + 1))
                .unwrap_err()
                .contains("longer")
        );
    }

    #[test]
    fn a_decision_becomes_a_narrow_rule_from_the_notice() {
        let (mut o, n, now) = sent();
        let wall = SystemTime::now();
        let c = o
            .answer(&decision(n.id, Lasting::Minutes(15)), now, wall)
            .unwrap();
        assert!(!c.permanent);
        assert_eq!(c.rule.process, [PATH]);
        assert_eq!(c.rule.ip, [Net::single(ip("93.184.215.14"))]);
        assert_eq!(c.rule.port, [443]);
        assert_eq!(c.rule.protocol, Protocol::Tcp);
        assert_eq!(c.rule.expires, Some(wall + Duration::from_secs(15 * 60)));
        let stamp = wall
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(c.rule.id, format!("prompt-allow-curl.exe-{stamp}-{}", n.id));
        crate::firewall::validate(std::slice::from_ref(&c.rule)).unwrap();
        // Answered: the same id is refused now.
        assert!(o.answer(&decision(n.id, Lasting::Once), now, wall).is_err());
    }

    #[test]
    fn widening_and_durations_are_bounded() {
        let wall = SystemTime::now();
        let (mut o, n, now) = sent();
        let wide = Decision {
            any_host: true,
            any_port: true,
            action: RuleAction::Block,
            ..decision(n.id, Lasting::Always)
        };
        let c = o.answer(&wide, now, wall).unwrap();
        assert!(c.permanent && c.rule.expires.is_none());
        // The program always stays: widening never makes a rule for every program.
        assert_eq!(c.rule.process, [PATH]);
        assert!(c.rule.ip.is_empty() && c.rule.port.is_empty());
        assert_eq!(c.rule.action, RuleAction::Block);

        let (mut o, n, now) = sent();
        let err = o
            .answer(&decision(n.id, Lasting::Minutes(525_600)), now, wall)
            .unwrap_err();
        assert!(err.contains("not one of the offered durations"));
        let ask = Decision {
            action: RuleAction::Ask,
            ..decision(n.id, Lasting::Always)
        };
        assert!(
            o.answer(&ask, now, wall)
                .unwrap_err()
                .contains("cannot ask")
        );
        // Refused durations and actions leave the notice answerable.
        assert!(o.answer(&decision(n.id, Lasting::Once), now, wall).is_ok());
    }

    #[test]
    fn forged_and_stale_ids_are_refused() {
        let wall = SystemTime::now();
        let (mut o, n, now) = sent();
        assert!(
            o.answer(&decision(n.id + 1000, Lasting::Once), now, wall)
                .unwrap_err()
                .contains("unknown")
        );
        assert!(
            o.answer(&decision(n.id, Lasting::Once), now + NOTICE_TTL, wall)
                .is_err()
        );
        assert_eq!(o.len(), 0, "expired notices are forgotten");
    }

    #[test]
    fn outstanding_notices_are_bounded() {
        let now = Instant::now();
        let mut o = Outstanding::new(3);
        let ids: Vec<u64> = (0..5)
            .map(|i| {
                o.add(
                    "a.exe",
                    r"C:\a.exe",
                    ip("10.0.0.1"),
                    1000 + i,
                    Protocol::Tcp,
                    now,
                )
                .id
            })
            .collect();
        assert_eq!(o.len(), 3);
        let wall = SystemTime::now();
        // The oldest were dropped; ids keep counting up and are never reused.
        assert!(
            o.answer(&decision(ids[0], Lasting::Once), now, wall)
                .is_err()
        );
        assert!(
            o.answer(&decision(ids[4], Lasting::Once), now, wall)
                .is_ok()
        );
        assert_eq!(ids, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn permanent_rules_append_as_valid_toml() {
        let (mut o, n, now) = sent();
        let c = o
            .answer(&decision(n.id, Lasting::Always), now, SystemTime::now())
            .unwrap();
        let existing = "# my rules\n[firewall]\ndefault = \"ask\"\n";
        let combined = format!("{existing}{}", rule_toml(&c.rule));
        let config = crate::config::Config::parse(&combined).unwrap();
        assert_eq!(config.connection_rules, std::slice::from_ref(&c.rule));
        assert!(
            combined.starts_with("# my rules\n"),
            "the user's text stays"
        );
        // A file that ends without a newline, even in a comment, still gets a separate, valid table.
        for tail in [
            "[firewall]\ndefault = \"ask\"",
            "[firewall]\ndefault = \"ask\" # trailing comment",
        ] {
            let combined = format!("{tail}{}", rule_toml(&c.rule));
            let rules = crate::config::Config::parse(&combined)
                .unwrap()
                .connection_rules;
            assert_eq!(rules.len(), 1, "{combined}");
        }
    }

    #[test]
    fn the_inbox_folds_repeats_and_forgets_in_time() {
        let now = Instant::now();
        let (mut o, first, _) = sent();
        let mut inbox = Inbox::new(2);
        assert!(inbox.add(first.clone(), now));
        // The same program, address and port again, as the service sends it after its coalescing window.
        let again = o.add(
            "curl.exe",
            &PATH.to_ascii_uppercase(),
            first.remote,
            first.port,
            first.protocol,
            now,
        );
        assert!(!inbox.add(again.clone(), now + Duration::from_secs(61)));
        assert_eq!(inbox.len(), 1);
        let folded = inbox.get(again.id).unwrap();
        assert_eq!(folded.count, 2, "attempts add up");
        assert!(inbox.get(first.id).is_none(), "the newest id answers");

        // Another port is another notice; the oldest goes when full.
        let other = |port| Notice {
            id: u64::from(port),
            port,
            ..first.clone()
        };
        assert!(inbox.add(other(1), now));
        assert!(inbox.add(other(2), now));
        assert_eq!(inbox.notices().map(|n| n.port).collect::<Vec<_>>(), [1, 2]);

        assert_eq!(inbox.take(1).unwrap().port, 1);
        assert!(inbox.take(1).is_none());
        inbox.expire(now + INBOX_TTL);
        assert!(inbox.is_empty());
        assert!(INBOX_TTL < NOTICE_TTL);
    }
}
