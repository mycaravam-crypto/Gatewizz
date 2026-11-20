//! Allow/block rules: deterministic, explainable decisions on what a request is and where it goes.
//!
//! `block` beats `allow`; when no rule matches, the default action applies. Every decision names its rule.

use serde::{Deserialize, Serialize};

use crate::tls::host_matches;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
    /// Hold for approval (M3). Accepted by the parser only to give a clear error until then.
    Approve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// All keys are optional and combined with AND; a rule without keys matches everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Match {
    /// The request goes to one of these hosts (exact name or `*.suffix`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,
    /// The request goes to none of these hosts. Write allowlists as one `block` rule with `not_host`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_host: Option<Vec<String>>,
    /// The client process image is one of these file names (`smartwizz.exe`), case-insensitive. An unknown process
    /// matches none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// A finding kind such as `secret.github_token`, or `secret.*` for any secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<String>,
    /// The request is (or is not) a request to an AI model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(rename = "match", default)]
    pub matches: Match,
    pub action: Action,
    pub severity: Severity,
}

/// What a request's body showed. `None` in [`Facts::content`] means the body was not inspected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Content<'a> {
    pub findings: &'a [&'a str],
    pub ai: bool,
}

/// What is known about a request when a decision is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts<'a> {
    pub host: &'a str,
    /// Image file name of the client process, if known.
    pub process: Option<&'a str>,
    /// `None` for a tunnel, whose requests are not visible.
    pub path: Option<&'a str>,
    pub content: Option<Content<'a>>,
    /// The requests in this tunnel will each be decided once decrypted, so rules on path and content are left to
    /// them. Without it, a missing fact makes `block` rules match and `allow` rules not (fail closed).
    pub defer_content: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    /// The deciding rule's id, or `default`.
    pub rule: String,
    pub severity: Option<Severity>,
    pub description: String,
}

pub const DEFAULT_RULE: &str = "default";

/// Checks what serde cannot: unique, non-empty ids and no `approve` before M3. Errors name the rule.
pub fn validate(rules: &[Rule], default_action: Action) -> Result<(), String> {
    if default_action == Action::Approve {
        return Err("general.default_action: approve is not available before M3".into());
    }
    for (i, rule) in rules.iter().enumerate() {
        if rule.id.trim().is_empty() || rule.id == DEFAULT_RULE {
            return Err(format!(
                "rules[{i}].id: must be non-empty and not \"{DEFAULT_RULE}\""
            ));
        }
        if rules[..i].iter().any(|earlier| earlier.id == rule.id) {
            return Err(format!("rules[{i}].id: duplicate id \"{}\"", rule.id));
        }
        if rule.action == Action::Approve {
            return Err(format!(
                "rules[{i}].action: approve is not available before M3"
            ));
        }
    }
    Ok(())
}

/// The first matching `block` rule, else the first matching `allow` rule, else the default action.
pub fn decide(facts: &Facts<'_>, rules: &[Rule], default_action: Action) -> Decision {
    let first = |action: Action| {
        rules
            .iter()
            .find(|rule| rule.action == action && applies(&rule.matches, action, facts))
    };
    match first(Action::Block).or_else(|| first(Action::Allow)) {
        Some(rule) => Decision {
            action: rule.action,
            rule: rule.id.clone(),
            severity: Some(rule.severity),
            description: rule.description.clone(),
        },
        None => Decision {
            action: default_action,
            rule: DEFAULT_RULE.to_string(),
            severity: None,
            description: String::new(),
        },
    }
}

fn applies(m: &Match, action: Action, facts: &Facts<'_>) -> bool {
    // One entry per key the rule sets: `Some(matched)` when the fact is known, `None` when it is not.
    let content = facts.content.as_ref();
    let checks: [Option<Option<bool>>; 6] = [
        m.host
            .as_ref()
            .map(|hosts| Some(hosts.iter().any(|p| host_matches(p, facts.host)))),
        m.not_host
            .as_ref()
            .map(|hosts| Some(!hosts.iter().any(|p| host_matches(p, facts.host)))),
        m.process.as_ref().map(|names| {
            Some(
                facts
                    .process
                    .is_some_and(|image| names.iter().any(|n| n.eq_ignore_ascii_case(image))),
            )
        }),
        m.path_prefix
            .as_ref()
            .map(|prefix| facts.path.map(|path| path.starts_with(prefix.as_str()))),
        m.finding.as_ref().map(|wanted| {
            content.map(|c| c.findings.iter().any(|kind| finding_matches(wanted, kind)))
        }),
        m.ai.map(|wanted| content.map(|c| c.ai == wanted)),
    ];
    let mut deferred = false;
    for check in checks.into_iter().flatten() {
        match check {
            Some(true) => {}
            Some(false) => return false,
            None if facts.defer_content => deferred = true,
            // Fail closed: an unknown fact lets a block rule apply and keeps an allow rule from applying.
            None if action == Action::Block => {}
            None => return false,
        }
    }
    !deferred
}

fn finding_matches(wanted: &str, kind: &str) -> bool {
    match wanted.strip_suffix(".*") {
        Some(family) => kind
            .strip_prefix(family)
            .is_some_and(|rest| rest.starts_with('.')),
        None => wanted == kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, action: Action, matches: Match) -> Rule {
        Rule {
            id: id.to_string(),
            description: format!("{id} description"),
            matches,
            action,
            severity: Severity::High,
        }
    }

    fn request<'a>(host: &'a str, content: Option<Content<'a>>) -> Facts<'a> {
        Facts {
            host,
            process: Some("smartwizz.exe"),
            path: Some("/v1/chat/completions"),
            content,
            defer_content: false,
        }
    }

    const SECRET: &[&str] = &["secret.github_token"];

    #[test]
    fn default_applies_when_nothing_matches() {
        let decision = decide(&request("a.example", None), &[], Action::Allow);
        assert_eq!(
            (decision.action, decision.rule.as_str()),
            (Action::Allow, "default")
        );
        assert_eq!(decision.severity, None);
    }

    #[test]
    fn block_beats_allow_regardless_of_order() {
        let rules = [
            rule("allow-all", Action::Allow, Match::default()),
            rule(
                "block-host",
                Action::Block,
                Match {
                    host: Some(vec!["*.example".into()]),
                    ..Match::default()
                },
            ),
        ];
        let decision = decide(&request("api.example", None), &rules, Action::Allow);
        assert_eq!(
            (decision.action, decision.rule.as_str()),
            (Action::Block, "block-host")
        );
        assert_eq!(decision.description, "block-host description");
        let other = decide(&request("other.test", None), &rules, Action::Block);
        assert_eq!(other.rule, "allow-all");
    }

    #[test]
    fn allowlist_is_a_block_rule_with_not_host() {
        let rules = [rule(
            "secrets-only-to-approved-models",
            Action::Block,
            Match {
                not_host: Some(vec!["llm.internal.example".into()]),
                finding: Some("secret.*".into()),
                ..Match::default()
            },
        )];
        let with_secret = Content {
            findings: SECRET,
            ai: true,
        };
        let blocked = decide(
            &request("api.openai.example", Some(with_secret.clone())),
            &rules,
            Action::Allow,
        );
        assert_eq!(blocked.action, Action::Block);
        let approved = decide(
            &request("llm.internal.example", Some(with_secret)),
            &rules,
            Action::Allow,
        );
        assert_eq!(approved.action, Action::Allow);
        let clean = Content {
            findings: &[],
            ai: true,
        };
        let no_secret = decide(
            &request("api.openai.example", Some(clean)),
            &rules,
            Action::Allow,
        );
        assert_eq!(no_secret.action, Action::Allow);
    }

    #[test]
    fn matches_process_path_finding_and_ai() {
        let facts = request(
            "h.example",
            Some(Content {
                findings: SECRET,
                ai: true,
            }),
        );
        let cases = [
            (
                Match {
                    process: Some(vec!["SmartWizz.EXE".into()]),
                    ..Match::default()
                },
                true,
            ),
            (
                Match {
                    process: Some(vec!["curl.exe".into()]),
                    ..Match::default()
                },
                false,
            ),
            (
                Match {
                    path_prefix: Some("/v1/".into()),
                    ..Match::default()
                },
                true,
            ),
            (
                Match {
                    path_prefix: Some("/v2/".into()),
                    ..Match::default()
                },
                false,
            ),
            (
                Match {
                    finding: Some("secret.github_token".into()),
                    ..Match::default()
                },
                true,
            ),
            (
                Match {
                    finding: Some("secret.*".into()),
                    ..Match::default()
                },
                true,
            ),
            (
                Match {
                    finding: Some("secret.aws_key".into()),
                    ..Match::default()
                },
                false,
            ),
            (
                Match {
                    finding: Some("secrets.*".into()),
                    ..Match::default()
                },
                false,
            ),
            (
                Match {
                    ai: Some(true),
                    ..Match::default()
                },
                true,
            ),
            (
                Match {
                    ai: Some(false),
                    ..Match::default()
                },
                false,
            ),
        ];
        for (m, expected) in cases {
            let rules = [rule("r", Action::Block, m.clone())];
            assert_eq!(
                decide(&facts, &rules, Action::Allow).action == Action::Block,
                expected,
                "{m:?}"
            );
        }
    }

    #[test]
    fn unknown_process_matches_no_process_list() {
        let mut facts = request("h.example", None);
        facts.process = None;
        let rules = [rule(
            "r",
            Action::Block,
            Match {
                process: Some(vec!["curl.exe".into()]),
                ..Match::default()
            },
        )];
        assert_eq!(decide(&facts, &rules, Action::Allow).action, Action::Allow);
    }

    #[test]
    fn missing_facts_fail_closed() {
        let needs_content = Match {
            finding: Some("secret.*".into()),
            ..Match::default()
        };
        let block = [rule("b", Action::Block, needs_content.clone())];
        let allow = [rule("a", Action::Allow, needs_content)];
        // A blind tunnel: no path, no content.
        let tunnel = Facts {
            host: "h.example",
            process: None,
            path: None,
            content: None,
            defer_content: false,
        };
        assert_eq!(decide(&tunnel, &block, Action::Allow).action, Action::Block);
        assert_eq!(decide(&tunnel, &allow, Action::Block).rule, "default");
        // A tunnel that will be decrypted: its requests decide, the CONNECT does not.
        let decrypted = Facts {
            defer_content: true,
            ..tunnel
        };
        assert_eq!(
            decide(&decrypted, &block, Action::Allow).action,
            Action::Allow
        );
    }

    #[test]
    fn validation_names_the_rule() {
        let ok = rule("a", Action::Block, Match::default());
        assert_eq!(validate(std::slice::from_ref(&ok), Action::Allow), Ok(()));
        let duplicate = validate(&[ok.clone(), ok.clone()], Action::Allow).unwrap_err();
        assert!(duplicate.starts_with("rules[1].id"), "{duplicate}");
        let approve = validate(
            &[rule("x", Action::Approve, Match::default())],
            Action::Allow,
        )
        .unwrap_err();
        assert!(
            approve.contains("rules[0].action") && approve.contains("M3"),
            "{approve}"
        );
        assert!(
            validate(
                &[rule("default", Action::Block, Match::default())],
                Action::Allow
            )
            .is_err()
        );
        assert!(
            validate(&[], Action::Approve)
                .unwrap_err()
                .contains("general.default_action")
        );
    }

    #[test]
    fn parses_toml_and_rejects_unknown_keys() {
        #[derive(Deserialize)]
        struct File {
            rules: Vec<Rule>,
        }
        let file: File = toml::from_str(
            r#"
            [[rules]]
            id = "secret-in-body"
            match = { finding = "secret.*", not_host = ["llm.internal.example"] }
            action = "block"
            severity = "critical"
            "#,
        )
        .unwrap();
        assert_eq!(file.rules[0].matches.finding.as_deref(), Some("secret.*"));
        let unknown = toml::from_str::<File>(
            "[[rules]]\nid = \"x\"\nmatch = { hostt = [\"a\"] }\naction = \"block\"\nseverity = \"low\"\n",
        );
        assert!(unknown.err().unwrap().to_string().contains("hostt"));
    }
}
