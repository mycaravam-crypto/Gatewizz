//! Request inspection: buffers a request body before anything goes upstream, then reports what it contains as finding
//! kinds and counts. Matched text never leaves this module; only kinds, counts and an AI model name do.

use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use hyper::{Request, StatusCode};
use serde::{Deserialize, Serialize};

use crate::event::Coverage;

/// What to do with a body that cannot be fully inspected (too large or compressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverLimit {
    /// Fail closed: refuse the request before any byte goes upstream.
    #[default]
    Block,
    /// Forward it uninspected beyond the limit, recorded as `partially_inspected`.
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLimits {
    pub max_bytes: usize,
    pub over_limit: OverLimit,
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            over_limit: OverLimit::Block,
        }
    }
}

/// One kind of finding and how often it occurred. Never the matched text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub kind: &'static str,
    pub count: u32,
}

/// What inspection learned about a request; all of it is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    pub findings: Vec<Finding>,
    pub model: Option<String>,
    pub coverage: Coverage,
    /// Request body size when it was read in full.
    pub bytes_up: Option<u64>,
}

pub enum Inspected {
    /// Forward this request; its body is the buffered one (plus the unread rest when over the limit).
    Forward(Box<Request<BoxBody<Bytes, hyper::Error>>>, Inspection),
    /// Refuse it; nothing has gone upstream.
    Refuse(Inspection, StatusCode, &'static str),
}

/// Reads the body up to `limits.max_bytes` and inspects it. A body that is larger, or compressed, follows
/// `limits.over_limit`.
pub async fn inspect(req: Request<Incoming>, limits: &BodyLimits) -> Inspected {
    let (parts, mut body) = req.into_parts();
    let mut inspection = Inspection {
        findings: Vec::new(),
        model: None,
        coverage: Coverage::Inspected,
        bytes_up: None,
    };
    let refuse = |mut inspection: Inspection, status, reason| {
        inspection.coverage = Coverage::Blocked;
        Inspected::Refuse(inspection, status, reason)
    };

    // ponytail: compressed bodies are not decompressed; the wizz tools and common SDKs send them uncompressed. Add
    // decompression with ratio and size limits when a real client needs it.
    let compressed = parts
        .headers
        .get(CONTENT_ENCODING)
        .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
    let declared_too_large = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
        .is_some_and(|len| len > limits.max_bytes as u64);
    if compressed || declared_too_large {
        let reason = if compressed {
            "compressed body not inspected"
        } else {
            "body over inspection limit"
        };
        return match limits.over_limit {
            OverLimit::Block => refuse(inspection, StatusCode::PAYLOAD_TOO_LARGE, reason),
            OverLimit::Allow => {
                inspection.coverage = Coverage::PartiallyInspected;
                let body = Prefixed {
                    head: None,
                    rest: body,
                };
                Inspected::Forward(
                    Box::new(Request::from_parts(parts, body.boxed())),
                    inspection,
                )
            }
        };
    }

    let mut buffered = Vec::new();
    let mut over = false;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return refuse(
                inspection,
                StatusCode::BAD_REQUEST,
                "request body incomplete",
            );
        };
        // ponytail: request trailers are dropped; no known AI client sends them.
        if let Ok(data) = frame.into_data() {
            buffered.extend_from_slice(&data);
            if buffered.len() > limits.max_bytes {
                over = true;
                break;
            }
        }
    }
    if over {
        return match limits.over_limit {
            OverLimit::Block => refuse(
                inspection,
                StatusCode::PAYLOAD_TOO_LARGE,
                "body over inspection limit",
            ),
            OverLimit::Allow => {
                inspection.coverage = Coverage::PartiallyInspected;
                let body = Prefixed {
                    head: Some(Bytes::from(buffered)),
                    rest: body,
                };
                Inspected::Forward(
                    Box::new(Request::from_parts(parts, body.boxed())),
                    inspection,
                )
            }
        };
    }

    inspection.findings = scan_secrets(&buffered);
    inspection.model = ai_model(parts.method.as_str(), parts.uri.path(), &buffered);
    inspection.bytes_up = Some(buffered.len() as u64);
    let body = Full::new(Bytes::from(buffered))
        .map_err(|never| match never {})
        .boxed();
    Inspected::Forward(Box::new(Request::from_parts(parts, body)), inspection)
}

/// The bytes already read, followed by the rest of the client's body.
struct Prefixed {
    head: Option<Bytes>,
    rest: Incoming,
}

impl Body for Prefixed {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        if let Some(head) = self.head.take().filter(|h| !h.is_empty()) {
            return Poll::Ready(Some(Ok(Frame::data(head))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.head.as_ref().is_none_or(Bytes::is_empty) && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let head = self.head.as_ref().map_or(0, |h| h.len() as u64);
        let rest = self.rest.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(rest.lower() + head);
        if let Some(upper) = rest.upper() {
            hint.set_upper(upper + head);
        }
        hint
    }
}

/// A token format: one of `prefixes`, then a run of `min..=max` bytes accepted by `body`. The byte before the prefix
/// must not be a token byte, and a longer run is not this format.
struct Pattern {
    kind: &'static str,
    prefixes: &'static [&'static str],
    body: fn(u8) -> bool,
    min: usize,
    max: usize,
}

fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn upper_alnum(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn alnum_underscore(b: u8) -> bool {
    alnum(b) || b == b'_'
}
fn alnum_dash(b: u8) -> bool {
    alnum(b) || b == b'-'
}
fn base64url(b: u8) -> bool {
    alnum(b) || b == b'-' || b == b'_'
}

// Formats are the providers' documented token shapes; values in tests are clearly fake.
const PATTERNS: &[Pattern] = &[
    Pattern {
        kind: "secret.aws_access_key",
        prefixes: &["AKIA", "ASIA"],
        body: upper_alnum,
        min: 16,
        max: 16,
    },
    Pattern {
        kind: "secret.github_token",
        prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        body: alnum,
        min: 36,
        max: 36,
    },
    Pattern {
        kind: "secret.github_token",
        prefixes: &["github_pat_"],
        body: alnum_underscore,
        min: 82,
        max: 82,
    },
    Pattern {
        kind: "secret.slack_token",
        prefixes: &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"],
        body: alnum_dash,
        min: 10,
        max: 250,
    },
    Pattern {
        kind: "secret.anthropic_key",
        prefixes: &["sk-ant-"],
        body: base64url,
        min: 32,
        max: 250,
    },
    // Also covers `sk-proj-…` and `sk-svcacct-…`; `sk-ant-` is excluded in `count_pattern`.
    Pattern {
        kind: "secret.openai_key",
        prefixes: &["sk-"],
        body: base64url,
        min: 20,
        max: 250,
    },
    Pattern {
        kind: "secret.google_api_key",
        prefixes: &["AIza"],
        body: base64url,
        min: 35,
        max: 35,
    },
];

fn count_pattern(text: &[u8], p: &Pattern) -> u32 {
    let mut count = 0;
    for prefix in p.prefixes {
        let prefix = prefix.as_bytes();
        let mut from = 0;
        while let Some(at) = find(&text[from..], prefix).map(|i| i + from) {
            from = at + 1;
            if at > 0 && base64url(text[at - 1]) {
                continue;
            }
            let rest = &text[at + prefix.len()..];
            if p.kind == "secret.openai_key" && rest.starts_with(b"ant-") {
                continue;
            }
            let run = rest.iter().take_while(|&&b| (p.body)(b)).count();
            if (p.min..=p.max).contains(&run) {
                count += 1;
            }
        }
    }
    count
}

/// `-----BEGIN … PRIVATE KEY-----` (RSA, EC, OPENSSH, PKCS#8 and encrypted forms).
fn count_private_keys(text: &[u8]) -> u32 {
    let mut count = 0;
    let mut from = 0;
    while let Some(at) = find(&text[from..], b"-----BEGIN ").map(|i| i + from) {
        from = at + 1;
        let label = &text[at + 11..text.len().min(at + 11 + 40)];
        if let Some(end) = find(label, b"-----")
            && label[..end].ends_with(b"PRIVATE KEY")
        {
            count += 1;
        }
    }
    count
}

/// A JWT: three dot-separated base64url segments, the first two JSON objects (`eyJ`).
fn count_jwts(text: &[u8]) -> u32 {
    let mut count = 0;
    let mut from = 0;
    while let Some(at) = find(&text[from..], b"eyJ").map(|i| i + from) {
        from = at + 1;
        if at > 0 && (base64url(text[at - 1]) || text[at - 1] == b'.') {
            continue;
        }
        let mut segments = text[at..]
            .split(|&b| b == b'.')
            .take(3)
            .map(|s| s.iter().take_while(|&&b| base64url(b)).count());
        let (Some(a), Some(b), Some(c)) = (segments.next(), segments.next(), segments.next())
        else {
            continue;
        };
        // The header and payload segments must be whole; the signature may be followed by any delimiter.
        let header_len = text[at..].iter().position(|&b| b == b'.');
        let payload = &text[at + a + 1..];
        if header_len == Some(a)
            && a >= 10
            && b >= 10
            && c >= 10
            && payload.starts_with(b"eyJ")
            && payload.get(b) == Some(&b'.')
        {
            count += 1;
        }
    }
    count
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn scan_text(text: &[u8], totals: &mut Vec<Finding>) {
    let mut add = |kind: &'static str, n: u32| {
        if n == 0 {
            return;
        }
        match totals.iter_mut().find(|f| f.kind == kind) {
            Some(f) => f.count += n,
            None => totals.push(Finding { kind, count: n }),
        }
    };
    for p in PATTERNS {
        add(p.kind, count_pattern(text, p));
    }
    add("secret.private_key", count_private_keys(text));
    add("secret.jwt", count_jwts(text));
}

/// Secret kinds and counts in a body. A JSON body is scanned per decoded string (keys and values), so escapes such as
/// `\n` in an embedded diff cannot hide a key; anything else is scanned as raw bytes.
pub fn scan_secrets(body: &[u8]) -> Vec<Finding> {
    let mut totals = Vec::new();
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(json) => scan_json(&json, &mut totals),
        Err(_) => scan_text(body, &mut totals),
    }
    totals.sort_by_key(|f| f.kind);
    totals
}

fn scan_json(value: &serde_json::Value, totals: &mut Vec<Finding>) {
    match value {
        serde_json::Value::String(s) => scan_text(s.as_bytes(), totals),
        serde_json::Value::Array(items) => items.iter().for_each(|v| scan_json(v, totals)),
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                scan_text(key.as_bytes(), totals);
                scan_json(v, totals);
            }
        }
        _ => {}
    }
}

/// The model of an OpenAI-compatible chat or completions request, or `None` if this is not one. The name comes from
/// the client, so it is limited to a safe charset and length before it is logged.
pub fn ai_model(method: &str, path: &str, body: &[u8]) -> Option<String> {
    let endpoint = path.ends_with("/chat/completions") || path.ends_with("/completions");
    if method != "POST" || !endpoint {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    let shaped = json.get("messages").is_some_and(|m| m.is_array()) || json.get("prompt").is_some();
    if !shaped {
        return None;
    }
    let model = json.get("model").and_then(|m| m.as_str()).unwrap_or("");
    let safe = !model.is_empty()
        && model.len() <= 100
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
        && scan_secrets(model.as_bytes()).is_empty();
    Some(if safe {
        model.to_owned()
    } else {
        "invalid".to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clearly fake values, assembled at runtime so no token-shaped literal sits in the source.
    pub fn fake(prefix: &str, filler: char, len: usize) -> String {
        format!("{prefix}{}", filler.to_string().repeat(len))
    }

    fn kinds(body: &str) -> Vec<(&'static str, u32)> {
        scan_secrets(body.as_bytes())
            .into_iter()
            .map(|f| (f.kind, f.count))
            .collect()
    }

    fn found(body: &str, kind: &str) -> bool {
        kinds(body).iter().any(|(k, _)| *k == kind)
    }

    #[test]
    fn finds_each_kind_and_rejects_near_misses() {
        let cases: &[(&str, String, String)] = &[
            (
                "secret.aws_access_key",
                fake(&["AK", "IA"].concat(), 'X', 16),
                fake(&["AK", "IA"].concat(), 'X', 15),
            ),
            (
                "secret.github_token",
                fake(&["gh", "p_"].concat(), 'x', 36),
                fake(&["gh", "p_"].concat(), 'x', 35),
            ),
            (
                "secret.github_token",
                fake(&["github", "_pat_"].concat(), 'x', 82),
                fake(&["github", "_pat_"].concat(), 'x', 20),
            ),
            (
                "secret.slack_token",
                fake(&["xo", "xb-"].concat(), 'x', 24),
                fake(&["xo", "xb-"].concat(), 'x', 5),
            ),
            (
                "secret.anthropic_key",
                fake(&["sk", "-ant-"].concat(), 'x', 40),
                fake(&["sk", "-ant-"].concat(), 'x', 10),
            ),
            (
                "secret.openai_key",
                fake(&["sk", "-proj-"].concat(), 'x', 40),
                fake(&["sk", "-"].concat(), 'x', 10),
            ),
            (
                "secret.google_api_key",
                fake(&["AI", "za"].concat(), 'x', 35),
                fake(&["AI", "za"].concat(), 'x', 34),
            ),
            (
                "secret.private_key",
                ["-----BEGIN RSA ", "PRIVATE KEY-----\nxxxx"].concat(),
                ["-----BEGIN ", "PUBLIC KEY-----\nxxxx"].concat(),
            ),
            (
                "secret.jwt",
                [
                    "eyJ",
                    &"x".repeat(12),
                    ".eyJ",
                    &"x".repeat(12),
                    ".",
                    &"x".repeat(12),
                ]
                .concat(),
                [
                    "eyJ",
                    &"x".repeat(12),
                    ".notjson",
                    &"x".repeat(12),
                    ".",
                    &"x".repeat(12),
                ]
                .concat(),
            ),
        ];
        for (kind, hit, miss) in cases {
            let text = format!("key = \"{hit}\"\n");
            assert_eq!(kinds(&text), [(*kind, 1)], "{kind} in {text}");
            assert!(
                kinds(&format!("key = \"{miss}\"\n")).is_empty(),
                "{kind}: {miss}"
            );
        }
    }

    #[test]
    fn tokens_inside_longer_words_do_not_match() {
        let embedded = format!("task{}", fake("-", 'x', 30)); // "task-xxx…" contains "sk-"
        assert!(kinds(&embedded).is_empty());
        let longer = fake(&["gh", "p_"].concat(), 'x', 40);
        assert!(kinds(&longer).is_empty());
        // An Anthropic key is not also an OpenAI key.
        assert_eq!(
            kinds(&fake(&["sk", "-ant-"].concat(), 'x', 40)),
            [("secret.anthropic_key", 1)]
        );
    }

    #[test]
    fn counts_repeats() {
        let key = fake(&["gh", "p_"].concat(), 'x', 36);
        assert_eq!(
            kinds(&format!("{key} {key}\n{key}")),
            [("secret.github_token", 3)]
        );
    }

    #[test]
    fn finds_keys_in_json_escaped_diffs() {
        let key = fake(&["gh", "p_"].concat(), 'x', 36);
        // The key starts a diff line. In the raw JSON it follows the escape `\n`, so the byte before it is `n` and a
        // raw scan would take it for part of a longer word; only decoding finds it.
        let diff = format!("--- a/.env\n+++ b/.env\n{key}\n");
        let body = serde_json::json!({
            "model": "gpt-x",
            "messages": [{"role": "user", "content": diff}],
        })
        .to_string();
        assert!(body.contains(&format!("\\n{key}")), "{body}");
        let mut raw = Vec::new();
        scan_text(body.as_bytes(), &mut raw);
        assert!(raw.is_empty(), "the raw scan alone misses it");
        assert!(found(&body, "secret.github_token"), "{body}");

        let unicode_escaped = format!(
            "{{\"content\":\"x\\u000a{}\"}}",
            fake(&["AK", "IA"].concat(), 'X', 16)
        );
        assert!(found(&unicode_escaped, "secret.aws_access_key"));
    }

    #[test]
    fn non_json_bodies_are_scanned_raw() {
        let key = fake(&["sk", "-ant-"].concat(), 'x', 40);
        assert!(found(&format!("a=1&key={key}"), "secret.anthropic_key"));
        assert!(scan_secrets(b"").is_empty());
        assert!(scan_secrets(&[0xff, 0xfe, 0x00]).is_empty());
    }

    #[test]
    fn detects_openai_compatible_requests() {
        let chat = br#"{"model":"llama3.1:8b","messages":[{"role":"user","content":"hi"}]}"#;
        assert_eq!(
            ai_model("POST", "/v1/chat/completions", chat),
            Some("llama3.1:8b".into())
        );
        let completion = br#"{"model":"gpt-x","prompt":"hi"}"#;
        assert_eq!(
            ai_model("POST", "/v1/completions", completion),
            Some("gpt-x".into())
        );
        assert_eq!(ai_model("GET", "/v1/chat/completions", chat), None);
        assert_eq!(ai_model("POST", "/v1/embeddings", chat), None);
        assert_eq!(ai_model("POST", "/v1/chat/completions", b"{}"), None);
        assert_eq!(ai_model("POST", "/v1/chat/completions", b"not json"), None);
    }

    #[test]
    fn model_names_cannot_carry_content() {
        let key = fake(&["gh", "p_"].concat(), 'x', 36);
        for model in [
            format!("m {key}"),
            key.clone(),
            "x".repeat(101),
            String::new(),
        ] {
            let body = serde_json::json!({"model": model, "messages": []}).to_string();
            assert_eq!(
                ai_model("POST", "/v1/chat/completions", body.as_bytes()),
                Some("invalid".into())
            );
        }
    }
}
