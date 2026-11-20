//! TLS interception for CONNECT tunnels: the client's TLS is terminated with a leaf for the CONNECT host, the upstream
//! gets its own, independently verified TLS connection, and the HTTP/1.1 requests in between pass through the proxy's
//! normal request path.

use std::fmt;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::ResolvesServerCert;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ClientConfig, ServerConfig};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::ca::Ca;

/// Both sides speak HTTP/1.1 only; offering `h2` would let a client negotiate a protocol the proxy cannot read.
const ALPN_HTTP1: &[u8] = b"http/1.1";

/// Issues the leaf certificate presented to the client for a CONNECT host.
pub type LeafIssuer = dyn Fn(&str) -> Result<Arc<CertifiedKey>, String> + Send + Sync;

pub struct Interceptor {
    leaf: Box<LeafIssuer>,
    upstream: TlsConnector,
    /// Hosts passed through untouched (pinned or mutual-TLS endpoints): exact names or `*.suffix`.
    tunnel_hosts: Vec<String>,
}

impl fmt::Debug for Interceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interceptor")
            .field("tunnel_hosts", &self.tunnel_hosts)
            .finish_non_exhaustive()
    }
}

/// Why the upstream TLS connection was not established.
#[derive(Debug, PartialEq, Eq)]
pub enum UpstreamTlsFailure {
    /// The upstream's certificate did not verify: untrusted, expired, or for another name.
    Certificate,
    Handshake,
}

impl Interceptor {
    /// `upstream` decides which upstream certificates are trusted; production uses [`platform_upstream`].
    pub fn new(
        leaf: Box<LeafIssuer>,
        mut upstream: ClientConfig,
        tunnel_hosts: Vec<String>,
    ) -> Self {
        upstream.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
        Self {
            leaf,
            upstream: TlsConnector::from(Arc::new(upstream)),
            tunnel_hosts,
        }
    }

    /// Whether `host` keeps the blind M1 tunnel.
    pub fn tunnels(&self, host: &str) -> bool {
        self.tunnel_hosts
            .iter()
            .any(|pattern| host_matches(pattern, host))
    }

    /// The acceptor that presents `host`'s leaf to the client.
    pub fn acceptor(&self, host: &str) -> Result<TlsAcceptor, String> {
        let key = (self.leaf)(host)?;
        let resolver: Arc<dyn ResolvesServerCert> = Arc::new(SingleCertAndKey::from(key));
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|err| format!("TLS server config: {err}"))?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Completes the upstream TLS handshake for `host`, verifying its certificate.
    pub async fn connect(
        &self,
        tcp: TcpStream,
        host: &str,
    ) -> Result<TlsStream<TcpStream>, UpstreamTlsFailure> {
        let name =
            ServerName::try_from(host.to_string()).map_err(|_| UpstreamTlsFailure::Handshake)?;
        self.upstream.connect(name, tcp).await.map_err(|err| {
            let certificate = err
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .is_some_and(|tls| matches!(tls, rustls::Error::InvalidCertificate(_)));
            if certificate {
                UpstreamTlsFailure::Certificate
            } else {
                UpstreamTlsFailure::Handshake
            }
        })
    }
}

/// Leaves from the local CA, as rustls wants them. The CA caches the certificates; the signing key is parsed per
/// tunnel, which is cheap next to the handshake.
pub fn leaf_issuer(ca: Arc<Ca>) -> Box<LeafIssuer> {
    Box::new(move |host: &str| {
        let leaf = ca.leaf(host)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key.clone()));
        let signer = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|err| format!("[ca] unusable leaf key for {host:?}: {err}"))?;
        Ok(Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(leaf.cert.clone())],
            signer,
        )))
    })
}

/// Upstream TLS verified by the operating system's trust store (the Windows certificate store on Windows).
pub fn platform_upstream() -> Result<ClientConfig, String> {
    use rustls_platform_verifier::BuilderVerifierExt;
    Ok(ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("TLS client config: {err}"))?
        .with_platform_verifier()
        .map_err(|err| format!("platform certificate verifier: {err}"))?
        .with_no_client_auth())
}

/// `ring` explicitly, so no build pulls in a second crypto backend.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Exact, case-insensitive host match, or `*.suffix` for any subdomain of `suffix` (not `suffix` itself).
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.');
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len().checked_sub(suffix.len() + 1).is_some_and(|dot| {
            host.as_bytes()[dot] == b'.' && host[dot + 1..].eq_ignore_ascii_case(suffix)
        }),
        None => host.eq_ignore_ascii_case(pattern),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_platform_verifier() {
        let config = platform_upstream().expect("platform trust store available");
        assert!(
            config.alpn_protocols.is_empty(),
            "ALPN is set by Interceptor::new"
        );
    }

    use std::net::SocketAddr;
    use std::time::Duration;

    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::{Request, Response, header};
    use hyper_util::rt::TokioIo;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use rustls::RootCertStore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use crate::event::{Coverage, Event};
    use crate::proxy::{Settings, serve};

    struct TestCa {
        cert: CertificateDer<'static>,
        issuer: Issuer<'static, KeyPair>,
    }

    fn test_ca(name: &str) -> TestCa {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap().der().clone();
        TestCa {
            cert,
            issuer: Issuer::new(params, key),
        }
    }

    fn leaf(ca: &TestCa, host: &str) -> Arc<CertifiedKey> {
        leaf_for(ca, &[host])
    }

    fn leaf_for(ca: &TestCa, hosts: &[&str]) -> Arc<CertifiedKey> {
        let key = KeyPair::generate().unwrap();
        let names: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
        let cert = CertificateParams::new(names)
            .unwrap()
            .signed_by(&key, &ca.issuer)
            .unwrap();
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signer = rustls::crypto::ring::sign::any_supported_type(&der).unwrap();
        Arc::new(CertifiedKey::new(vec![cert.der().clone()], signer))
    }

    fn trusting(ca: &TestCa) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert.clone()).unwrap();
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    /// A TLS upstream presenting `cert`; it answers `<method> <path> <body bytes>` and reports each request line.
    /// With `close`, every response ends the connection.
    async fn upstream(cert: Arc<CertifiedKey>, close: bool) -> (u16, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(cert)));
        config.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (seen, received) = mpsc::channel(16);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, seen) = (acceptor.clone(), seen.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let line = format!("{} {}", req.method(), req.uri());
                            let host = req.headers().get(header::HOST).cloned();
                            let body = req.into_body().collect().await?.to_bytes();
                            let _ = seen.send(format!("{line} host={host:?}")).await;
                            let mut response = Response::new(Full::new(Bytes::from(format!(
                                "{line} {}",
                                body.len()
                            ))));
                            if close {
                                response
                                    .headers_mut()
                                    .insert(header::CONNECTION, "close".parse().unwrap());
                            }
                            Ok::<_, hyper::Error>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        (port, received)
    }

    /// A proxy that decrypts with `gatewizz` and trusts upstreams signed by `trusted`.
    async fn proxy(
        gatewizz: Arc<TestCa>,
        trusted: &TestCa,
        port: u16,
        tunnel_hosts: Vec<String>,
    ) -> (SocketAddr, mpsc::Receiver<Event>) {
        let interceptor = Interceptor::new(
            Box::new(move |host: &str| Ok(leaf(&gatewizz, host))),
            trusting(trusted),
            tunnel_hosts,
        );
        let settings = Settings {
            allowed_connect_ports: vec![port],
            tls: Some(Arc::new(interceptor)),
            ..Settings::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (events, received) = mpsc::channel(16);
        tokio::spawn(serve(listener, settings, events, std::future::pending()));
        (addr, received)
    }

    /// Sends `CONNECT localhost:<port>` and returns the stream plus the proxy's status line.
    async fn connect(proxy: SocketAddr, port: u16) -> (tokio::net::TcpStream, String) {
        connect_to(proxy, "localhost", port).await
    }

    async fn connect_to(
        proxy: SocketAddr,
        host: &str,
        port: u16,
    ) -> (tokio::net::TcpStream, String) {
        let mut tcp = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
        tcp.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            if tcp.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        (tcp, head.lines().next().unwrap_or_default().to_string())
    }

    /// TLS to "localhost" over the tunnel, offering h2 as well, and an HTTP/1.1 client on top.
    async fn handshake(
        tcp: tokio::net::TcpStream,
        trust: &TestCa,
    ) -> Result<
        (
            hyper::client::conn::http1::SendRequest<Full<Bytes>>,
            Option<Vec<u8>>,
        ),
        std::io::Error,
    > {
        handshake_as(tcp, trust, "localhost").await
    }

    async fn handshake_as(
        tcp: tokio::net::TcpStream,
        trust: &TestCa,
        name: &str,
    ) -> Result<
        (
            hyper::client::conn::http1::SendRequest<Full<Bytes>>,
            Option<Vec<u8>>,
        ),
        std::io::Error,
    > {
        let mut config = trusting(trust);
        config.alpn_protocols = vec![b"h2".to_vec(), ALPN_HTTP1.to_vec()];
        let name = ServerName::try_from(name.to_string()).unwrap();
        let tls = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await?;
        let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        Ok((sender, alpn))
    }

    async fn send(
        sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        method: &str,
        path: &str,
        host: &str,
        body: &'static str,
    ) -> (u16, String) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, host)
            .body(Full::new(Bytes::from_static(body.as_bytes())))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        let status = response.status().as_u16();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn next(events: &mut mpsc::Receiver<Event>) -> Event {
        timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap()
    }

    /// Every file below `dir`, rotated events and CA files included.
    fn files_below(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.extend(files_below(&path));
            } else {
                files.push(path);
            }
        }
        files
    }

    /// M2 acceptance (#22): an OpenAI-compatible chat request whose diff holds a fake API key is decrypted with the
    /// local CA, blocked with a 403 naming the allowlist rule for a host outside the allowlist, with nothing sent
    /// upstream, and passed for the allowlisted host. Afterwards no file the run wrote contains the key.
    #[tokio::test]
    async fn m2_secret_reaches_only_the_allowlisted_model_host() {
        use crate::config::EventTarget;
        use crate::rules::{Action, Match, Rule, Severity};

        let dir = std::env::temp_dir().join(format!("gatewizz-m2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // The local CA as `gatewizz ca install` creates it; on Windows it is also stored (DPAPI) under `dir`.
        let ca = Arc::new(Ca::generate().unwrap());
        #[cfg(windows)]
        ca.save(&dir).unwrap();
        let client_trust = TestCa {
            cert: CertificateDer::from(ca.cert().to_vec()),
            issuer: Issuer::new(CertificateParams::default(), KeyPair::generate().unwrap()),
        };
        // One model upstream that answers as "localhost" (allowlisted) and as "127.0.0.1" (not allowlisted).
        let origin = test_ca("model host");
        let (port, mut seen) =
            upstream(leaf_for(&origin, &["localhost", "127.0.0.1"]), false).await;

        // Small files, so the run rotates the event log and the scan covers rotated files too.
        let (events, writer) =
            crate::event::spawn(EventTarget::File(dir.join("events.jsonl")), 4096, 3, 64).unwrap();
        let settings = Settings {
            allowed_connect_ports: vec![port],
            tls: Some(Arc::new(Interceptor::new(
                leaf_issuer(ca),
                trusting(&origin),
                Vec::new(),
            ))),
            // The README's allowlist: secrets go only to the approved model host.
            rules: vec![Rule {
                id: "secrets-only-to-approved-models".into(),
                description: "Secrets may only be sent to the approved model host".into(),
                matches: Match {
                    finding: Some("secret.*".into()),
                    not_host: Some(vec!["localhost".into()]),
                    ..Match::default()
                },
                action: Action::Block,
                severity: Severity::Critical,
            }],
            ..Settings::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, settings, events, std::future::pending()));

        // A clearly fake GitHub token in a diff, as a review tool would send it; JSON-escaped newlines included.
        let key = format!(
            "{}a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
            ["gh", "p_"].concat()
        );
        let body: &'static str = Box::leak(
            serde_json::json!({
                "model": "gpt-test",
                "messages": [{
                    "role": "user",
                    "content": format!("Review this diff:\n+const TOKEN = \"{key}\";\n")
                }]
            })
            .to_string()
            .into_boxed_str(),
        );
        let path = "/v1/chat/completions";

        // Not allowlisted: 403 naming the rule, and the upstream sees no request.
        let (tcp, status) = connect_to(proxy, "127.0.0.1", port).await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        let (mut sender, _) = handshake_as(tcp, &client_trust, "127.0.0.1").await.unwrap();
        let (status, text) = send(
            &mut sender,
            "POST",
            path,
            &format!("127.0.0.1:{port}"),
            body,
        )
        .await;
        assert_eq!(status, 403, "{text}");
        assert!(
            text.contains("blocked by rule \"secrets-only-to-approved-models\" (critical)"),
            "{text}"
        );
        assert!(
            timeout(Duration::from_millis(300), seen.recv())
                .await
                .is_err(),
            "the blocked request must not reach the upstream"
        );

        // Allowlisted: passes, decrypted and inspected. Several requests so the event log rotates.
        let (tcp, status) = connect(proxy, port).await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        let (mut sender, _) = handshake(tcp, &client_trust).await.unwrap();
        let allowed = 16;
        for _ in 0..allowed {
            let (status, text) = send(
                &mut sender,
                "POST",
                path,
                &format!("localhost:{port}"),
                body,
            )
            .await;
            assert_eq!(status, 200, "{text}");
            assert!(
                seen.recv()
                    .await
                    .unwrap()
                    .starts_with("POST /v1/chat/completions")
            );
        }

        // Events are written one unbuffered line at a time; wait until all are on disk.
        let lines = || -> Vec<serde_json::Value> {
            let mut files: Vec<_> = files_below(&dir)
                .into_iter()
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("events.jsonl")
                })
                .collect();
            files.sort();
            files
                .iter()
                .flat_map(|p| {
                    std::fs::read_to_string(p)
                        .unwrap_or_default()
                        .lines()
                        .map(String::from)
                        .collect::<Vec<_>>()
                })
                .filter_map(|line| serde_json::from_str(&line).ok())
                .collect()
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while lines().len() < 1 + allowed && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let events = lines();
        assert_eq!(events.len(), 1 + allowed, "{events:?}");
        assert!(
            dir.join("events.jsonl.1").exists(),
            "the run must rotate the log"
        );

        let blocked = events.iter().find(|e| e["status"] == 403).unwrap();
        assert_eq!(blocked["host"], "127.0.0.1");
        assert_eq!(blocked["rule"], "secrets-only-to-approved-models");
        assert_eq!(blocked["coverage"], "blocked");
        assert_eq!(blocked["model"], "gpt-test");
        assert_eq!(blocked["findings"][0]["kind"], "secret.github_token");
        let passed: Vec<_> = events.iter().filter(|e| e["status"] == 200).collect();
        assert_eq!(passed.len(), allowed);
        assert!(passed.iter().all(|e| e["host"] == "localhost"
            && e["coverage"] == "inspected"
            && e["findings"][0]["kind"] == "secret.github_token"));

        // The key appears nowhere on disk: not in events, rotated events or CA files.
        let files = files_below(&dir);
        assert!(files.len() >= 2, "{files:?}");
        for file in &files {
            let bytes = std::fs::read(file).unwrap();
            for needle in [key.as_bytes(), &key.as_bytes()[4..]] {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle),
                    "{} holds the key",
                    file.display()
                );
            }
        }
        drop(writer);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn decrypts_requests_and_keeps_the_tunnel_alive() {
        let (gatewizz, origin) = (Arc::new(test_ca("gatewizz test")), test_ca("origin test"));
        let (port, mut seen) = upstream(leaf(&origin, "localhost"), false).await;
        let (proxy, mut events) = proxy(gatewizz.clone(), &origin, port, Vec::new()).await;

        let (tcp, status) = connect(proxy, port).await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        let (mut sender, alpn) = handshake(tcp, &gatewizz).await.unwrap();
        assert_eq!(
            alpn.as_deref(),
            Some(ALPN_HTTP1),
            "h2 must never be negotiated"
        );
        let host = format!("localhost:{port}");

        let (status, body) = send(&mut sender, "GET", "/one?token=x", &host, "").await;
        assert_eq!((status, body.as_str()), (200, "GET /one?token=x 0"));
        let (status, body) = send(&mut sender, "POST", "/two", &host, "hello").await;
        assert_eq!((status, body.as_str()), (200, "POST /two 5"));

        assert!(seen.recv().await.unwrap().starts_with("GET /one?token=x"));
        assert!(seen.recv().await.unwrap().starts_with("POST /two"));
        for (method, path) in [("GET", "/one"), ("POST", "/two")] {
            let event = next(&mut events).await;
            assert_eq!((event.method.as_str(), event.path.as_str()), (method, path));
            assert_eq!((event.host.as_str(), event.status), ("localhost", 200));
            assert_eq!(event.coverage, Coverage::Inspected);
        }
    }

    #[tokio::test]
    async fn leaves_from_the_local_ca_are_accepted() {
        let ca = Arc::new(Ca::generate().unwrap());
        let gatewizz = TestCa {
            cert: CertificateDer::from(ca.cert().to_vec()),
            issuer: Issuer::new(CertificateParams::default(), KeyPair::generate().unwrap()),
        };
        let origin = test_ca("origin test");
        let (port, _seen) = upstream(leaf(&origin, "localhost"), false).await;
        let interceptor = Interceptor::new(leaf_issuer(ca), trusting(&origin), Vec::new());
        let settings = Settings {
            allowed_connect_ports: vec![port],
            tls: Some(Arc::new(interceptor)),
            ..Settings::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (events, _received) = mpsc::channel(16);
        tokio::spawn(serve(listener, settings, events, std::future::pending()));

        let (tcp, status) = connect(addr, port).await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        // A client trusting only the local CA's certificate accepts the leaf it issued.
        let (mut sender, _) = handshake(tcp, &gatewizz).await.unwrap();
        let (status, body) =
            send(&mut sender, "GET", "/ok", &format!("localhost:{port}"), "").await;
        assert_eq!((status, body.as_str()), (200, "GET /ok 0"));
    }

    #[tokio::test]
    async fn rules_decide_each_decrypted_request() {
        use crate::rules::{Action, Match, Rule, Severity};
        let (gatewizz, origin) = (Arc::new(test_ca("gatewizz test")), test_ca("origin test"));
        let (port, mut seen) = upstream(leaf(&origin, "localhost"), false).await;
        let interceptor = {
            let gatewizz = gatewizz.clone();
            Interceptor::new(
                Box::new(move |host: &str| Ok(leaf(&gatewizz, host))),
                trusting(&origin),
                Vec::new(),
            )
        };
        let settings = Settings {
            allowed_connect_ports: vec![port],
            tls: Some(Arc::new(interceptor)),
            rules: vec![Rule {
                id: "no-admin".into(),
                description: String::new(),
                matches: Match {
                    path_prefix: Some("/admin".into()),
                    ..Match::default()
                },
                action: Action::Block,
                severity: Severity::Medium,
            }],
            ..Settings::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (events, mut received) = mpsc::channel(16);
        tokio::spawn(serve(listener, settings, events, std::future::pending()));

        // The CONNECT carries no path, so the path rule waits for the requests inside.
        let (tcp, status) = connect(addr, port).await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        let (mut sender, _) = handshake(tcp, &gatewizz).await.unwrap();
        let host = format!("localhost:{port}");
        assert_eq!(send(&mut sender, "GET", "/public", &host, "").await.0, 200);
        let (status, body) = send(&mut sender, "GET", "/admin/users", &host, "").await;
        assert_eq!(status, 403);
        assert!(body.contains("no-admin"), "{body}");

        assert!(seen.recv().await.unwrap().starts_with("GET /public"));
        assert!(
            timeout(Duration::from_millis(200), seen.recv())
                .await
                .is_err()
        );
        assert_eq!(next(&mut received).await.rule.as_deref(), Some("default"));
        let blocked = next(&mut received).await;
        assert_eq!(
            (blocked.path.as_str(), blocked.rule.as_deref()),
            ("/admin/users", Some("no-admin"))
        );
    }

    #[tokio::test]
    async fn refuses_untrusted_and_wrong_host_upstreams() {
        let (gatewizz, origin) = (Arc::new(test_ca("gatewizz test")), test_ca("origin test"));
        let rogue = test_ca("rogue test");
        for cert in [leaf(&rogue, "localhost"), leaf(&origin, "other.example")] {
            let (port, mut seen) = upstream(cert, false).await;
            let (proxy, mut events) = proxy(gatewizz.clone(), &origin, port, Vec::new()).await;
            let (_tcp, status) = connect(proxy, port).await;
            assert!(status.starts_with("HTTP/1.1 502"), "{status}");
            let event = next(&mut events).await;
            assert_eq!(event.reason, Some("upstream certificate rejected"));
            assert_eq!(event.coverage, Coverage::Blocked);
            assert!(
                timeout(Duration::from_millis(200), seen.recv())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn tunnel_hosts_keep_the_blind_tunnel() {
        let (gatewizz, origin) = (Arc::new(test_ca("gatewizz test")), test_ca("origin test"));
        let (port, _seen) = upstream(leaf(&origin, "localhost"), false).await;
        let (proxy, mut events) =
            proxy(gatewizz, &origin, port, vec!["localhost".to_string()]).await;
        let (tcp, status) = connect(proxy, port).await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        // The client sees the origin's own certificate: nothing in between.
        let (mut sender, _) = handshake(tcp, &origin).await.unwrap();
        let (status, _) = send(&mut sender, "GET", "/", &format!("localhost:{port}"), "").await;
        assert_eq!(status, 200);
        drop(sender);
        assert_eq!(next(&mut events).await.coverage, Coverage::Tunneled);
    }

    #[tokio::test]
    async fn records_clients_that_reject_the_leaf() {
        let (gatewizz, origin) = (Arc::new(test_ca("gatewizz test")), test_ca("origin test"));
        let (port, _seen) = upstream(leaf(&origin, "localhost"), false).await;
        let (proxy, mut events) = proxy(gatewizz, &origin, port, Vec::new()).await;
        let (tcp, _) = connect(proxy, port).await;
        // A pinning client: it trusts only the origin, so the gatewizz leaf fails.
        assert!(handshake(tcp, &origin).await.is_err());
        let event = next(&mut events).await;
        assert_eq!(
            event.reason,
            Some("client rejected the gatewizz certificate")
        );
    }

    #[tokio::test]
    async fn refuses_a_host_header_for_another_site() {
        let (gatewizz, origin) = (Arc::new(test_ca("gatewizz test")), test_ca("origin test"));
        let (port, mut seen) = upstream(leaf(&origin, "localhost"), false).await;
        let (proxy, mut events) = proxy(gatewizz.clone(), &origin, port, Vec::new()).await;
        let (tcp, _) = connect(proxy, port).await;
        let (mut sender, _) = handshake(tcp, &gatewizz).await.unwrap();
        let (status, _) = send(&mut sender, "GET", "/", "evil.example", "").await;
        assert_eq!(status, 421);
        let event = next(&mut events).await;
        assert_eq!(event.reason, Some("Host header does not match the tunnel"));
        assert!(
            timeout(Duration::from_millis(200), seen.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn reconnects_when_the_upstream_closed_between_requests() {
        let (gatewizz, origin) = (Arc::new(test_ca("gatewizz test")), test_ca("origin test"));
        let (port, _seen) = upstream(leaf(&origin, "localhost"), true).await;
        let (proxy, _events) = proxy(gatewizz.clone(), &origin, port, Vec::new()).await;
        let (tcp, _) = connect(proxy, port).await;
        let (mut sender, _) = handshake(tcp, &gatewizz).await.unwrap();
        let host = format!("localhost:{port}");
        for path in ["/first", "/second"] {
            let (status, body) = send(&mut sender, "GET", path, &host, "").await;
            assert_eq!((status, body), (200, format!("GET {path} 0")));
        }
    }

    #[test]
    fn matches_exact_hosts_and_subdomain_wildcards() {
        assert!(host_matches("api.example.com", "API.example.com"));
        assert!(host_matches("api.example.com", "api.example.com."));
        assert!(!host_matches("api.example.com", "example.com"));
        assert!(host_matches("*.example.com", "a.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "badexample.com"));
        assert!(!host_matches("*.example.com", "com"));
    }
}
