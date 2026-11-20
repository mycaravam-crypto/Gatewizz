//! Explicit HTTP/1.1 forward proxy: plain HTTP forwarding, CONNECT tunnels and, with a CA, TLS interception of
//! CONNECT tunnels (see `tls.rs`).
//!
//! Bodies are streamed, never buffered; the proxy never retries and never follows redirects.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::timeout;

use crate::event::{self, Coverage, Event};
use crate::process::{self, Process};
use crate::tls::{self, Interceptor};

type Body = BoxBody<Bytes, hyper::Error>;

/// Hop-by-hop headers (RFC 9110 §7.6.1) plus the proxy-only ones; never forwarded in either direction.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

#[derive(Debug, Clone)]
pub struct Settings {
    pub allowed_connect_ports: Vec<u16>,
    pub max_connections: usize,
    /// Largest request head (start line plus headers) accepted; larger heads get 431.
    pub max_header_bytes: usize,
    /// DNS lookup plus TCP connect to the upstream.
    pub connect_timeout: Duration,
    /// A client must send a complete request head within this time, also between keep-alive requests.
    pub header_timeout: Duration,
    /// The upstream must answer with response headers within this time.
    pub response_timeout: Duration,
    /// A tunnel with no bytes in either direction for this long is closed.
    pub idle_timeout: Duration,
    /// On shutdown, in-flight requests get this long to finish.
    pub shutdown_timeout: Duration,
    /// CONNECT hosts that keep the blind tunnel even when TLS interception is on (pinned or mTLS endpoints).
    pub tunnel_hosts: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allowed_connect_ports: vec![443],
            max_connections: 512,
            max_header_bytes: 64 * 1024,
            connect_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(30),
            response_timeout: Duration::from_secs(120),
            idle_timeout: Duration::from_secs(300),
            shutdown_timeout: Duration::from_secs(10),
            tunnel_hosts: Vec::new(),
        }
    }
}

impl Event {
    fn rejected_by_parser(
        client: SocketAddr,
        process: Process,
        status: StatusCode,
        reason: &'static str,
    ) -> Self {
        Self {
            time: event::now(),
            client,
            process,
            method: String::new(),
            host: String::new(),
            port: 0,
            path: String::new(),
            coverage: Coverage::Blocked,
            status: status.as_u16(),
            reason: Some(reason),
            bytes_up: None,
            bytes_down: None,
        }
    }
}

struct Ctx {
    settings: Settings,
    listen: SocketAddr,
    events: mpsc::Sender<Event>,
    /// TLS interception; without a CA every CONNECT is a blind tunnel.
    tls: Option<Arc<Interceptor>>,
}

impl Ctx {
    /// Waits when the event queue is full: events are never dropped.
    async fn emit(&self, event: Event) {
        // A closed receiver means shutdown; nothing is left to record to.
        let _ = self.events.send(event).await;
    }
}

/// Accepts connections until `shutdown` completes, each served on its own task. Then it stops accepting, asks every
/// connection to finish its in-flight request and close, and returns once all have, or after `shutdown_timeout`.
// ponytail: CONNECT tunnels run detached after the upgrade and are not drained; they end with the runtime.
pub async fn serve(
    listener: TcpListener,
    settings: Settings,
    tls: Option<Arc<Interceptor>>,
    events: mpsc::Sender<Event>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let listen = listener.local_addr()?;
    let max = settings.max_connections;
    let limit = Arc::new(Semaphore::new(max));
    let (stop, stopping) = watch::channel(false);
    let ctx = Arc::new(Ctx {
        settings,
        listen,
        events,
        tls,
    });
    tokio::pin!(shutdown);
    loop {
        let (stream, client) = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    // Out of file handles and similar: back off instead of spinning, keep serving.
                    eprintln!("gatewizz: accept failed: {err}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        // ponytail: over the limit the connection is closed without a response; queueing would hide overload.
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let ctx = ctx.clone();
        let mut stopping = stopping.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Attribute once per connection, at accept: the client's socket row exists only while it is connected.
            // The IP Helper and process queries block, so they run off the async workers.
            let process =
                tokio::task::spawn_blocking(move || process::client_process(client, listen))
                    .await
                    .unwrap_or(Process::Unknown("lookup panicked"));
            let svc_ctx = ctx.clone();
            let svc_process = process.clone();
            let svc =
                service_fn(move |req| handle(svc_ctx.clone(), client, svc_process.clone(), req));
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(ctx.settings.header_timeout)
                .max_header_size(ctx.settings.max_header_bytes)
                .serve_connection(TokioIo::new(stream), svc)
                .with_upgrades();
            tokio::pin!(conn);
            let result = tokio::select! {
                result = conn.as_mut() => result,
                () = async { let _ = stopping.wait_for(|stop| *stop).await; } => {
                    // Finish the request in flight, then close instead of waiting for the next one.
                    conn.as_mut().graceful_shutdown();
                    conn.await
                }
            };
            // hyper answers malformed requests itself (400, 431) before any handler runs, so record them here.
            // Client resets and idle keep-alive timeouts are normal ends and are not recorded.
            if let Err(err) = result
                && let Some((status, reason)) = malformed(&err)
            {
                ctx.emit(Event::rejected_by_parser(client, process, status, reason))
                    .await;
            }
        });
    }
    drop(listener);
    let _ = stop.send(true);
    // Every connection holds a permit until it ends, so holding all of them means none is left.
    let drained = timeout(
        ctx.settings.shutdown_timeout,
        limit.acquire_many(max as u32),
    )
    .await;
    if drained.is_err() {
        eprintln!("gatewizz: shutdown deadline reached with requests still in flight");
    }
    Ok(())
}

async fn handle(
    ctx: Arc<Ctx>,
    client: SocketAddr,
    process: Process,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    Ok(if req.method() == Method::CONNECT {
        tunnel(ctx, client, process, req).await
    } else {
        forward(&ctx, client, process, req).await
    })
}

async fn forward(
    ctx: &Ctx,
    client: SocketAddr,
    process: Process,
    mut req: Request<Incoming>,
) -> Response<Body> {
    let mut event = Event {
        time: event::now(),
        client,
        process,
        method: req.method().to_string(),
        host: req.uri().host().unwrap_or_default().to_string(),
        port: req.uri().port_u16().unwrap_or(80),
        path: req.uri().path().to_string(),
        coverage: Coverage::Blocked,
        status: 0,
        reason: None,
        bytes_up: None,
        bytes_down: None,
    };
    let Some((host, port)) = http_target(req.uri()) else {
        return refuse(
            ctx,
            event,
            StatusCode::BAD_REQUEST,
            "absolute http:// URI required",
        )
        .await;
    };
    let upstream = match connect_upstream(ctx, &host, port).await {
        Ok(stream) => stream,
        Err(failure) => return refuse(ctx, event, failure.status(), failure.reason()).await,
    };
    event.coverage = Coverage::PartiallyInspected;
    let authority = req.uri().authority().map(|a| a.as_str().to_string());
    to_origin_form(&mut req, authority);
    relay(ctx, event, req, upstream).await
}

/// Rewrites the target to origin form (`/path?query`) and sets `Host` from `authority` when the client sent none.
fn to_origin_form(req: &mut Request<Incoming>, authority: Option<String>) {
    let origin_form = req
        .uri()
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .parse::<Uri>()
        .unwrap_or_else(|_| Uri::from_static("/"));
    *req.uri_mut() = origin_form;
    if !req.headers().contains_key(header::HOST)
        && let Some(value) = authority.and_then(|a| HeaderValue::from_str(&a).ok())
    {
        req.headers_mut().insert(header::HOST, value);
    }
}

/// Sends one request over a fresh upstream connection and streams the response back.
async fn relay<S>(
    ctx: &Ctx,
    mut event: Event,
    mut req: Request<Incoming>,
    upstream: S,
) -> Response<Body>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    strip_hop_by_hop(req.headers_mut());
    // hyper already answered `100 Continue` to the client when it read the body.
    req.headers_mut().remove(header::EXPECT);

    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await {
            Ok(pair) => pair,
            Err(_) => {
                return refuse(
                    ctx,
                    event,
                    StatusCode::BAD_GATEWAY,
                    "upstream handshake failed",
                )
                .await;
            }
        };
    // Ends when the response body is consumed or dropped (client gone).
    tokio::spawn(conn);
    // ponytail: one upstream connection per request, no pooling; add a pool if the latency budget needs it.
    let response = match timeout(ctx.settings.response_timeout, sender.send_request(req)).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => return refuse(ctx, event, StatusCode::BAD_GATEWAY, "upstream failed").await,
        Err(_) => {
            return refuse(
                ctx,
                event,
                StatusCode::GATEWAY_TIMEOUT,
                "upstream response timeout",
            )
            .await;
        }
    };
    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    event.status = parts.status.as_u16();
    ctx.emit(event).await;
    Response::from_parts(parts, body.boxed())
}

async fn tunnel(
    ctx: Arc<Ctx>,
    client: SocketAddr,
    process: Process,
    req: Request<Incoming>,
) -> Response<Body> {
    let mut event = Event {
        time: event::now(),
        client,
        process,
        method: Method::CONNECT.to_string(),
        host: req.uri().host().unwrap_or_default().to_string(),
        port: req.uri().port_u16().unwrap_or(0),
        path: String::new(),
        coverage: Coverage::Blocked,
        status: 0,
        reason: None,
        bytes_up: None,
        bytes_down: None,
    };
    let (Some(host), Some(port)) = (req.uri().host(), req.uri().port_u16()) else {
        return refuse(
            &ctx,
            event,
            StatusCode::BAD_REQUEST,
            "CONNECT needs host:port",
        )
        .await;
    };
    if !ctx.settings.allowed_connect_ports.contains(&port) {
        return refuse(
            &ctx,
            event,
            StatusCode::FORBIDDEN,
            "CONNECT port not allowed",
        )
        .await;
    }
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if let Some(tls) = ctx.tls.clone()
        && !ctx
            .settings
            .tunnel_hosts
            .iter()
            .any(|pattern| tls::host_matches(pattern, &host))
    {
        return intercept(ctx, tls, req, host, port, event).await;
    }
    let upstream = match connect_upstream(&ctx, &host, port).await {
        Ok(stream) => stream,
        Err(failure) => return refuse(&ctx, event, failure.status(), failure.reason()).await,
    };
    event.coverage = Coverage::Tunneled;
    event.status = StatusCode::OK.as_u16();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let (up, down) =
                    pipe(TokioIo::new(upgraded), upstream, ctx.settings.idle_timeout).await;
                event.bytes_up = Some(up);
                event.bytes_down = Some(down);
            }
            Err(_) => event.reason = Some("client left before the tunnel opened"),
        }
        ctx.emit(event).await;
    });
    Response::new(Empty::new().map_err(|never| match never {}).boxed())
}

/// Answers the CONNECT, terminates the client's TLS and serves the decrypted requests, each inspected and sent upstream
/// over gatewizz's own TLS connection. A successful tunnel records one event per request, not one for itself.
// ponytail: intercepted tunnels run detached like blind ones and are not drained on shutdown.
async fn intercept(
    ctx: Arc<Ctx>,
    tls: Arc<Interceptor>,
    req: Request<Incoming>,
    host: String,
    port: u16,
    mut event: Event,
) -> Response<Body> {
    // Loops and unknown hosts are refused at CONNECT; each request inside connects on its own.
    let resolved = timeout(ctx.settings.connect_timeout, resolve(&ctx, &host, port))
        .await
        .unwrap_or(Err(UpstreamFailure::Timeout));
    if let Err(failure) = resolved {
        return refuse(&ctx, event, failure.status(), failure.reason()).await;
    }
    event.status = StatusCode::OK.as_u16();
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(req).await else {
            event.reason = Some("client left before the tunnel opened");
            ctx.emit(event).await;
            return;
        };
        let accepted = timeout(
            ctx.settings.header_timeout,
            tls.accept(&host, TokioIo::new(upgraded)),
        )
        .await
        .unwrap_or(Err("client TLS handshake timeout"));
        let stream = match accepted {
            Ok(stream) => stream,
            Err(reason) => {
                // Pinning or a client trust store without the gatewizz CA: recorded, never tunneled instead.
                event.reason = Some(reason);
                ctx.emit(event).await;
                return;
            }
        };
        let (client, process) = (event.client, event.process.clone());
        let svc_ctx = ctx.clone();
        let svc = service_fn(move |req| {
            inspect(
                svc_ctx.clone(),
                tls.clone(),
                client,
                process.clone(),
                host.clone(),
                port,
                req,
            )
        });
        let served = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(ctx.settings.header_timeout)
            .max_header_size(ctx.settings.max_header_bytes)
            .serve_connection(TokioIo::new(stream), svc)
            .await;
        if let Err(err) = served
            && let Some((status, reason)) = malformed(&err)
        {
            let mut rejected = Event::rejected_by_parser(client, event.process, status, reason);
            (rejected.host, rejected.port) = (event.host, port);
            ctx.emit(rejected).await;
        }
    });
    Response::new(Empty::new().map_err(|never| match never {}).boxed())
}

/// One decrypted request: sent to the CONNECT host, whatever the request line or `Host` header name.
async fn inspect(
    ctx: Arc<Ctx>,
    tls: Arc<Interceptor>,
    client: SocketAddr,
    process: Process,
    host: String,
    port: u16,
    mut req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let mut event = Event {
        time: event::now(),
        client,
        process,
        method: req.method().to_string(),
        host: host.clone(),
        port,
        path: req.uri().path().to_string(),
        coverage: Coverage::Blocked,
        status: 0,
        reason: None,
        bytes_up: None,
        bytes_down: None,
    };
    let tcp = match connect_upstream(&ctx, &host, port).await {
        Ok(stream) => stream,
        Err(failure) => return Ok(refuse(&ctx, event, failure.status(), failure.reason()).await),
    };
    let upstream = match timeout(ctx.settings.connect_timeout, tls.connect(&host, tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(reason)) => return Ok(refuse(&ctx, event, StatusCode::BAD_GATEWAY, reason).await),
        Err(_) => {
            return Ok(refuse(
                &ctx,
                event,
                StatusCode::GATEWAY_TIMEOUT,
                "upstream TLS handshake timeout",
            )
            .await);
        }
    };
    event.coverage = Coverage::Inspected;
    let authority = if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    };
    to_origin_form(&mut req, Some(authority));
    Ok(relay(&ctx, event, req, upstream).await)
}

/// Answers the client directly, records the event and closes the connection.
async fn refuse(
    ctx: &Ctx,
    mut event: Event,
    status: StatusCode,
    reason: &'static str,
) -> Response<Body> {
    event.status = status.as_u16();
    event.reason = Some(reason);
    ctx.emit(event).await;
    let mut response = Response::new(
        Full::new(Bytes::from(format!("gatewizz: {reason}\n")))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

#[derive(Debug, PartialEq, Eq)]
enum UpstreamFailure {
    Loop,
    Timeout,
    Unreachable,
}

impl UpstreamFailure {
    fn status(&self) -> StatusCode {
        match self {
            Self::Loop => StatusCode::FORBIDDEN,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Unreachable => StatusCode::BAD_GATEWAY,
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            Self::Loop => "request targets gatewizz itself",
            Self::Timeout => "upstream connect timeout",
            Self::Unreachable => "upstream unreachable",
        }
    }
}

/// Resolves the target, refusing any address that is gatewizz itself.
async fn resolve(ctx: &Ctx, host: &str, port: u16) -> Result<Vec<SocketAddr>, UpstreamFailure> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| UpstreamFailure::Unreachable)?
        .collect();
    if addrs.iter().any(|addr| is_self(*addr, ctx.listen)) {
        return Err(UpstreamFailure::Loop);
    }
    Ok(addrs)
}

/// Resolves and connects directly (never through another proxy), refusing any address that is gatewizz itself.
async fn connect_upstream(ctx: &Ctx, host: &str, port: u16) -> Result<TcpStream, UpstreamFailure> {
    let attempt = async {
        let addrs = resolve(ctx, host, port).await?;
        TcpStream::connect(addrs.as_slice())
            .await
            .map_err(|_| UpstreamFailure::Unreachable)
    };
    timeout(ctx.settings.connect_timeout, attempt)
        .await
        .unwrap_or(Err(UpstreamFailure::Timeout))
}

fn is_self(target: SocketAddr, listen: SocketAddr) -> bool {
    target.port() == listen.port()
        && (target.ip() == listen.ip()
            || listen.ip().is_unspecified()
            || (target.ip().is_loopback() && listen.ip().is_loopback()))
}

/// `http://host[:port]/…` → (host, port). Anything else is not a forward-proxy request.
fn http_target(uri: &Uri) -> Option<(String, u16)> {
    if uri.scheme_str() != Some("http") {
        return None;
    }
    let host = uri.host()?.trim_start_matches('[').trim_end_matches(']');
    Some((host.to_string(), uri.port_u16().unwrap_or(80)))
}

/// Request framing is parsed by hyper alone, and every request is re-framed towards the upstream, so client and
/// upstream can never disagree about where a request ends (no smuggling). hyper rejects differing or invalid
/// `Content-Length` with 400; for `Transfer-Encoding` plus `Content-Length` it uses chunked, drops the length and closes
/// the connection after the response (RFC 9112 §6.3).
fn malformed(err: &hyper::Error) -> Option<(StatusCode, &'static str)> {
    if err.is_parse_too_large() {
        Some((
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request head too large",
        ))
    } else if err.is_parse() {
        Some((StatusCode::BAD_REQUEST, "malformed request"))
    } else {
        None
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// Copies both directions until both sides closed, an error, or `idle` without any traffic.
/// Returns (client→upstream, upstream→client) bytes.
async fn pipe<A, B>(client: A, upstream: B, idle: Duration) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_rx, mut client_tx) = tokio::io::split(client);
    let (mut upstream_rx, mut upstream_tx) = tokio::io::split(upstream);
    let mut up_buf = vec![0u8; 16 * 1024];
    let mut down_buf = vec![0u8; 16 * 1024];
    let (mut up, mut down) = (0u64, 0u64);
    let (mut client_open, mut upstream_open) = (true, true);
    while client_open || upstream_open {
        tokio::select! {
            read = client_rx.read(&mut up_buf), if client_open => match read {
                Ok(0) => {
                    client_open = false;
                    let _ = upstream_tx.shutdown().await;
                }
                Ok(n) => {
                    if upstream_tx.write_all(&up_buf[..n]).await.is_err() {
                        break;
                    }
                    up += n as u64;
                }
                Err(_) => break,
            },
            read = upstream_rx.read(&mut down_buf), if upstream_open => match read {
                Ok(0) => {
                    upstream_open = false;
                    let _ = client_tx.shutdown().await;
                }
                Ok(n) => {
                    if client_tx.write_all(&down_buf[..n]).await.is_err() {
                        break;
                    }
                    down += n as u64;
                }
                Err(_) => break,
            },
            () = tokio::time::sleep(idle) => break,
        }
    }
    (up, down)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn strips_hop_by_hop_and_connection_listed_headers() {
        let mut map = headers(&[
            ("connection", "keep-alive, x-secret-hop"),
            ("x-secret-hop", "1"),
            ("proxy-authorization", "Basic abc"),
            ("keep-alive", "timeout=5"),
            ("upgrade", "websocket"),
            ("content-type", "text/plain"),
        ]);
        strip_hop_by_hop(&mut map);
        let left: Vec<&str> = map.keys().map(HeaderName::as_str).collect();
        assert_eq!(left, ["content-type"]);
    }

    #[test]
    fn parses_forward_proxy_targets() {
        let target = |s: &str| http_target(&s.parse::<Uri>().unwrap());
        assert_eq!(
            target("http://example.com/a?b"),
            Some(("example.com".into(), 80))
        );
        assert_eq!(
            target("http://example.com:8080/"),
            Some(("example.com".into(), 8080))
        );
        assert_eq!(target("http://[::1]:81/"), Some(("::1".into(), 81)));
        assert_eq!(target("https://example.com/"), None);
        assert_eq!(target("/origin-form"), None);
    }

    #[test]
    fn detects_requests_to_itself() {
        let listen: SocketAddr = "127.0.0.1:8899".parse().unwrap();
        assert!(is_self("127.0.0.1:8899".parse().unwrap(), listen));
        assert!(is_self("127.0.0.2:8899".parse().unwrap(), listen));
        assert!(is_self("[::1]:8899".parse().unwrap(), listen));
        assert!(!is_self("127.0.0.1:8900".parse().unwrap(), listen));
        assert!(!is_self("10.0.0.1:8899".parse().unwrap(), listen));
    }

    #[tokio::test]
    async fn pipe_copies_both_ways_and_counts() {
        let (client, mut client_peer) = tokio::io::duplex(64);
        let (upstream, mut upstream_peer) = tokio::io::duplex(64);
        let piping = tokio::spawn(pipe(client, upstream, Duration::from_secs(5)));

        client_peer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        upstream_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        upstream_peer.write_all(b"world!").await.unwrap();
        let mut buf = [0u8; 6];
        client_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world!");

        drop(client_peer);
        drop(upstream_peer);
        assert_eq!(piping.await.unwrap(), (5, 6));
    }

    #[tokio::test]
    async fn pipe_closes_idle_tunnels() {
        let (client, _client_peer) = tokio::io::duplex(64);
        let (upstream, _upstream_peer) = tokio::io::duplex(64);
        let counts = timeout(
            Duration::from_secs(2),
            pipe(client, upstream, Duration::from_millis(50)),
        )
        .await
        .expect("idle tunnel must close");
        assert_eq!(counts, (0, 0));
    }

    /// End to end: a proxy on an ephemeral port with the given settings.
    async fn start(settings: Settings) -> (SocketAddr, mpsc::Receiver<Event>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (events, received) = mpsc::channel(16);
        tokio::spawn(serve(
            listener,
            settings,
            None,
            events,
            std::future::pending(),
        ));
        (addr, received)
    }

    /// A raw upstream that answers one request per connection and hands back the bytes it received.
    async fn recording_upstream() -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut seen = Vec::new();
                    let mut buf = [0u8; 4096];
                    // Read until the chunked body's terminator, or a short quiet period.
                    while let Ok(Ok(n)) =
                        timeout(Duration::from_millis(200), stream.read(&mut buf)).await
                    {
                        if n == 0 {
                            break;
                        }
                        seen.extend_from_slice(&buf[..n]);
                        if seen.ends_with(b"0\r\n\r\n") {
                            break;
                        }
                    }
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tx.send(seen).await;
                });
            }
        });
        (addr, rx)
    }

    async fn exchange(proxy: SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .expect("proxy must close the connection")
            .unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    async fn next_event(events: &mut mpsc::Receiver<Event>) -> Event {
        timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap()
    }

    /// An upstream that answers each request after `delay`, and reports when a request head arrived.
    async fn slow_upstream(delay: Duration) -> (SocketAddr, mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (arrived, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let arrived = arrived.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = arrived.send(()).await;
                    tokio::time::sleep(delay).await;
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow")
                        .await;
                });
            }
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn events_never_hold_header_values_or_queries() {
        let (proxy, mut events) = start(Settings::default()).await;
        let (upstream, _seen) = recording_upstream().await;
        let request = format!(
            "GET http://{upstream}/v1/chat?api_key=QSECRET HTTP/1.1\r\nHost: {upstream}\r\n\
             Authorization: Bearer ASECRET\r\nCookie: session=CSECRET\r\n\
             Proxy-Authorization: Basic PSECRET\r\nConnection: close\r\n\r\n"
        );
        let response = exchange(proxy, request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let event = next_event(&mut events).await;
        assert_eq!(event.path, "/v1/chat");
        let line = serde_json::to_string(&event).unwrap();
        for leak in ["SECRET", "api_key", "Bearer", "session", "Basic"] {
            assert!(!line.contains(leak), "{leak} in {line}");
        }
    }

    #[tokio::test]
    async fn shutdown_drains_a_slow_request() {
        let (upstream, mut arrived) = slow_upstream(Duration::from_millis(500)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let (events, mut received) = mpsc::channel(16);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let settings = Settings {
            shutdown_timeout: Duration::from_secs(5),
            ..Settings::default()
        };
        let server = tokio::spawn(serve(listener, settings, None, events, async {
            let _ = stopped.await;
        }));

        let client = tokio::spawn(async move {
            let request =
                format!("GET http://{upstream}/slow HTTP/1.1\r\nHost: {upstream}\r\n\r\n");
            exchange(proxy, request.as_bytes()).await
        });
        timeout(Duration::from_secs(5), arrived.recv())
            .await
            .unwrap();
        let started = std::time::Instant::now();
        stop.send(()).unwrap();

        timeout(Duration::from_secs(5), server)
            .await
            .expect("serve must return once drained")
            .unwrap()
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "drain waited for the deadline"
        );
        // The keep-alive connection was answered, then closed instead of waiting for another request.
        let response = client.await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("slow"), "{response}");
        assert_eq!(next_event(&mut received).await.status, 200);
        // No new connections once shutdown has started.
        assert!(TcpStream::connect(proxy).await.is_err());
    }

    #[tokio::test]
    async fn shutdown_gives_up_at_the_deadline() {
        let (upstream, mut arrived) = slow_upstream(Duration::from_secs(60)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let (events, _received) = mpsc::channel(16);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let settings = Settings {
            shutdown_timeout: Duration::from_millis(200),
            ..Settings::default()
        };
        let server = tokio::spawn(serve(listener, settings, None, events, async {
            let _ = stopped.await;
        }));
        let mut client = TcpStream::connect(proxy).await.unwrap();
        let request = format!("GET http://{upstream}/hang HTTP/1.1\r\nHost: {upstream}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        timeout(Duration::from_secs(5), arrived.recv())
            .await
            .unwrap();
        stop.send(()).unwrap();
        timeout(Duration::from_secs(2), server)
            .await
            .expect("serve must return at the deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn smuggled_request_never_reaches_upstream() {
        let (proxy, mut events) = start(Settings::default()).await;
        let (upstream, mut seen) = recording_upstream().await;
        let request = format!(
            "POST http://{upstream}/a HTTP/1.1\r\nHost: {upstream}\r\nContent-Length: 60\r\n\
             Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n\
             GET http://{upstream}/smuggled HTTP/1.1\r\nHost: {upstream}\r\n\r\n"
        );
        let response = exchange(proxy, request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        let received = String::from_utf8(seen.recv().await.unwrap())
            .unwrap()
            .to_lowercase();
        assert!(received.starts_with("post /a http/1.1\r\n"), "{received}");
        assert!(
            received.contains("transfer-encoding: chunked"),
            "{received}"
        );
        assert!(!received.contains("content-length"), "{received}");
        assert!(!received.contains("smuggled"), "{received}");
        assert_eq!(next_event(&mut events).await.path, "/a");
        // The connection was closed after the first response: the trailing request is never forwarded.
        assert!(
            timeout(Duration::from_millis(300), seen.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn malformed_request_is_answered_and_recorded() {
        let (proxy, mut events) = start(Settings::default()).await;
        let response = exchange(
            proxy,
            b"POST http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nabcde",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        let event = next_event(&mut events).await;
        assert_eq!((event.coverage, event.status), (Coverage::Blocked, 400));
        assert_eq!(event.reason, Some("malformed request"));
    }

    #[tokio::test]
    async fn tunnels_allowed_ports_and_counts_bytes() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });
        let settings = Settings {
            allowed_connect_ports: vec![echo_addr.port()],
            ..Settings::default()
        };
        let (proxy, mut events) = start(settings).await;

        let mut client = TcpStream::connect(proxy).await.unwrap();
        let connect = format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n");
        client.write_all(connect.as_bytes()).await.unwrap();
        let mut head = [0u8; 12];
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 200");
        let mut rest = Vec::new();
        while !rest.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).await.unwrap();
            rest.push(byte[0]);
        }
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        drop(client);

        let event = next_event(&mut events).await;
        assert_eq!(event.coverage, Coverage::Tunneled);
        assert_eq!((event.bytes_up, event.bytes_down), (Some(4), Some(4)));
        // The test itself is the client, so attribution must name this process.
        #[cfg(windows)]
        assert!(
            matches!(event.process, Process::Known { pid, .. } if pid == std::process::id()),
            "{:?}",
            event.process
        );
        #[cfg(not(windows))]
        assert_eq!(event.process, Process::Unknown("unsupported"));
    }

    #[tokio::test]
    async fn refuses_connect_to_other_ports() {
        let (proxy, mut events) = start(Settings::default()).await;
        let response = exchange(proxy, b"CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(
            next_event(&mut events).await.reason,
            Some("CONNECT port not allowed")
        );
    }

    #[tokio::test]
    async fn closes_connections_over_the_limit() {
        let settings = Settings {
            max_connections: 1,
            ..Settings::default()
        };
        let (proxy, _events) = start(settings).await;
        let _held = TcpStream::connect(proxy).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut second = TcpStream::connect(proxy).await.unwrap();
        let mut buf = [0u8; 1];
        let read = timeout(Duration::from_secs(2), second.read(&mut buf))
            .await
            .unwrap();
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "second connection must be closed"
        );
    }

    /// Reads one response whose body length is given by `Content-Length` (all responses in these tests).
    async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> String {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let length = head
            .lines()
            .find_map(|line| {
                line.to_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().to_string())
            })
            .map_or(0, |v| v.parse::<usize>().unwrap());
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await.unwrap();
        head + &String::from_utf8(body).unwrap()
    }

    #[tokio::test]
    async fn keeps_the_client_connection_alive_across_requests() {
        let (proxy, mut events) = start(Settings::default()).await;
        let (upstream, mut seen) = recording_upstream().await;
        let mut client = TcpStream::connect(proxy).await.unwrap();
        for path in ["/one", "/two"] {
            let request =
                format!("GET http://{upstream}{path} HTTP/1.1\r\nHost: {upstream}\r\n\r\n");
            client.write_all(request.as_bytes()).await.unwrap();
            let response = read_response(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            // The upstream's `Connection: close` is hop-by-hop and must not end the client's connection.
            assert!(
                !response.to_lowercase().contains("connection: close"),
                "{response}"
            );
            assert!(
                String::from_utf8(seen.recv().await.unwrap())
                    .unwrap()
                    .contains(path)
            );
            assert_eq!(next_event(&mut events).await.path, path);
        }
    }

    #[tokio::test]
    async fn forwards_chunked_body_after_100_continue() {
        let (proxy, _events) = start(Settings::default()).await;
        let (upstream, mut seen) = recording_upstream().await;
        let mut client = TcpStream::connect(proxy).await.unwrap();
        let head = format!(
            "POST http://{upstream}/up HTTP/1.1\r\nHost: {upstream}\r\nExpect: 100-continue\r\n\
             Transfer-Encoding: chunked\r\n\r\n"
        );
        client.write_all(head.as_bytes()).await.unwrap();
        let mut interim = [0u8; 25];
        client.read_exact(&mut interim).await.unwrap();
        assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
        client.write_all(b"5\r\nhello\r\n0\r\n\r\n").await.unwrap();
        assert!(read_response(&mut client).await.starts_with("HTTP/1.1 200"));

        let received = String::from_utf8(seen.recv().await.unwrap())
            .unwrap()
            .to_lowercase();
        assert!(received.contains("hello"), "{received}");
        assert!(!received.contains("expect:"), "{received}");
    }

    #[tokio::test]
    async fn client_disconnect_mid_upload_closes_the_upstream() {
        let (proxy, _events) = start(Settings::default()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let closed = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut sink = Vec::new();
            // Ends only when the proxy closes its side.
            timeout(Duration::from_secs(5), stream.read_to_end(&mut sink))
                .await
                .is_ok()
        });
        let mut client = TcpStream::connect(proxy).await.unwrap();
        let head = format!(
            "POST http://{upstream}/ HTTP/1.1\r\nHost: {upstream}\r\nContent-Length: 1000\r\n\r\n"
        );
        client.write_all(head.as_bytes()).await.unwrap();
        client.write_all(&[b'x'; 10]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(client);
        assert!(closed.await.unwrap(), "upstream connection must be closed");
    }

    #[tokio::test]
    async fn silent_upstream_gets_a_gateway_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let settings = Settings {
            response_timeout: Duration::from_millis(200),
            ..Settings::default()
        };
        let (proxy, mut events) = start(settings).await;
        let response = exchange(
            proxy,
            format!("GET http://{upstream}/ HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 504"), "{response}");
        let event = next_event(&mut events).await;
        assert_eq!(
            (event.status, event.reason),
            (504, Some("upstream response timeout"))
        );
    }

    #[tokio::test]
    async fn silent_client_is_disconnected() {
        let settings = Settings {
            header_timeout: Duration::from_millis(200),
            ..Settings::default()
        };
        let (proxy, _events) = start(settings).await;
        let mut client = TcpStream::connect(proxy).await.unwrap();
        let mut buf = Vec::new();
        let read = timeout(Duration::from_secs(3), client.read_to_end(&mut buf)).await;
        assert!(
            read.is_ok(),
            "a client that sends no request head must be disconnected"
        );
    }

    #[tokio::test]
    async fn refuses_requests_to_itself() {
        let (proxy, mut events) = start(Settings::default()).await;
        let port = proxy.port();
        for target in [
            format!("http://127.0.0.1:{port}/"),
            format!("http://localhost:{port}/"),
        ] {
            let response = exchange(
                proxy,
                format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 403"), "{target}: {response}");
            assert_eq!(
                next_event(&mut events).await.reason,
                Some("request targets gatewizz itself")
            );
        }
    }

    #[tokio::test]
    async fn rejects_obs_fold_and_oversized_heads() {
        let (proxy, mut events) = start(Settings::default()).await;
        let folded = exchange(
            proxy,
            b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\nX-A: a\r\n b\r\n\r\n",
        )
        .await;
        assert!(folded.starts_with("HTTP/1.1 400"), "{folded}");
        assert_eq!(
            next_event(&mut events).await.reason,
            Some("malformed request")
        );

        let big = format!(
            "GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\nX-Big: {}\r\n\r\n",
            "a".repeat(Settings::default().max_header_bytes + 1)
        );
        let oversized = exchange(proxy, big.as_bytes()).await;
        assert!(oversized.starts_with("HTTP/1.1 431"), "{oversized}");
        assert_eq!(
            next_event(&mut events).await.reason,
            Some("request head too large")
        );
    }

    mod interception {
        use super::*;
        use crate::ca::Ca;
        use rustls::pki_types::ServerName;
        use rustls::{ClientConfig, RootCertStore, ServerConfig};
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        fn trusting(root: &[u8]) -> ClientConfig {
            let mut roots = RootCertStore::empty();
            roots.add(root.to_vec().into()).unwrap();
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }

        /// A TLS upstream presenting a leaf for `name` from `ca`. It answers `METHOD PATH BODY-LENGTH` and reports
        /// each decrypted request it served.
        async fn tls_upstream(ca: &Ca, name: &str) -> (SocketAddr, mpsc::Receiver<String>) {
            let leaf = ca.leaf(name).unwrap();
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.cert.clone().into()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(leaf.key.clone().into()),
            )
            .unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = mpsc::channel(8);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let (acceptor, tx) = (acceptor.clone(), tx.clone());
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let tx = tx.clone();
                            async move {
                                let line = format!("{} {}", req.method(), req.uri());
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let line = format!("{line} {}", body.len());
                                let _ = tx.send(line.clone()).await;
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(line))))
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
            (addr, rx)
        }

        /// A proxy with interception by `ca` whose upstream connections trust `upstream_root`.
        async fn start_tls(
            ca: Ca,
            upstream_root: &Ca,
            settings: Settings,
        ) -> (SocketAddr, mpsc::Receiver<Event>) {
            let tls = Interceptor::with_upstream(ca, trusting(upstream_root.cert()));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (events, received) = mpsc::channel(16);
            tokio::spawn(serve(
                listener,
                settings,
                Some(Arc::new(tls)),
                events,
                std::future::pending(),
            ));
            (addr, received)
        }

        fn allowing(port: u16) -> Settings {
            Settings {
                allowed_connect_ports: vec![port],
                ..Settings::default()
            }
        }

        async fn connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
            let mut stream = TcpStream::connect(proxy).await.unwrap();
            let connect = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
            stream.write_all(connect.as_bytes()).await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            assert!(head.starts_with(b"HTTP/1.1 200"));
            stream
        }

        /// CONNECT, then TLS to the proxy's leaf offering h2 and http/1.1, trusting `root`.
        async fn tls_client(
            proxy: SocketAddr,
            target: SocketAddr,
            root: &[u8],
        ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
            let mut config = trusting(root);
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let name = ServerName::try_from(target.ip().to_string()).unwrap();
            TlsConnector::from(Arc::new(config))
                .connect(name, connect(proxy, target).await)
                .await
        }

        #[tokio::test]
        async fn inspects_requests_with_keep_alive() {
            let (gate, upstream_ca) = (Ca::generate().unwrap(), Ca::generate().unwrap());
            let (upstream, mut seen) = tls_upstream(&upstream_ca, "127.0.0.1").await;
            // The client trusts the gatewizz CA only.
            let gate_root = gate.cert().to_vec();
            let (proxy, mut events) =
                start_tls(gate, &upstream_ca, allowing(upstream.port())).await;
            let mut client = tls_client(proxy, upstream, &gate_root).await.unwrap();
            assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));

            for (request, expected) in [
                (
                    "GET /one?q=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                    "GET /one?q=1 0",
                ),
                (
                    "POST /two HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\nhello",
                    "POST /two 5",
                ),
                (
                    "GET /three HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                    "GET /three 0",
                ),
            ] {
                client.write_all(request.as_bytes()).await.unwrap();
                let response = read_response(&mut client).await;
                assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                assert!(response.ends_with(expected), "{response}");
                assert_eq!(seen.recv().await.unwrap(), expected);
                let event = next_event(&mut events).await;
                assert_eq!(event.coverage, Coverage::Inspected);
                assert_eq!((event.status, event.port), (200, upstream.port()));
                assert_eq!(event.path, expected.split(['?', ' ']).nth(1).unwrap());
            }
        }

        #[tokio::test]
        async fn rejects_untrusted_and_wrong_host_upstreams() {
            let (upstream_ca, stranger) = (Ca::generate().unwrap(), Ca::generate().unwrap());
            for (upstream_ca_used, name) in
                [(&stranger, "127.0.0.1"), (&upstream_ca, "example.com")]
            {
                let gate = Ca::generate().unwrap();
                let (upstream, mut seen) = tls_upstream(upstream_ca_used, name).await;
                let gate_root = gate.cert().to_vec();
                let (proxy, mut events) =
                    start_tls(gate, &upstream_ca, allowing(upstream.port())).await;
                let mut client = tls_client(proxy, upstream, &gate_root).await.unwrap();
                client
                    .write_all(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nkey")
                    .await
                    .unwrap();
                let response = read_response(&mut client).await;
                assert!(response.starts_with("HTTP/1.1 502"), "{response}");
                let event = next_event(&mut events).await;
                assert_eq!(event.reason, Some("upstream certificate rejected"));
                assert_eq!(event.coverage, Coverage::Blocked);
                assert!(
                    timeout(Duration::from_millis(200), seen.recv())
                        .await
                        .is_err(),
                    "no request may reach an unverified upstream"
                );
            }
        }

        #[tokio::test]
        async fn tunnel_hosts_keep_the_blind_tunnel() {
            let (gate, upstream_ca) = (Ca::generate().unwrap(), Ca::generate().unwrap());
            let gate_root = gate.cert().to_vec();
            let (upstream, mut seen) = tls_upstream(&upstream_ca, "127.0.0.1").await;
            let settings = Settings {
                tunnel_hosts: vec!["127.0.0.1".into()],
                ..allowing(upstream.port())
            };
            let (proxy, mut events) = start_tls(gate, &upstream_ca, settings).await;
            // Tunneled, the client sees the upstream's own certificate, not a gatewizz leaf.
            assert!(tls_client(proxy, upstream, &gate_root).await.is_err());
            let mut client = tls_client(proxy, upstream, upstream_ca.cert())
                .await
                .unwrap();
            client
                .write_all(b"GET /t HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            assert!(read_response(&mut client).await.starts_with("HTTP/1.1 200"));
            assert_eq!(seen.recv().await.unwrap(), "GET /t 0");
            drop(client);
            let mut coverages = vec![
                next_event(&mut events).await.coverage,
                next_event(&mut events).await.coverage,
            ];
            coverages.dedup();
            assert_eq!(coverages, [Coverage::Tunneled]);
        }

        #[tokio::test]
        async fn client_refusing_the_leaf_is_recorded() {
            let (gate, upstream_ca) = (Ca::generate().unwrap(), Ca::generate().unwrap());
            let (upstream, mut seen) = tls_upstream(&upstream_ca, "127.0.0.1").await;
            let (proxy, mut events) =
                start_tls(gate, &upstream_ca, allowing(upstream.port())).await;
            // Pinning or its own trust store: the client does not trust the gatewizz CA.
            assert!(
                tls_client(proxy, upstream, upstream_ca.cert())
                    .await
                    .is_err()
            );
            let event = next_event(&mut events).await;
            assert_eq!(
                (event.method.as_str(), event.coverage),
                ("CONNECT", Coverage::Blocked)
            );
            assert_eq!(event.reason, Some("client TLS handshake failed"));
            assert!(
                timeout(Duration::from_millis(200), seen.recv())
                    .await
                    .is_err()
            );
        }
    }
}
