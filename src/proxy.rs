//! Explicit HTTP/1.1 forward proxy: plain HTTP forwarding and CONNECT tunnels.
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

type UpstreamSender = hyper::client::conn::http1::SendRequest<Body>;

use crate::approve::{Approvals, Held, Outcome};
use crate::detect::{self, BodyLimits, Inspected};
use crate::event::{self, Coverage, Event};
use crate::process::{self, Process};
use crate::rules::{self, Action, Content, Decision, Facts, Rule};
use crate::tls::{Interceptor, UpstreamTlsFailure};

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
    /// Decrypts CONNECT tunnels when set; without it every CONNECT is a blind tunnel (M1 behaviour).
    pub tls: Option<Arc<Interceptor>>,
    /// Allow/block rules, validated at config load.
    pub rules: Vec<Rule>,
    pub default_action: Action,
    /// The approval window's queue; without one, `approve` rules block (fail closed).
    pub approvals: Option<Arc<Approvals>>,
    /// How much of a request body is read and inspected before any request byte goes upstream.
    pub body: BodyLimits,
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
            tls: None,
            rules: Vec::new(),
            default_action: Action::Allow,
            approvals: None,
            body: BodyLimits::default(),
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
            findings: Vec::new(),
            model: None,
            status: status.as_u16(),
            reason: Some(reason),
            bytes_up: None,
            bytes_down: None,
            action: None,
            rule: None,
        }
    }
}

struct Ctx {
    settings: Settings,
    listen: SocketAddr,
    events: mpsc::Sender<Event>,
}

impl Ctx {
    fn decide(&self, facts: &Facts<'_>) -> Decision {
        rules::decide(facts, &self.settings.rules, self.settings.default_action)
    }

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
        findings: Vec::new(),
        model: None,
        status: 0,
        reason: None,
        bytes_up: None,
        bytes_down: None,
        action: None,
        rule: None,
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
    // Decided before the upstream connection is opened, so a blocked request sends it nothing.
    let decision = ctx.decide(&Facts {
        host: &host,
        process: image_name(&event.process),
        path: Some(&event.path),
        // The body is read in `relay`; rules on its content are decided there.
        content: None,
        defer_content: true,
    });
    if let Some(blocked) = enforce(ctx, &mut event, decision, Stage::Early).await {
        return blocked;
    }
    let authority = req.uri().authority().map(|a| a.as_str().to_string());
    to_origin_form(&mut req, authority);
    // ponytail: one upstream connection per request, no pooling; add a pool if the latency budget needs it.
    relay(ctx, event, Upstream::Connect { host: &host, port }, req).await
}

/// The upstream a request goes to. Plain HTTP connects only once the request is decided, so a refused or held
/// request opens no upstream connection at all; a decrypted request already has its tunnel's connection.
enum Upstream<'a> {
    Connect { host: &'a str, port: u16 },
    Ready(&'a mut UpstreamSender),
}

/// TCP and an HTTP/1.1 connection to a plain-HTTP upstream.
async fn connect_http(
    ctx: &Ctx,
    host: &str,
    port: u16,
) -> Result<UpstreamSender, (StatusCode, &'static str)> {
    let tcp = connect_upstream(ctx, host, port)
        .await
        .map_err(|failure| (failure.status(), failure.reason()))?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "upstream handshake failed"))?;
    // Ends when the response body is consumed or dropped (client gone).
    tokio::spawn(conn);
    Ok(sender)
}

/// Turns a proxy request into what the upstream expects: origin-form target, no hop-by-hop headers, a `Host`.
fn to_origin_form(req: &mut Request<Incoming>, authority: Option<String>) {
    let origin_form = req
        .uri()
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .parse::<Uri>()
        .unwrap_or_else(|_| Uri::from_static("/"));
    *req.uri_mut() = origin_form;
    strip_hop_by_hop(req.headers_mut());
    // hyper already answered `100 Continue` to the client when it read the body.
    req.headers_mut().remove(header::EXPECT);
    if !req.headers().contains_key(header::HOST)
        && let Some(value) = authority.and_then(|a| HeaderValue::from_str(&a).ok())
    {
        req.headers_mut().insert(header::HOST, value);
    }
}

/// Sends one request on an established upstream connection and returns the response, recording the event.
async fn relay(
    ctx: &Ctx,
    mut event: Event,
    upstream: Upstream<'_>,
    req: Request<Incoming>,
) -> Response<Body> {
    // Plain HTTP and decrypted HTTPS both end here: the body is read and inspected before any request byte is sent.
    let req = match detect::inspect(req, &ctx.settings.body).await {
        Inspected::Forward(req, inspection) => {
            event.findings = inspection.findings;
            event.model = inspection.model;
            event.coverage = inspection.coverage;
            event.bytes_up = inspection.bytes_up;
            *req
        }
        Inspected::Refuse(inspection, status, reason) => {
            event.findings = inspection.findings;
            event.coverage = inspection.coverage;
            return refuse(ctx, event, status, reason).await;
        }
    };
    // The final decision, now that the body is known. Only a fully read body counts: for a partially inspected
    // one, rules on findings or AI requests fail closed.
    let decision = {
        let kinds: Vec<&str> = event.findings.iter().map(|finding| finding.kind).collect();
        let content = (event.coverage == Coverage::Inspected).then(|| Content {
            findings: &kinds,
            ai: event.model.is_some(),
        });
        ctx.decide(&Facts {
            host: &event.host,
            process: image_name(&event.process),
            path: Some(&event.path),
            content,
            defer_content: false,
        })
    };
    if let Some(blocked) = enforce(ctx, &mut event, decision, Stage::Final).await {
        return blocked;
    }
    let mut connected;
    let sender = match upstream {
        Upstream::Ready(sender) => sender,
        Upstream::Connect { host, port } => match connect_http(ctx, host, port).await {
            Ok(sender) => {
                connected = sender;
                &mut connected
            }
            Err((status, reason)) => return refuse(ctx, event, status, reason).await,
        },
    };
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
        findings: Vec::new(),
        model: None,
        status: 0,
        reason: None,
        bytes_up: None,
        bytes_down: None,
        action: None,
        rule: None,
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
    let interceptor = ctx
        .settings
        .tls
        .clone()
        .filter(|interceptor| !interceptor.tunnels(&host));
    // A blind tunnel shows only host and process. When the tunnel is decrypted, each request inside is decided on
    // its own, so rules about paths and content wait for those.
    let decision = ctx.decide(&Facts {
        host: &host,
        process: image_name(&event.process),
        path: None,
        content: None,
        defer_content: interceptor.is_some(),
    });
    // A blind tunnel is decided once, here; a decrypted one asks for approval per request.
    let stage = if interceptor.is_some() {
        Stage::Early
    } else {
        Stage::Final
    };
    if let Some(blocked) = enforce(&ctx, &mut event, decision, stage).await {
        return blocked;
    }
    if let Some(interceptor) = interceptor {
        return intercept(ctx, interceptor, event, host, port, req).await;
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

/// Opens and verifies the upstream TLS connection first, so a bad upstream certificate is answered with 502 before
/// the client sends anything. Then the client's TLS is terminated with a leaf for `host`, and each decrypted request
/// goes through [`inside`], always to `host`.
async fn intercept(
    ctx: Arc<Ctx>,
    interceptor: Arc<Interceptor>,
    mut event: Event,
    host: String,
    port: u16,
    req: Request<Incoming>,
) -> Response<Body> {
    let acceptor = match interceptor.acceptor(&host) {
        Ok(acceptor) => acceptor,
        Err(err) => {
            eprintln!("gatewizz: no certificate for {host}: {err}");
            return refuse(
                &ctx,
                event,
                StatusCode::BAD_GATEWAY,
                "no certificate for this host",
            )
            .await;
        }
    };
    let sender = match upstream_tls(&ctx, &interceptor, &host, port).await {
        Ok(sender) => sender,
        Err((status, reason)) => return refuse(&ctx, event, status, reason).await,
    };
    let upstream = Arc::new(tokio::sync::Mutex::new(sender));
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(req).await else {
            event.reason = Some("client left before the tunnel opened");
            ctx.emit(event).await;
            return;
        };
        let handshake = timeout(
            ctx.settings.header_timeout,
            acceptor.accept(TokioIo::new(upgraded)),
        );
        let Ok(Ok(client_tls)) = handshake.await else {
            // Pinning, a private trust store or a missing CA install: never fall back to a blind tunnel.
            event.status = StatusCode::OK.as_u16();
            event.reason = Some("client rejected the gatewizz certificate");
            ctx.emit(event).await;
            return;
        };
        let (client, process) = (event.client, event.process.clone());
        let svc_ctx = ctx.clone();
        let svc = service_fn(move |req| {
            let (ctx, interceptor, upstream) =
                (svc_ctx.clone(), interceptor.clone(), upstream.clone());
            let (host, process) = (host.clone(), process.clone());
            async move {
                Ok::<_, Infallible>(
                    inside(
                        &ctx,
                        &interceptor,
                        &upstream,
                        client,
                        process,
                        &host,
                        port,
                        req,
                    )
                    .await,
                )
            }
        });
        // ponytail: like blind tunnels, decrypted tunnels are not drained on shutdown; they end with the runtime.
        let _ = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(ctx.settings.header_timeout)
            .max_header_size(ctx.settings.max_header_bytes)
            .serve_connection(TokioIo::new(client_tls), svc)
            .await;
    });
    Response::new(Empty::new().map_err(|never| match never {}).boxed())
}

/// TCP plus verified TLS to the upstream, then an HTTP/1.1 connection on it.
async fn upstream_tls(
    ctx: &Ctx,
    interceptor: &Interceptor,
    host: &str,
    port: u16,
) -> Result<UpstreamSender, (StatusCode, &'static str)> {
    let tcp = connect_upstream(ctx, host, port)
        .await
        .map_err(|failure| (failure.status(), failure.reason()))?;
    let tls = match timeout(ctx.settings.connect_timeout, interceptor.connect(tcp, host)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(UpstreamTlsFailure::Certificate)) => {
            return Err((StatusCode::BAD_GATEWAY, "upstream certificate rejected"));
        }
        Ok(Err(UpstreamTlsFailure::Handshake)) => {
            return Err((StatusCode::BAD_GATEWAY, "upstream TLS handshake failed"));
        }
        Err(_) => return Err((StatusCode::GATEWAY_TIMEOUT, "upstream connect timeout")),
    };
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "upstream handshake failed"))?;
    tokio::spawn(conn);
    Ok(sender)
}

/// One decrypted request in a tunnel to `host`. It always goes to `host`: a `Host` header naming anything else is
/// refused, so a tunnel to an allowed host cannot reach another site behind the same server (domain fronting).
#[allow(clippy::too_many_arguments)]
async fn inside(
    ctx: &Ctx,
    interceptor: &Interceptor,
    upstream: &tokio::sync::Mutex<UpstreamSender>,
    client: SocketAddr,
    process: Process,
    host: &str,
    port: u16,
    mut req: Request<Incoming>,
) -> Response<Body> {
    let mut event = Event {
        time: event::now(),
        client,
        process,
        method: req.method().to_string(),
        host: host.to_string(),
        port,
        path: req.uri().path().to_string(),
        // Set by `relay` once the body has been inspected.
        coverage: Coverage::Blocked,
        findings: Vec::new(),
        model: None,
        status: 0,
        reason: None,
        bytes_up: None,
        bytes_down: None,
        action: None,
        rule: None,
    };
    let named = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<hyper::http::uri::Authority>().ok());
    if named.is_some_and(|authority| {
        !authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .eq_ignore_ascii_case(host)
    }) {
        let mut event = event;
        event.coverage = Coverage::Blocked;
        return refuse(
            ctx,
            event,
            StatusCode::MISDIRECTED_REQUEST,
            "Host header does not match the tunnel",
        )
        .await;
    }
    let decision = ctx.decide(&Facts {
        host,
        process: image_name(&event.process),
        path: Some(&event.path),
        // The body is read in `relay`; rules on its content are decided there.
        content: None,
        defer_content: true,
    });
    if let Some(blocked) = enforce(ctx, &mut event, decision, Stage::Early).await {
        return blocked;
    }
    let authority = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    to_origin_form(&mut req, Some(authority));
    let mut sender = upstream.lock().await;
    // The upstream may have closed the idle connection between two requests; reconnecting then is not a retry,
    // because nothing of this request was sent yet.
    if sender.ready().await.is_err() {
        match upstream_tls(ctx, interceptor, host, port).await {
            Ok(fresh) => *sender = fresh,
            Err((status, reason)) => {
                let mut event = event;
                event.coverage = Coverage::Blocked;
                return refuse(ctx, event, status, reason).await;
            }
        }
    }
    // The lock is held until the response head arrives; HTTP/1.1 serves one request at a time anyway.
    relay(ctx, event, Upstream::Ready(&mut sender), req).await
}

/// Notes the decision on the event. Anything but `allow` answers 403 naming the rule, records the event and closes
/// the connection; nothing reaches the upstream.
/// Where a decision is taken. A request is decided early (host, process, path) and finally (after the body is read,
/// or at CONNECT for a blind tunnel); blocks apply at both, approvals are asked only at the final one so a request
/// is never asked twice.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Early,
    Final,
}

/// Notes the decision on the event and applies it. `block`, and an `approve` that is denied, times out or has no
/// window to ask, answer 403 naming the rule, record the event and close the connection; nothing reaches the
/// upstream. A request held for approval waits here, before any of its bytes are sent.
async fn enforce(
    ctx: &Ctx,
    event: &mut Event,
    decision: Decision,
    stage: Stage,
) -> Option<Response<Body>> {
    event.action = Some(decision.action);
    event.rule = Some(decision.rule.clone());
    match decision.action {
        Action::Allow => None,
        Action::Approve if stage == Stage::Early => None,
        Action::Approve => {
            let outcome = match &ctx.settings.approvals {
                Some(approvals) => {
                    approvals
                        .ask(Held {
                            process: event.process.clone(),
                            host: event.host.clone(),
                            rule: decision.rule.clone(),
                            findings: event.findings.iter().map(|f| f.kind.to_string()).collect(),
                        })
                        .await
                }
                None => Outcome::Blocked("no approval window"),
            };
            match outcome {
                Outcome::Allowed(reason) => {
                    event.reason = Some(reason);
                    None
                }
                Outcome::Blocked(reason) => Some(forbid(ctx, event, &decision, reason).await),
            }
        }
        Action::Block => Some(forbid(ctx, event, &decision, "blocked by rule").await),
    }
}

/// The 403 for a blocked request: rule, severity, description and the event time, so the user can find the event.
async fn forbid(
    ctx: &Ctx,
    event: &Event,
    decision: &Decision,
    reason: &'static str,
) -> Response<Body> {
    let mut blocked = event.clone();
    blocked.coverage = Coverage::Blocked;
    blocked.status = StatusCode::FORBIDDEN.as_u16();
    blocked.reason = Some(reason);
    let time = blocked.time.clone();
    ctx.emit(blocked).await;
    let severity = decision
        .severity
        .map_or(String::new(), |s| format!(" ({})", s.as_str()));
    let why = if reason == "blocked by rule" {
        String::new()
    } else {
        format!(": {reason}")
    };
    let description = if decision.description.is_empty() {
        String::new()
    } else {
        format!("{}\n", decision.description)
    };
    let text = format!(
        "gatewizz: blocked by rule \"{}\"{severity}{why}\n{description}event time: {time}\n",
        decision.rule
    );
    let mut response = Response::new(
        Full::new(Bytes::from(text))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = StatusCode::FORBIDDEN;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// Image file name of a known client process (`smartwizz.exe`), as `match.process` names it.
fn image_name(process: &Process) -> Option<&str> {
    match process {
        Process::Known { image, .. } => image.rsplit(['\\', '/']).next(),
        Process::Unknown(_) => None,
    }
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

/// Resolves and connects directly (never through another proxy), refusing any address that is gatewizz itself.
async fn connect_upstream(ctx: &Ctx, host: &str, port: u16) -> Result<TcpStream, UpstreamFailure> {
    let attempt = async {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| UpstreamFailure::Unreachable)?
            .collect();
        if addrs.iter().any(|addr| is_self(*addr, ctx.listen)) {
            return Err(UpstreamFailure::Loop);
        }
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
        tokio::spawn(serve(listener, settings, events, std::future::pending()));
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
        let server = tokio::spawn(serve(listener, settings, events, async {
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
        let server = tokio::spawn(serve(listener, settings, events, async {
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

    /// A clearly fake GitHub token, assembled at runtime so no token-shaped literal sits in the source.
    fn fake_token() -> String {
        format!("{}{}", ["gh", "p_"].concat(), "x".repeat(36))
    }

    fn post(upstream: SocketAddr, extra_headers: &str, body: &str) -> String {
        format!(
            "POST http://{upstream}/v1/chat/completions HTTP/1.1\r\nHost: {upstream}\r\n{extra_headers}\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn inspects_bodies_and_records_findings_without_content() {
        let dir = std::env::temp_dir().join(format!("gatewizz-detect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("events.jsonl");
        let (events, writer) = event::spawn(
            crate::config::EventTarget::File(path.clone()),
            1 << 20,
            1,
            16,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, Settings::default(), events, async {
            let _ = stopped.await;
        }));
        let (upstream, mut seen) = recording_upstream().await;

        let token = fake_token();
        let diff = format!("--- a/.env\n+++ b/.env\n{token}\n");
        let body = serde_json::json!({
            "model": "llama3.1:8b",
            "messages": [{"role": "user", "content": diff}],
        })
        .to_string();
        let response = exchange(proxy, post(upstream, "", &body).as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        // Detection reports; deciding is #21's job, so the request still reaches the upstream unchanged.
        let received = String::from_utf8(seen.recv().await.unwrap()).unwrap();
        assert!(received.ends_with(&body), "{received}");

        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
        writer.join().unwrap().unwrap();
        let mut leaked = Vec::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            if text.contains(&token) || text.contains(&token[4..]) {
                leaked.push(text);
            }
        }
        assert!(leaked.is_empty(), "secret written to disk: {leaked:?}");
        let line: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
        assert_eq!(line["coverage"], "inspected");
        assert_eq!(
            line["findings"],
            serde_json::json!([{"kind": "secret.github_token", "count": 1}])
        );
        assert_eq!(line["model"], "llama3.1:8b");
        assert_eq!(line["bytes_up"], body.len());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn over_limit_bodies_are_blocked_by_default() {
        let settings = Settings {
            body: BodyLimits {
                max_bytes: 16,
                ..BodyLimits::default()
            },
            ..Settings::default()
        };
        let (proxy, mut events) = start(settings).await;
        let (upstream, mut seen) = recording_upstream().await;
        for (headers, body) in [
            ("", "x".repeat(17)),
            ("Content-Encoding: gzip\r\n", "x".repeat(4)),
        ] {
            let response = exchange(proxy, post(upstream, headers, &body).as_bytes()).await;
            assert!(response.starts_with("HTTP/1.1 413"), "{response}");
            let event = next_event(&mut events).await;
            assert_eq!((event.coverage, event.status), (Coverage::Blocked, 413));
        }
        // Fail closed: no request byte reached the upstream. (Plain HTTP opens the TCP connection before the body
        // is read, so the upstream may see an empty connection; decrypted requests already have theirs.)
        while let Ok(Some(bytes)) = timeout(Duration::from_millis(300), seen.recv()).await {
            assert!(bytes.is_empty(), "{}", String::from_utf8_lossy(&bytes));
        }
    }

    #[tokio::test]
    async fn over_limit_bodies_pass_partially_inspected_when_allowed() {
        let settings = Settings {
            body: BodyLimits {
                max_bytes: 16,
                over_limit: detect::OverLimit::Allow,
            },
            ..Settings::default()
        };
        let (proxy, mut events) = start(settings).await;
        let (upstream, mut seen) = recording_upstream().await;
        // Chunked, so the limit is only discovered while reading; the read part and the rest must both arrive.
        let body = "y".repeat(40);
        let request = format!(
            "POST http://{upstream}/up HTTP/1.1\r\nHost: {upstream}\r\nTransfer-Encoding: chunked\r\n\
             Connection: close\r\n\r\n14\r\n{}\r\n14\r\n{}\r\n0\r\n\r\n",
            &body[..20],
            &body[20..]
        );
        let response = exchange(proxy, request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let received = String::from_utf8(seen.recv().await.unwrap()).unwrap();
        let payload: String = received
            .split("\r\n")
            .filter(|l| l.chars().all(|c| c == 'y') && !l.is_empty())
            .collect();
        assert_eq!(payload, body, "{received}");
        let event = next_event(&mut events).await;
        assert_eq!(event.coverage, Coverage::PartiallyInspected);
        assert!(event.findings.is_empty());
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
        // The inspected body is re-framed with its exact length; neither the client's Content-Length nor its chunked
        // framing reaches the upstream.
        assert!(received.contains("content-length: 3\r\n"), "{received}");
        assert!(!received.contains("content-length: 60"), "{received}");
        assert!(!received.contains("transfer-encoding"), "{received}");
        assert!(received.ends_with("\r\n\r\nabc"), "{received}");
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
    async fn read_response(stream: &mut TcpStream) -> String {
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
    async fn client_disconnect_mid_upload_leaves_no_upstream_connection() {
        let (proxy, _events) = start(Settings::default()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        // The body is read before the upstream connection opens, so normally none is opened at all; if one is,
        // it must be closed once the client is gone.
        let closed = tokio::spawn(async move {
            let Ok(accepted) = timeout(Duration::from_secs(1), listener.accept()).await else {
                return true;
            };
            let (mut stream, _) = accepted.unwrap();
            let mut sink = Vec::new();
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
        assert!(
            closed.await.unwrap(),
            "no upstream connection may outlive the client"
        );
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

    fn block_rule(id: &str, matches: rules::Match) -> Rule {
        Rule {
            id: id.to_string(),
            description: "test rule".to_string(),
            matches,
            action: Action::Block,
            severity: rules::Severity::High,
        }
    }

    #[tokio::test]
    async fn blocked_requests_get_403_and_send_nothing_upstream() {
        let (upstream, mut seen) = recording_upstream().await;
        let settings = Settings {
            rules: vec![block_rule(
                "only-localhost",
                rules::Match {
                    not_host: Some(vec!["localhost".into()]),
                    ..rules::Match::default()
                },
            )],
            ..Settings::default()
        };
        let (proxy, mut events) = start(settings).await;

        let blocked = format!("GET http://{upstream}/x?k=v HTTP/1.1\r\nHost: {upstream}\r\n\r\n");
        let response = exchange(proxy, blocked.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(
            response.contains("blocked by rule \"only-localhost\" (high)"),
            "{response}"
        );
        assert!(
            response.contains("test rule") && response.contains("event time: "),
            "{response}"
        );
        let event = next_event(&mut events).await;
        assert_eq!(
            (
                event.action,
                event.rule.as_deref(),
                event.coverage,
                event.status
            ),
            (
                Some(Action::Block),
                Some("only-localhost"),
                Coverage::Blocked,
                403
            )
        );
        assert!(response.contains(&event.time), "the 403 names the event");
        assert!(
            timeout(Duration::from_millis(300), seen.recv())
                .await
                .is_err(),
            "nothing may reach the upstream"
        );

        let port = upstream.port();
        let allowed =
            format!("GET http://localhost:{port}/y HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n");
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(allowed.as_bytes()).await.unwrap();
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let event = next_event(&mut events).await;
        assert_eq!(
            (event.action, event.rule.as_deref()),
            (Some(Action::Allow), Some("default"))
        );
    }

    #[tokio::test]
    async fn content_rules_block_blind_tunnels() {
        let settings = Settings {
            rules: vec![block_rule(
                "no-secrets",
                rules::Match {
                    finding: Some("secret.*".into()),
                    ..rules::Match::default()
                },
            )],
            ..Settings::default()
        };
        let (proxy, mut events) = start(settings).await;
        // A blind tunnel's content cannot be checked, so a rule about content blocks it (fail closed).
        let response = exchange(
            proxy,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(
            next_event(&mut events).await.rule.as_deref(),
            Some("no-secrets")
        );
    }

    #[tokio::test]
    async fn secrets_only_reach_allowlisted_hosts() {
        let (upstream, mut seen) = recording_upstream().await;
        let settings = Settings {
            rules: vec![block_rule(
                "secrets-only-to-approved-models",
                rules::Match {
                    finding: Some("secret.*".into()),
                    not_host: Some(vec!["localhost".into()]),
                    ..rules::Match::default()
                },
            )],
            ..Settings::default()
        };
        let (proxy, mut events) = start(settings).await;
        // Built at runtime so no token-shaped literal sits in the source.
        let key = format!("{}{}", ["gh", "p_"].concat(), "x".repeat(36));
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"review:\n+token = {key}\n"}}]}}"#
        );
        let request = |host: String| {
            format!(
                "POST http://{host}/v1/chat/completions HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };

        let response = exchange(proxy, request(upstream.to_string()).as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(
            response.contains("secrets-only-to-approved-models"),
            "{response}"
        );
        assert!(!response.contains(&key), "the 403 must not echo the secret");
        let event = next_event(&mut events).await;
        assert_eq!(
            event.rule.as_deref(),
            Some("secrets-only-to-approved-models")
        );
        // Blocked because the key was found, not because the body went unread.
        assert_eq!(event.coverage, Coverage::Blocked);
        assert!(
            event
                .findings
                .iter()
                .any(|f| f.kind == "secret.github_token"),
            "{event:?}"
        );
        assert!(
            !format!("{event:?}").contains(&key),
            "events never hold the secret"
        );
        // forward() opens the TCP connection before the body is read; not one request byte may follow.
        if let Ok(Some(bytes)) = timeout(Duration::from_millis(500), seen.recv()).await {
            assert!(bytes.is_empty(), "upstream received {} bytes", bytes.len());
        }

        let port = upstream.port();
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(request(format!("localhost:{port}")).as_bytes())
            .await
            .unwrap();
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let event = next_event(&mut events).await;
        assert_eq!(
            (event.action, event.rule.as_deref()),
            (Some(Action::Allow), Some("default"))
        );
        assert_eq!(event.coverage, Coverage::Inspected);
    }

    /// A plain-HTTP upstream that counts connections and reports each request head it receives.
    async fn counting_upstream() -> (
        SocketAddr,
        Arc<std::sync::atomic::AtomicUsize>,
        mpsc::Receiver<String>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel(8);
        let counter = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                    let _ = tx.send(String::from_utf8_lossy(&head).into_owned()).await;
                });
            }
        });
        (addr, connections, rx)
    }

    fn approve_all() -> Rule {
        Rule {
            id: "ask-first".into(),
            description: String::new(),
            matches: rules::Match::default(),
            action: Action::Approve,
            severity: rules::Severity::Medium,
        }
    }

    async fn held(approvals: &crate::approve::Approvals) -> u64 {
        for _ in 0..100 {
            if let Some((id, held, _)) = approvals.pending().into_iter().next() {
                assert_eq!(held.rule, "ask-first");
                return id;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the request was never held");
    }

    #[tokio::test]
    async fn approval_holds_the_request_until_allowed() {
        use crate::approve::{Approvals, Verdict};
        let (upstream, connections, mut seen) = counting_upstream().await;
        let approvals = Arc::new(Approvals::new(Duration::from_secs(10), 4));
        let _window = approvals.attach();
        let settings = Settings {
            rules: vec![approve_all()],
            approvals: Some(approvals.clone()),
            ..Settings::default()
        };
        let (proxy, mut events) = start(settings).await;
        let mut client = TcpStream::connect(proxy).await.unwrap();
        let request = format!("GET http://{upstream}/held HTTP/1.1\r\nHost: {upstream}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();

        let id = held(&approvals).await;
        // While held, not even a connection reaches the upstream.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(approvals.answer(id, Verdict::AllowOnce));

        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(seen.recv().await.unwrap().starts_with("GET /held"));
        let event = next_event(&mut events).await;
        assert_eq!(
            (event.action, event.rule.as_deref(), event.reason),
            (
                Some(Action::Approve),
                Some("ask-first"),
                Some("approved once")
            )
        );
    }

    #[tokio::test]
    async fn denied_unanswered_and_windowless_approvals_block() {
        use crate::approve::{Approvals, Verdict};
        let (upstream, connections, _seen) = counting_upstream().await;
        let request = format!("GET http://{upstream}/x HTTP/1.1\r\nHost: {upstream}\r\n\r\n");

        // Denied in the window.
        let approvals = Arc::new(Approvals::new(Duration::from_secs(10), 4));
        let window = approvals.attach();
        let settings = Settings {
            rules: vec![approve_all()],
            approvals: Some(approvals.clone()),
            ..Settings::default()
        };
        let (proxy, mut events) = start(settings.clone()).await;
        let pending = tokio::spawn({
            let request = request.clone();
            async move { exchange(proxy, request.as_bytes()).await }
        });
        let id = held(&approvals).await;
        assert!(approvals.answer(id, Verdict::Deny));
        let response = pending.await.unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(
            response.contains("ask-first") && response.contains("approval denied"),
            "{response}"
        );
        assert_eq!(
            next_event(&mut events).await.reason,
            Some("approval denied")
        );

        // No window attached: blocked at once.
        drop(window);
        let response = exchange(proxy, request.as_bytes()).await;
        assert!(response.contains("no approval window"), "{response}");

        // No approval queue at all (no tray, e.g. not on Windows): blocked too.
        let (bare, _events) = start(Settings {
            approvals: None,
            ..settings
        })
        .await;
        let response = exchange(bare, request.as_bytes()).await;
        assert!(response.contains("no approval window"), "{response}");

        // Nobody answers: blocked when the time is up.
        let quick = Arc::new(Approvals::new(Duration::from_millis(200), 4));
        let _window = quick.attach();
        let (proxy, _events) = start(Settings {
            rules: vec![approve_all()],
            approvals: Some(quick),
            ..Settings::default()
        })
        .await;
        let response = exchange(proxy, request.as_bytes()).await;
        assert!(response.contains("approval timed out"), "{response}");

        assert_eq!(
            connections.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a blocked request never reaches the upstream"
        );
    }
}
