// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The egress proxy: the only way out of an Execution.
//!
//! Every connection is attributed to its Execution from the socket peer address before a single byte
//! of HTTP is read; a connection nobody can attribute is closed. Then each request is checked against
//! the destination policy, resolved once, validated address by address, and connected to an address
//! the policy already accepted.
//!
//! Two request shapes are accepted, as an explicit forward proxy does:
//!
//! * `CONNECT host:port` opens a byte tunnel, which is how HTTPS leaves the Execution;
//! * an absolute-form `http://` request is forwarded in origin form.
//!
//! # Phase-0 limitation
//!
//! Phase-0 CONNECT mediation authorizes the tunnel endpoint but does not provide L7 TLS identity
//! enforcement. Shared-IP/SNI-mismatch or domain-fronting-style behavior remains outside the Phase-0
//! security claim and is addressed by a later TLS mediation phase.

use std::convert::Infallible;
use std::error::Error as StdError;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use soglia_core::config::EgressConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tracing::{info, warn};

use crate::attribution::{AttributionResult, Binding, ConnectionAttributor};
use crate::policy::{DestinationPolicy, Host, Target};
use crate::resolver::Resolver;
use crate::tunnel::{self, TunnelEnd, TunnelLimits};

/// The body type of every response the proxy produces.
pub type ProxyBody = BoxBody<Bytes, Box<dyn StdError + Send + Sync>>;

/// Headers that describe one hop and never cross the proxy.
const HOP_BY_HOP: [HeaderName; 8] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    HeaderName::from_static("proxy-connection"),
    header::TE,
    header::TRAILER,
    header::UPGRADE,
];

/// The limits the egress proxy applies.
#[derive(Debug, Clone, Copy)]
pub struct EgressLimits {
    /// How long opening a connection to a destination may take.
    pub connect_timeout: Duration,
    /// How long a proxied exchange may stay silent.
    pub idle_timeout: Duration,
    /// The largest plain-HTTP request body forwarded.
    pub max_request_bytes: usize,
    /// The largest plain-HTTP response body relayed.
    pub max_response_bytes: usize,
    /// The most bytes one tunnel may carry.
    pub max_tunnel_bytes: u64,
}

impl EgressLimits {
    /// The limits a configuration asks for.
    pub fn from_config(config: &EgressConfig) -> Self {
        Self {
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            idle_timeout: Duration::from_millis(config.idle_timeout_ms),
            max_request_bytes: usize::try_from(config.max_request_bytes).unwrap_or(usize::MAX),
            max_response_bytes: usize::try_from(config.max_response_bytes).unwrap_or(usize::MAX),
            max_tunnel_bytes: config.max_tunnel_bytes,
        }
    }
}

/// The egress proxy.
pub struct EgressProxy {
    policy: Arc<DestinationPolicy>,
    attribution: Arc<dyn ConnectionAttributor>,
    resolver: Arc<dyn Resolver>,
    limits: EgressLimits,
    connections: Arc<Semaphore>,
    max_connections: usize,
    connection_high_water: AtomicUsize,
    connection_refused: AtomicU64,
}

/// Why a request was not proxied.
#[derive(Debug)]
enum Refusal {
    BadRequest(&'static str),
    Denied(String),
    Unresolvable(String),
    Unreachable(String),
    Timeout(String),
}

impl Refusal {
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Denied(_) => StatusCode::FORBIDDEN,
            Self::Unresolvable(_) | Self::Unreachable(_) => StatusCode::BAD_GATEWAY,
            Self::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    fn reason(&self) -> &str {
        match self {
            Self::BadRequest(reason) => reason,
            Self::Denied(reason)
            | Self::Unresolvable(reason)
            | Self::Unreachable(reason)
            | Self::Timeout(reason) => reason,
        }
    }
}

impl EgressProxy {
    /// A proxy over the given policy, attribution table and resolver.
    pub fn new(
        policy: Arc<DestinationPolicy>,
        attribution: Arc<dyn ConnectionAttributor>,
        resolver: Arc<dyn Resolver>,
        limits: EgressLimits,
    ) -> Self {
        Self::new_bounded(policy, attribution, resolver, limits, 512)
    }

    /// A proxy with an explicit bound on accepted connections with live tasks.
    pub fn new_bounded(
        policy: Arc<DestinationPolicy>,
        attribution: Arc<dyn ConnectionAttributor>,
        resolver: Arc<dyn Resolver>,
        limits: EgressLimits,
        max_connections: usize,
    ) -> Self {
        Self {
            policy,
            attribution,
            resolver,
            limits,
            connections: Arc::new(Semaphore::new(max_connections)),
            max_connections,
            connection_high_water: AtomicUsize::new(0),
            connection_refused: AtomicU64::new(0),
        }
    }

    /// Accepts connections on `listener` until `shutdown` turns true.
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) {
        loop {
            let accepted = tokio::select! {
                biased;
                _ = shutdown.wait_for(|stop| *stop) => return,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, peer)) => {
                    let Ok(connection_permit) = Arc::clone(&self.connections).try_acquire_owned()
                    else {
                        let refused_total = self
                            .connection_refused
                            .fetch_add(1, Ordering::Relaxed)
                            .saturating_add(1);
                        warn!(
                            event.name = "egress.connection_limit",
                            limit = self.max_connections,
                            refused_total,
                            "egress connection refused before attribution or application reads"
                        );
                        drop(stream);
                        continue;
                    };
                    let active = self
                        .max_connections
                        .saturating_sub(self.connections.available_permits());
                    self.connection_high_water
                        .fetch_max(active, Ordering::Relaxed);
                    tracing::debug!(
                        event.name = "egress.connection_occupancy",
                        active,
                        high_water = self.connection_high_water.load(Ordering::Relaxed),
                        limit = self.max_connections,
                        refused_total = self.connection_refused.load(Ordering::Relaxed),
                        "bounded egress connection occupancy"
                    );
                    let proxy = Arc::clone(&self);
                    let connection_shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        let _connection_permit = connection_permit;
                        proxy.connection(stream, peer, connection_shutdown).await;
                    });
                }
                Err(error) => warn!(event.name = "egress.accept_failed", %error, "accept failed"),
            }
        }
    }

    async fn connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        mut shutdown: watch::Receiver<bool>,
    ) {
        // Attribution comes from the kernel's view of the peer, before any byte from the agent is
        // read. Nothing the agent sends can change which Execution this connection belongs to.
        let local = match stream.local_addr() {
            Ok(local) => local,
            Err(error) => {
                warn!(event.name = "egress.local_address_failed", peer = %peer, %error, "an accepted connection was closed");
                return;
            }
        };
        let binding = match self.attribution.resolve(peer, local).await {
            AttributionResult::Resolved(binding) => binding,
            denied => {
                warn!(
                    event.name = "egress.unattributed",
                    peer = %peer,
                    result = ?denied,
                    "an unattributed connection was closed before application reads"
                );
                return;
            }
        };

        let mut revoked = binding.clone();
        let proxy = Arc::clone(&self);
        let request_shutdown = shutdown.clone();
        let service = service_fn(move |request| {
            let proxy = Arc::clone(&proxy);
            let binding = binding.clone();
            let shutdown = request_shutdown.clone();
            async move { Ok::<_, Infallible>(proxy.handle(binding, request, shutdown).await) }
        });
        let connection = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades();

        tokio::select! {
            biased;
            _ = shutdown.wait_for(|stop| *stop) => {}
            result = connection => {
                if let Err(error) = result {
                    warn!(event.name = "egress.connection_failed", peer = %peer, %error, "connection ended with an error");
                }
            }
            () = revoked.revoked() => {}
        }
    }

    async fn handle(
        self: Arc<Self>,
        binding: Binding,
        request: Request<Incoming>,
        shutdown: watch::Receiver<bool>,
    ) -> Response<ProxyBody> {
        let method = request.method().clone();
        let presented = request.uri().to_string();
        let outcome = if method == Method::CONNECT {
            self.connect(binding.clone(), request, shutdown).await
        } else {
            self.forward(request).await
        };

        match outcome {
            Ok(response) => {
                info!(
                    event.name = "egress.allowed",
                    execution_id = %binding.id,
                    method = %method,
                    target = %presented,
                    status = response.status().as_u16(),
                    "egress request allowed"
                );
                response
            }
            Err(refusal) => {
                warn!(
                    event.name = "egress.denied",
                    execution_id = %binding.id,
                    method = %method,
                    target = %presented,
                    status = refusal.status().as_u16(),
                    reason = refusal.reason(),
                    "egress request refused"
                );
                let mut response = plain(refusal.status(), refusal.reason().to_owned());
                // A refused exchange ends the connection: nothing further on it is trusted.
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
                response
            }
        }
    }

    /// `CONNECT host:port`: authorize, resolve once, validate, connect, tunnel.
    async fn connect(
        self: Arc<Self>,
        binding: Binding,
        request: Request<Incoming>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<Response<ProxyBody>, Refusal> {
        let authority = request
            .uri()
            .authority()
            .ok_or(Refusal::BadRequest("CONNECT needs a host:port target"))?;
        if authority.as_str().contains('@') {
            return Err(Refusal::BadRequest(
                "a CONNECT target may not carry user information",
            ));
        }
        let port = authority
            .port_u16()
            .ok_or(Refusal::BadRequest("CONNECT needs an explicit port"))?;
        let target = self
            .policy
            .authorize(authority.host(), port)
            .map_err(|denial| Refusal::Denied(denial.to_string()))?;
        let (upstream, _) = self.open(&target).await?;

        let limits = TunnelLimits {
            idle: self.limits.idle_timeout,
            max_bytes: self.limits.max_tunnel_bytes,
        };
        let id = binding.id;
        tokio::spawn(async move {
            let tunnel = async {
                match hyper::upgrade::on(request).await {
                    Ok(upgraded) => {
                        let end =
                            tunnel::run(TokioIo::new(upgraded), upstream, limits, binding).await;
                        let end = match end {
                            TunnelEnd::Closed(Ok(_)) => "closed",
                            TunnelEnd::Closed(Err(_)) => "failed",
                            TunnelEnd::Idle => "idle",
                            TunnelEnd::ByteLimit => "byte-limit",
                            TunnelEnd::Revoked => "execution-teardown",
                        };
                        info!(event.name = "egress.tunnel_ended", execution_id = %id, end, "tunnel ended");
                    }
                    Err(error) => {
                        warn!(event.name = "egress.upgrade_failed", execution_id = %id, %error, "CONNECT upgrade failed");
                    }
                }
            };
            tokio::select! {
                biased;
                _ = shutdown.wait_for(|stop| *stop) => {
                    info!(event.name = "egress.tunnel_ended", execution_id = %id, end = "runtime-shutdown", "tunnel ended");
                }
                () = tunnel => {}
            }
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(empty())
            .unwrap_or_else(|_| plain(StatusCode::INTERNAL_SERVER_ERROR, String::new())))
    }

    /// An absolute-form `http://` request: authorize, resolve once, validate, forward.
    async fn forward(&self, request: Request<Incoming>) -> Result<Response<ProxyBody>, Refusal> {
        let uri = request.uri().clone();
        match uri.scheme_str() {
            Some("http") => {}
            Some(_) => {
                return Err(Refusal::BadRequest(
                    "only http:// is forwarded; HTTPS must use CONNECT",
                ));
            }
            None => {
                return Err(Refusal::BadRequest(
                    "a proxy request must be in absolute form",
                ));
            }
        }
        let authority = uri
            .authority()
            .ok_or(Refusal::BadRequest("the request has no host"))?;
        if authority.as_str().contains('@') {
            return Err(Refusal::BadRequest(
                "the request target may not carry user information",
            ));
        }
        // The Host header must say what the request line says; otherwise the destination could be
        // told a different name than the one the policy approved.
        if let Some(host) = request.headers().get(header::HOST) {
            let matches = host
                .to_str()
                .is_ok_and(|value| value.eq_ignore_ascii_case(authority.as_str()));
            if !matches {
                return Err(Refusal::BadRequest(
                    "the Host header does not match the request target",
                ));
            }
        }
        let port = authority.port_u16().unwrap_or(80);
        let target = self
            .policy
            .authorize(authority.host(), port)
            .map_err(|denial| Refusal::Denied(denial.to_string()))?;
        let (upstream, address) = self.open(&target).await?;

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(upstream))
                .await
                .map_err(|error| Refusal::Unreachable(format!("{address}: {error}")))?;
        tokio::spawn(connection);

        let (parts, body) = request.into_parts();
        let origin_form = uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .parse::<Uri>()
            .map_err(|_| Refusal::BadRequest("the request path is malformed"))?;
        let mut outbound = Request::builder()
            .method(parts.method)
            .uri(origin_form)
            .version(Version::HTTP_11)
            .body(
                Limited::new(body, self.limits.max_request_bytes)
                    .map_err(|error| error as Box<dyn StdError + Send + Sync>)
                    .boxed(),
            )
            .map_err(|_| Refusal::BadRequest("the request could not be rebuilt"))?;
        *outbound.headers_mut() = forwardable(&parts.headers);
        let host = HeaderValue::from_str(authority.as_str())
            .map_err(|_| Refusal::BadRequest("the request host is malformed"))?;
        outbound.headers_mut().insert(header::HOST, host);

        let response =
            tokio::time::timeout(self.limits.idle_timeout, sender.send_request(outbound))
                .await
                .map_err(|_| Refusal::Timeout(format!("{address} did not answer in time")))?
                .map_err(|error| Refusal::Unreachable(format!("{address}: {error}")))?;

        let (mut parts, body) = response.into_parts();
        parts.headers = forwardable(&parts.headers);
        let body = Limited::new(body, self.limits.max_response_bytes)
            .map_err(|error| error as Box<dyn StdError + Send + Sync>)
            .boxed();

        Ok(Response::from_parts(parts, body))
    }

    /// Resolves `target` once, validates every candidate, and connects to one that passed.
    async fn open(&self, target: &Target) -> Result<(TcpStream, SocketAddr), Refusal> {
        let resolved: Vec<IpAddr> = match &target.host {
            Host::Ip(address) => vec![*address],
            Host::Name(name) => self
                .resolver
                .resolve(name)
                .await
                .map_err(|error| Refusal::Unresolvable(format!("{name}: {error}")))?,
        };
        let candidates = self
            .policy
            .validate(target, &resolved)
            .map_err(|denial| Refusal::Denied(denial.to_string()))?;

        let mut last =
            Refusal::Unreachable(format!("{}: no address accepted a connection", target.host));
        for candidate in candidates {
            match tokio::time::timeout(self.limits.connect_timeout, TcpStream::connect(candidate))
                .await
            {
                Ok(Ok(stream)) => return Ok((stream, candidate)),
                Ok(Err(error)) => last = Refusal::Unreachable(format!("{candidate}: {error}")),
                Err(_) => last = Refusal::Timeout(format!("{candidate}: connection timed out")),
            }
        }

        Err(last)
    }
}

/// Copies the headers that may cross the proxy.
fn forwardable(headers: &HeaderMap) -> HeaderMap {
    let mut kept = headers.clone();
    // A `Connection` header may name further hop-by-hop headers.
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in HOP_BY_HOP.iter().chain(named.iter()) {
        kept.remove(name);
    }

    kept
}

fn empty() -> ProxyBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

fn plain(status: StatusCode, message: String) -> Response<ProxyBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(message))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::AttributionTable;
    use crate::resolver::fixed::FixedResolver;
    use soglia_core::ExecutionId;
    use soglia_core::config::{EgressRule, NetworkConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Harness {
        proxy: SocketAddr,
        attribution: Arc<AttributionTable>,
        shutdown: watch::Sender<bool>,
    }

    fn limits() -> EgressLimits {
        EgressLimits {
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            max_request_bytes: 1024,
            max_response_bytes: 1 << 20,
            max_tunnel_bytes: 1 << 20,
        }
    }

    /// A proxy whose policy allows `allowed.test` and `bound.test` on `port`, and optionally
    /// reaches loopback, which is how the tests can host a destination at all.
    async fn harness(
        port: u16,
        resolver: FixedResolver,
        loopback: bool,
        attribute: bool,
    ) -> Harness {
        harness_with_resolver(port, Arc::new(resolver), loopback, attribute).await
    }

    async fn harness_with_resolver(
        port: u16,
        resolver: Arc<dyn Resolver>,
        loopback: bool,
        attribute: bool,
    ) -> Harness {
        let egress = EgressConfig {
            allow: vec![
                EgressRule {
                    host: "allowed.test".into(),
                    ports: vec![port],
                },
                EgressRule {
                    host: "bound.test".into(),
                    ports: vec![port],
                },
            ],
            ..EgressConfig::default()
        };
        let mut policy =
            DestinationPolicy::new(&egress, &NetworkConfig::default(), Vec::new()).unwrap();
        if loopback {
            policy = policy.allowing_loopback_for_tests();
        }
        let attribution = Arc::new(AttributionTable::new());
        if attribute {
            attribution
                .bind(
                    "127.0.0.1".parse().unwrap(),
                    ExecutionId::generate().unwrap(),
                )
                .unwrap();
        }
        let proxy = Arc::new(EgressProxy::new(
            Arc::new(policy),
            attribution.clone(),
            resolver,
            limits(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stop) = watch::channel(false);
        tokio::spawn(proxy.serve(listener, stop));

        Harness {
            proxy: address,
            attribution,
            shutdown,
        }
    }

    /// A destination that echoes what it receives.
    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        address
    }

    /// A destination that answers every HTTP request with the request line and Host it saw.
    async fn http_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let service = service_fn(|request: Request<Incoming>| async move {
                        let host = request
                            .headers()
                            .get(header::HOST)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        let seen = format!(
                            "{} {} host={host} proxy-auth={}",
                            request.method(),
                            request.uri(),
                            request.headers().contains_key(header::PROXY_AUTHORIZATION)
                        );
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(seen))))
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        address
    }

    /// Reads a response head, up to and including the blank line.
    async fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    async fn exchange(proxy: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn an_allowed_connect_tunnels_bytes() {
        let upstream = echo_server().await;
        let resolver = FixedResolver::default().with("allowed.test", &["127.0.0.1"]);
        let harness = harness(upstream.port(), resolver, true, true).await;

        let mut stream = TcpStream::connect(harness.proxy).await.unwrap();
        let request = format!(
            "CONNECT allowed.test:{port} HTTP/1.1\r\nHost: allowed.test:{port}\r\n\r\n",
            port = upstream.port()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let head = read_head(&mut stream).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");

        stream.write_all(b"through the tunnel").await.unwrap();
        let mut echoed = [0_u8; 18];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"through the tunnel");
    }

    #[tokio::test]
    async fn a_connect_to_an_unlisted_host_is_forbidden() {
        let upstream = echo_server().await;
        let resolver = FixedResolver::default().with("other.test", &["127.0.0.1"]);
        let harness = harness(upstream.port(), resolver, true, true).await;

        let response = exchange(
            harness.proxy,
            &format!(
                "CONNECT other.test:{0} HTTP/1.1\r\nHost: other.test:{0}\r\n\r\n",
                upstream.port()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    }

    #[tokio::test]
    async fn an_allowed_name_resolving_to_a_forbidden_address_is_forbidden() {
        // The real policy, no loopback exception: this is H1 at the unit level.
        for answers in [
            &["127.0.0.1"][..],
            &["93.184.216.34", "169.254.169.254"][..],
            &["10.201.0.5"][..],
            &["::ffff:127.0.0.1"][..],
        ] {
            let resolver = FixedResolver::default().with("allowed.test", answers);
            let harness = harness(443, resolver, false, true).await;
            let response = exchange(
                harness.proxy,
                "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n",
            )
            .await;
            assert!(
                response.starts_with("HTTP/1.1 403"),
                "{answers:?}: {response}"
            );
        }
    }

    #[tokio::test]
    async fn an_unattributed_connection_is_closed_without_an_answer() {
        let upstream = echo_server().await;
        let resolver = FixedResolver::default().with("allowed.test", &["127.0.0.1"]);
        let harness = harness(upstream.port(), resolver, true, false).await;

        let response = exchange(
            harness.proxy,
            &format!(
                "CONNECT allowed.test:{0} HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
                upstream.port()
            ),
        )
        .await;
        assert!(response.is_empty(), "{response}");
    }

    #[tokio::test]
    async fn a_revoked_execution_loses_its_open_tunnel() {
        let upstream = echo_server().await;
        let resolver = FixedResolver::default().with("allowed.test", &["127.0.0.1"]);
        let harness = harness(upstream.port(), resolver, true, true).await;

        let mut stream = TcpStream::connect(harness.proxy).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT allowed.test:{0} HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
                    upstream.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let head = read_head(&mut stream).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");

        harness.attribution.revoke("127.0.0.1".parse().unwrap());
        let mut rest = Vec::new();
        let closed =
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut rest)).await;
        assert!(
            closed.is_ok(),
            "the tunnel must close when its Execution tears down"
        );
    }

    #[tokio::test]
    async fn runtime_cancellation_closes_an_open_tunnel() {
        let upstream = echo_server().await;
        let resolver = FixedResolver::default().with("allowed.test", &["127.0.0.1"]);
        let harness = harness(upstream.port(), resolver, true, true).await;

        let mut stream = TcpStream::connect(harness.proxy).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT allowed.test:{0} HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
                    upstream.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let head = read_head(&mut stream).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        stream.write_all(b"before shutdown").await.unwrap();
        let mut echoed = [0_u8; 15];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"before shutdown");

        harness.shutdown.send_replace(true);
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut rest))
            .await
            .expect("runtime cancellation must close the tunnel");
        assert_eq!(closed.unwrap(), 0);
    }

    struct BlockingResolver {
        started: Arc<tokio::sync::Notify>,
        dropped: Arc<tokio::sync::Notify>,
    }

    impl Resolver for BlockingResolver {
        fn resolve<'a>(&'a self, _name: &'a str) -> crate::resolver::Resolution<'a> {
            let started = Arc::clone(&self.started);
            let dropped = Arc::clone(&self.dropped);
            Box::pin(async move {
                struct DropNotice(Arc<tokio::sync::Notify>);
                impl Drop for DropNotice {
                    fn drop(&mut self) {
                        self.0.notify_one();
                    }
                }
                let _notice = DropNotice(dropped);
                started.notify_one();
                std::future::pending().await
            })
        }
    }

    #[tokio::test]
    async fn runtime_cancellation_drops_pending_dns() {
        let started = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(tokio::sync::Notify::new());
        let resolver = Arc::new(BlockingResolver {
            started: Arc::clone(&started),
            dropped: Arc::clone(&dropped),
        });
        let harness = harness_with_resolver(443, resolver, true, true).await;

        let mut stream = TcpStream::connect(harness.proxy).await.unwrap();
        stream
            .write_all(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .expect("the DNS operation did not start");

        harness.shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), dropped.notified())
            .await
            .expect("the pending DNS future was not cancelled");
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut rest))
            .await
            .expect("runtime cancellation must close the proxy connection")
            .unwrap();
    }

    #[tokio::test]
    async fn an_absolute_form_request_is_forwarded_in_origin_form() {
        let upstream = http_server().await;
        let resolver = FixedResolver::default().with("allowed.test", &["127.0.0.1"]);
        let harness = harness(upstream.port(), resolver, true, true).await;

        let response = exchange(
            harness.proxy,
            &format!(
                "GET http://allowed.test:{0}/data?q=1 HTTP/1.1\r\nHost: allowed.test:{0}\r\nProxy-Authorization: Basic eA==\r\nConnection: close\r\n\r\n",
                upstream.port()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.contains(&format!(
                "GET /data?q=1 host=allowed.test:{} proxy-auth=false",
                upstream.port()
            )),
            "{response}"
        );
    }

    #[tokio::test]
    async fn malformed_proxy_requests_are_refused() {
        let upstream = http_server().await;
        let resolver = FixedResolver::default().with("allowed.test", &["127.0.0.1"]);
        let harness = harness(upstream.port(), resolver, true, true).await;
        let port = upstream.port();

        for (request, status) in [
            (
                format!(
                    "GET https://allowed.test:{port}/ HTTP/1.1\r\nHost: allowed.test:{port}\r\n\r\n"
                ),
                "400",
            ),
            (
                "GET /relative HTTP/1.1\r\nHost: allowed.test\r\n\r\n".to_owned(),
                "400",
            ),
            (
                format!("GET http://allowed.test:{port}/ HTTP/1.1\r\nHost: evil.test\r\n\r\n"),
                "400",
            ),
            (
                format!(
                    "GET http://allowed.test:{}/ HTTP/1.1\r\nHost: allowed.test:{}\r\n\r\n",
                    port + 1,
                    port + 1
                ),
                "403",
            ),
            (
                format!("CONNECT 127.1:{port} HTTP/1.1\r\nHost: 127.1:{port}\r\n\r\n"),
                "403",
            ),
        ] {
            let response = exchange(harness.proxy, &request).await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{request}: {response}"
            );
        }
    }

    #[test]
    fn hop_by_hop_headers_do_not_cross() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("close, x-private"),
        );
        headers.insert("x-private", HeaderValue::from_static("1"));
        headers.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic eA=="),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        let kept = forwardable(&headers);
        assert!(kept.contains_key(header::ACCEPT));
        assert!(!kept.contains_key(header::CONNECTION));
        assert!(!kept.contains_key("x-private"));
        assert!(!kept.contains_key(header::PROXY_AUTHORIZATION));
    }
}
