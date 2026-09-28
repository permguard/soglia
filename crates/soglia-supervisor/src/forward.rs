// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The trusted ingress direction: from the Supervisor to the agent's listener.
//!
//! The host policy lets only the Supervisor's user open connections toward an Execution, and only to
//! the configured agent port. The answer is read into a bounded buffer; nothing is streamed, because
//! nothing may reach the caller before the Execution is destroyed.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper_util::rt::TokioIo;
use soglia_proxy::ingress::Invocation;
use tokio::net::TcpStream;
use tokio::time::Instant;

/// The agent's answer, buffered.
#[derive(Debug)]
pub struct Answer {
    /// Its status.
    pub status: StatusCode,
    /// Its content type.
    pub content_type: Option<HeaderValue>,
    /// Its body.
    pub body: Bytes,
}

/// Why the exchange with the agent failed.
#[derive(Debug)]
pub enum ForwardError {
    /// The agent's listener refused or dropped the connection.
    Connect(String),
    /// The HTTP exchange failed, typically because the agent died.
    Exchange(String),
    /// The answer exceeds the buffer.
    TooLarge,
}

impl fmt::Display for ForwardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(reason) => write!(formatter, "cannot reach the agent: {reason}"),
            Self::Exchange(reason) => write!(formatter, "the exchange failed: {reason}"),
            Self::TooLarge => formatter.write_str("the answer is too large"),
        }
    }
}

impl std::error::Error for ForwardError {}

/// `true` once the agent's listener accepts a connection; `false` if `timeout` passes first.
pub async fn wait_ready(listener: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let attempt =
            tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(listener)).await;
        if matches!(attempt, Ok(Ok(_))) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    false
}

/// Forwards the invocation to the agent and buffers its answer, up to `max_response` bytes.
pub async fn invoke(
    listener: SocketAddr,
    path: &str,
    invocation: &Invocation,
    max_response: usize,
) -> Result<Answer, ForwardError> {
    let stream = TcpStream::connect(listener)
        .await
        .map_err(|error| ForwardError::Connect(error.to_string()))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| ForwardError::Exchange(error.to_string()))?;
    tokio::spawn(connection);

    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, "agent")
        .body(Full::new(invocation.body.clone()))
        .map_err(|error| ForwardError::Exchange(error.to_string()))?;
    if let Some(content_type) = &invocation.content_type {
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type.clone());
    }

    let response = sender
        .send_request(request)
        .await
        .map_err(|error| ForwardError::Exchange(error.to_string()))?;
    let status = response.status();
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let body = Limited::new(response.into_body(), max_response)
        .collect()
        .await
        .map_err(|error| {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                ForwardError::TooLarge
            } else {
                ForwardError::Exchange(error.to_string())
            }
        })?
        .to_bytes();

    Ok(Answer {
        status,
        content_type,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    use http::Response;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use tokio::net::{TcpListener, TcpSocket};

    async fn agent(body: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| async move {
                        let seen = request.uri().path().to_owned();
                        let echo = request.into_body().collect().await.unwrap().to_bytes();
                        let mut response = Response::new(Full::new(if body.is_empty() {
                            Bytes::from(format!("{seen} {}", String::from_utf8_lossy(&echo)))
                        } else {
                            Bytes::from_static(body)
                        }));
                        response
                            .headers_mut()
                            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                        Ok::<_, Infallible>(response)
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        address
    }

    fn invocation(body: &'static [u8]) -> Invocation {
        Invocation {
            agent: "echo".into(),
            body: Bytes::from_static(body),
            content_type: None,
        }
    }

    #[tokio::test]
    async fn the_invocation_reaches_the_agent_and_its_answer_is_buffered() {
        let listener = agent(b"").await;
        assert!(wait_ready(listener, Duration::from_secs(1)).await);
        let answer = invoke(listener, "/run", &invocation(b"hello"), 1024)
            .await
            .unwrap();
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.body, Bytes::from_static(b"/run hello"));
        assert_eq!(answer.content_type.unwrap(), "text/plain");
    }

    #[tokio::test]
    async fn an_oversized_answer_is_refused() {
        let listener = agent(&[b'x'; 2048]).await;
        let refused = invoke(listener, "/", &invocation(b""), 1024)
            .await
            .unwrap_err();
        assert!(matches!(refused, ForwardError::TooLarge), "{refused}");
    }

    #[tokio::test]
    async fn an_absent_listener_is_never_ready() {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = socket.local_addr().unwrap();
        assert!(!wait_ready(address, Duration::from_millis(200)).await);
    }
}
