// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The ingress proxy: the only way into an Execution.
//!
//! `POST /v1/execute/{agent}` creates one fresh Execution, forwards the request body to the agent,
//! and answers only after the Execution has been completely destroyed. The response is buffered for
//! exactly that reason: when the caller receives success, the Execution that produced it no longer
//! exists. The ingress does not stream.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use soglia_core::ExecutionId;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::warn;

/// One invocation, as the caller sent it.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// The configured agent to run.
    pub agent: String,
    /// The request body, forwarded to the agent as it is.
    pub body: Bytes,
    /// The request's content type, forwarded when present.
    pub content_type: Option<HeaderValue>,
}

/// What an invocation came to.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The agent answered and its Execution was destroyed; the answer is released as it is.
    Answered {
        /// The Execution that produced it.
        execution: ExecutionId,
        /// The agent's status.
        status: StatusCode,
        /// The agent's content type.
        content_type: Option<HeaderValue>,
        /// The agent's body.
        body: Bytes,
    },
    /// Soglia refused or failed the invocation.
    Refused {
        /// The Execution, when one was created.
        execution: Option<ExecutionId>,
        /// The status the caller receives.
        status: StatusCode,
        /// Why, for the caller and the log.
        reason: String,
    },
}

/// A boxed invocation in progress.
pub type Execution<'a> = Pin<Box<dyn Future<Output = Outcome> + Send + 'a>>;

/// What runs an invocation from start to verified teardown.
pub trait Executor: Send + Sync {
    /// Runs `invocation` and resolves only after its Execution is gone, or was never created.
    fn execute(&self, invocation: Invocation) -> Execution<'_>;
}

/// The ingress limits.
#[derive(Debug, Clone, Copy)]
pub struct IngressLimits {
    /// The largest request body accepted.
    pub max_request_bytes: usize,
}

/// Accepts invocations on `listener` until `shutdown` turns true.
pub async fn serve(
    listener: TcpListener,
    executor: Arc<dyn Executor>,
    limits: IngressLimits,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.wait_for(|stop| *stop) => return,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                warn!(event.name = "ingress.accept_failed", %error, "accept failed");
                continue;
            }
        };
        let executor = Arc::clone(&executor);
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let executor = Arc::clone(&executor);
                async move { Ok::<_, Infallible>(handle(executor, limits, request).await) }
            });
            if let Err(error) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                warn!(event.name = "ingress.connection_failed", peer = %peer, %error, "ingress connection ended with an error");
            }
        });
    }
}

async fn handle(
    executor: Arc<dyn Executor>,
    limits: IngressLimits,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let Some(agent) = request
        .uri()
        .path()
        .strip_prefix("/v1/execute/")
        .filter(|agent| !agent.is_empty() && !agent.contains('/'))
        .map(ToOwned::to_owned)
    else {
        return refusal(
            None,
            StatusCode::NOT_FOUND,
            "the path is /v1/execute/{agent}",
        );
    };
    if request.method() != Method::POST {
        return refusal(
            None,
            StatusCode::METHOD_NOT_ALLOWED,
            "an invocation is a POST",
        );
    }
    let content_type = request.headers().get(header::CONTENT_TYPE).cloned();
    let body = match Limited::new(request.into_body(), limits.max_request_bytes)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return refusal(
                None,
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request body exceeds ingress.max_request_bytes",
            );
        }
    };

    match executor
        .execute(Invocation {
            agent,
            body,
            content_type,
        })
        .await
    {
        Outcome::Answered {
            execution,
            status,
            content_type,
            body,
        } => {
            let mut response = Response::new(Full::new(body));
            *response.status_mut() = status;
            if let Some(content_type) = content_type {
                response
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, content_type);
            }
            insert_execution(&mut response, Some(execution));
            response
        }
        Outcome::Refused {
            execution,
            status,
            reason,
        } => refusal(execution, status, &reason),
    }
}

fn refusal(
    execution: Option<ExecutionId>,
    status: StatusCode,
    reason: &str,
) -> Response<Full<Bytes>> {
    let body = match execution {
        Some(id) => format!(
            "{{\"error\":{},\"execution_id\":\"{id}\"}}",
            json_string(reason)
        ),
        None => format!("{{\"error\":{}}}", json_string(reason)),
    };
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    insert_execution(&mut response, execution);
    response
}

/// Tells the caller which Execution served it, for correlation with the logs. Nothing reads this
/// header back: identity inside Soglia never comes from a header.
fn insert_execution(response: &mut Response<Full<Bytes>>, execution: Option<ExecutionId>) {
    if let Some(id) = execution
        && let Ok(value) = HeaderValue::from_str(&id.to_string())
    {
        response.headers_mut().insert("soglia-execution-id", value);
    }
}

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            control if control.is_control() => {
                out.push_str(&format!("\\u{:04x}", u32::from(control)))
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// An executor that records what it was asked and answers from a script.
    struct Scripted {
        seen: Mutex<Vec<Invocation>>,
        answer: Outcome,
    }

    impl Executor for Scripted {
        fn execute(&self, invocation: Invocation) -> Execution<'_> {
            self.seen.lock().unwrap().push(invocation);
            let answer = self.answer.clone();
            Box::pin(async move { answer })
        }
    }

    async fn ingress(answer: Outcome) -> (SocketAddr, Arc<Scripted>, watch::Sender<bool>) {
        let executor = Arc::new(Scripted {
            seen: Mutex::new(Vec::new()),
            answer,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = watch::channel(false);
        tokio::spawn(serve(
            listener,
            Arc::clone(&executor) as Arc<dyn Executor>,
            IngressLimits {
                max_request_bytes: 64,
            },
            stopped,
        ));
        (address, executor, stop)
    }

    async fn post(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await;
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn an_invocation_reaches_the_executor_and_its_answer_the_caller() {
        let id = ExecutionId::generate().unwrap();
        let (address, executor, _stop) = ingress(Outcome::Answered {
            execution: id,
            status: StatusCode::OK,
            content_type: Some(HeaderValue::from_static("text/plain")),
            body: Bytes::from_static(b"done"),
        })
        .await;

        let response = post(
            address,
            "POST /v1/execute/echo HTTP/1.1\r\nHost: soglia\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("done"), "{response}");
        assert!(
            response.contains(&format!("soglia-execution-id: {id}")),
            "{response}"
        );

        let seen = executor.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].agent, "echo");
        assert_eq!(seen[0].body, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn a_refusal_is_reported_as_json_with_its_status() {
        let id = ExecutionId::generate().unwrap();
        let (address, _executor, _stop) = ingress(Outcome::Refused {
            execution: Some(id),
            status: StatusCode::GATEWAY_TIMEOUT,
            reason: "the agent \"echo\" timed out".into(),
        })
        .await;

        let response = post(
            address,
            "POST /v1/execute/echo HTTP/1.1\r\nHost: soglia\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 504"), "{response}");
        assert!(
            response.contains(r#"{"error":"the agent \"echo\" timed out","execution_id":""#),
            "{response}"
        );
    }

    #[tokio::test]
    async fn malformed_invocations_never_reach_the_executor() {
        let (address, executor, _stop) = ingress(Outcome::Refused {
            execution: None,
            status: StatusCode::OK,
            reason: String::new(),
        })
        .await;

        for (request, status) in [
            (
                "GET /v1/execute/echo HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                "405",
            ),
            (
                "POST /v1/other HTTP/1.1\r\nHost: s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "404",
            ),
            (
                "POST /v1/execute/ HTTP/1.1\r\nHost: s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "404",
            ),
            (
                "POST /v1/execute/a/b HTTP/1.1\r\nHost: s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "404",
            ),
        ] {
            let response = post(address, request).await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{request}: {response}"
            );
        }
        let oversized = format!(
            "POST /v1/execute/echo HTTP/1.1\r\nHost: s\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}",
            "x".repeat(100)
        );
        let response = post(address, &oversized).await;
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
        assert!(executor.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn reasons_are_escaped_as_json() {
        assert_eq!(json_string("a\"b\\c\nd\u{1}"), r#""a\"b\\c\nd\u0001""#);
    }
}
