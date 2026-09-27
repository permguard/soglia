// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The privileged helper processes and the channel to each.
//!
//! The original trusted process — still root — creates one socketpair per helper, starts the helper
//! by re-executing the Soglia binary in its role, and hands it exactly one end as its standard input.
//! It keeps exactly the other end. The helper inherits no other descriptor: the standard library
//! opens everything close-on-exec. There is no socket path, so nothing else — least of all an
//! Execution — can connect to the channel.
//!
//! What authenticates the Supervisor to a helper is possession of that descriptor. `SO_PEERCRED`
//! would report the credentials at socketpair creation, which were root, and says nothing about the
//! Supervisor after it dropped privileges, so it is not used as proof.

use std::fmt;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use soglia_core::helper::{Hello, HelperResponse};
use soglia_core::ipc::{read_frame, write_frame};

/// Why a helper exchange failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperError {
    /// The channel broke: the helper is gone, and the runtime cannot continue safely.
    Channel(String),
    /// The helper carried out the request and it failed.
    Failed(String),
    /// The helper answered with something the request does not allow.
    Unexpected(String),
}

impl fmt::Display for HelperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(reason) => write!(formatter, "the helper channel failed: {reason}"),
            Self::Failed(reason) => write!(formatter, "{reason}"),
            Self::Unexpected(reason) => write!(formatter, "unexpected helper answer: {reason}"),
        }
    }
}

impl std::error::Error for HelperError {}

/// One privileged helper.
pub struct Helper {
    role: &'static str,
    channel: Arc<Mutex<UnixStream>>,
    process: Mutex<Child>,
}

impl Helper {
    /// Starts `executable` in `role` with one end of a fresh socketpair as its standard input.
    pub fn spawn(executable: &Path, role: &'static str) -> io::Result<Self> {
        let (ours, theirs) = UnixStream::pair()?;
        let process = Command::new(executable)
            .arg(format!("__{role}"))
            .env_clear()
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        Ok(Self {
            role,
            channel: Arc::new(Mutex::new(ours)),
            process: Mutex::new(process),
        })
    }

    /// The helper's role, for logs.
    pub fn role(&self) -> &'static str {
        self.role
    }

    /// Sends the configuration and waits until the helper has swept and is ready. Blocking: it runs
    /// before the async runtime exists.
    pub fn hello(&self, config_yaml: &str) -> Result<Vec<String>, HelperError> {
        let hello = Hello {
            config_yaml: config_yaml.to_owned(),
        };
        match exchange(&self.channel, &hello)? {
            HelperResponse::Ready { swept } => Ok(swept),
            HelperResponse::Failed { reason } => Err(HelperError::Failed(reason)),
            other => Err(HelperError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Sends one request and waits for its answer, off the async executor.
    ///
    /// The request and its answer are exchanged under one lock, so an exchange that outlives the
    /// caller — a timed-out Execution — still completes as a pair and leaves the channel in step.
    pub async fn call<R>(&self, request: R) -> Result<HelperResponse, HelperError>
    where
        R: Serialize + Send + 'static,
    {
        let channel = Arc::clone(&self.channel);
        let answer = tokio::task::spawn_blocking(move || exchange(&channel, &request))
            .await
            .map_err(|error| HelperError::Channel(error.to_string()))??;
        match answer {
            HelperResponse::Failed { reason } => Err(HelperError::Failed(reason)),
            other => Ok(other),
        }
    }
}

/// How long a helper may take to clean up and exit once its channel closes.
const EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

impl Drop for Helper {
    /// Closes the channel and waits for the helper to finish: on end of input it kills or freezes
    /// whatever is still live, and the runtime should not report itself stopped before that is done.
    fn drop(&mut self) {
        if let Ok(stream) = self.channel.lock() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let Ok(mut process) = self.process.lock() else {
            return;
        };
        let started = std::time::Instant::now();
        while started.elapsed() < EXIT_GRACE {
            if !matches!(process.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        eprintln!(
            "soglia: the {} helper did not exit after its channel closed",
            self.role
        );
    }
}

fn exchange<R: Serialize>(
    channel: &Mutex<UnixStream>,
    request: &R,
) -> Result<HelperResponse, HelperError> {
    let mut stream = channel
        .lock()
        .map_err(|_| HelperError::Channel("the channel lock is poisoned".to_owned()))?;
    write_frame(&mut *stream, request).map_err(|error| HelperError::Channel(error.to_string()))?;
    read_frame(&mut *stream).map_err(|error| HelperError::Channel(error.to_string()))
}
