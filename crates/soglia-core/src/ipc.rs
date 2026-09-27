// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Framing for the channel between the Supervisor and a privileged helper.
//!
//! The channel is one end of a socketpair the original trusted process created before dropping
//! privileges; there is no socket path anyone else could connect to. What protects it is who holds
//! the descriptors, not `SO_PEERCRED`, which records the credentials at creation time and says
//! nothing about the Supervisor after the drop.
//!
//! Each frame is a 4-byte big-endian length followed by that many bytes of JSON. Framing is strict:
//! an oversized frame, a truncated frame or a body that does not decode as the expected message ends
//! the conversation instead of being skipped.

use std::fmt;
use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The largest frame either side accepts.
pub const MAX_FRAME_BYTES: u32 = 1 << 20;

/// Why a frame could not be exchanged.
#[derive(Debug)]
pub enum FrameError {
    /// The peer closed the channel before a frame began.
    Closed,
    /// The channel failed or ended inside a frame.
    Io(io::Error),
    /// The announced length exceeds [`MAX_FRAME_BYTES`].
    TooLarge(u32),
    /// The body is not the expected message.
    Decode(String),
    /// The message could not be encoded.
    Encode(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("the peer closed the channel"),
            Self::Io(error) => write!(formatter, "the channel failed: {error}"),
            Self::TooLarge(length) => write!(
                formatter,
                "a frame of {length} bytes exceeds the {MAX_FRAME_BYTES}-byte limit"
            ),
            Self::Decode(reason) => write!(formatter, "an unexpected message arrived: {reason}"),
            Self::Encode(reason) => write!(formatter, "a message could not be encoded: {reason}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Writes one message as a frame.
pub fn write_frame<T: Serialize>(writer: &mut impl Write, message: &T) -> Result<(), FrameError> {
    let body =
        serde_json::to_vec(message).map_err(|error| FrameError::Encode(error.to_string()))?;
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(length));
    }
    writer
        .write_all(&length.to_be_bytes())
        .map_err(FrameError::Io)?;
    writer.write_all(&body).map_err(FrameError::Io)?;
    writer.flush().map_err(FrameError::Io)
}

/// Reads one frame and decodes it as `T`.
pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, FrameError> {
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Err(FrameError::Closed),
            Ok(0) => return Err(FrameError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FrameError::Io(error)),
        }
    }

    let length = u32::from_be_bytes(header);
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(length));
    }
    let mut body = vec![0_u8; length as usize];
    reader.read_exact(&mut body).map_err(FrameError::Io)?;

    serde_json::from_slice(&body).map_err(|error| FrameError::Decode(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::Cursor;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    enum Request {
        Probe,
        Destroy { tag: String },
    }

    #[test]
    fn a_message_round_trips() {
        let mut channel = Vec::new();
        write_frame(
            &mut channel,
            &Request::Destroy {
                tag: "0123456789".into(),
            },
        )
        .unwrap();
        write_frame(&mut channel, &Request::Probe).unwrap();

        let mut reader = Cursor::new(channel);
        assert_eq!(
            read_frame::<Request>(&mut reader).unwrap(),
            Request::Destroy {
                tag: "0123456789".into()
            }
        );
        assert_eq!(read_frame::<Request>(&mut reader).unwrap(), Request::Probe);
        assert!(matches!(
            read_frame::<Request>(&mut reader),
            Err(FrameError::Closed)
        ));
    }

    #[test]
    fn an_oversized_frame_is_refused_before_it_is_read() {
        let mut channel = (MAX_FRAME_BYTES + 1).to_be_bytes().to_vec();
        channel.extend_from_slice(b"{}");
        let refused = read_frame::<Request>(&mut Cursor::new(channel)).unwrap_err();
        assert!(matches!(refused, FrameError::TooLarge(_)), "{refused}");
    }

    #[test]
    fn a_truncated_frame_is_an_error_not_a_close() {
        let mut channel = Vec::new();
        write_frame(&mut channel, &Request::Probe).unwrap();
        channel.truncate(channel.len() - 1);
        assert!(matches!(
            read_frame::<Request>(&mut Cursor::new(channel)),
            Err(FrameError::Io(_))
        ));

        let header_only = vec![0_u8, 0];
        assert!(matches!(
            read_frame::<Request>(&mut Cursor::new(header_only)),
            Err(FrameError::Io(_))
        ));
    }

    #[test]
    fn an_unexpected_operation_is_refused() {
        let body = br#"{"Mount":{"path":"/"}}"#;
        let mut channel = (body.len() as u32).to_be_bytes().to_vec();
        channel.extend_from_slice(body);
        assert!(matches!(
            read_frame::<Request>(&mut Cursor::new(channel)),
            Err(FrameError::Decode(_))
        ));
    }
}
