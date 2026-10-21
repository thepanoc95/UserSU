//! Wire protocol between the `usud` daemon and its clients (the `su` symlink,
//! the manager app, and the `usud` CLI itself).
//!
//! Framing is a 4-byte little-endian length followed by a bincode-encoded
//! [`Request`] or [`Response`].  The same framing is used over both the Unix
//! socket and any stdio bridge, so the manager app can speak it without a
//! bincode implementation by falling back to the JSON encoding in
//! [`Response::to_json`].

use crate::config::{Config, Profile};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Bumped whenever the protocol changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default maximum frame size, guarding against a hostile length prefix.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

/// A client request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Request {
    /// Protocol handshake; must be the first frame on a connection.
    Hello {
        /// Client protocol version.
        version: u32,
        /// Optional client name for logging, e.g. `manager`.
        client: Option<String>,
    },
    /// Report daemon status.
    Status,
    /// Read the running configuration.
    GetConfig,
    /// Replace the running configuration and persist it.
    SetConfig {
        /// The new configuration.
        config: Box<Config>,
    },
    /// List profiles.
    ListProfiles,
    /// Activate a profile by name.
    ActivateProfile {
        /// Profile to activate.
        name: String,
    },
    /// List the merged contents of a directory inside UserFS.
    ListDir {
        /// Path relative to the UserFS root.
        path: String,
    },
    /// Read a file inside UserFS.
    ReadFile {
        /// Path relative to the UserFS root.
        path: String,
    },
    /// Write a file inside UserFS, copying up from a lower layer if needed.
    WriteFile {
        /// Path relative to the UserFS root.
        path: String,
        /// New contents.
        data: Vec<u8>,
    },
    /// Remove a path inside UserFS, whiteout-ing a lower-only entry.
    RemoveFile {
        /// Path relative to the UserFS root.
        path: String,
    },
    /// Ask for a privilege grant for a command.
    Su {
        /// The command to run; empty means an interactive shell.
        command: Vec<String>,
        /// Requested target uid.
        uid: u32,
        /// Requested target gid.
        gid: u32,
        /// Whether to keep the caller's environment.
        keep_env: bool,
        /// Whether the client sent its stdin/stdout/stderr as ancillary file
        /// descriptors.  When set, the daemon runs the command with those
        /// descriptors, so output reaches the client instead of the daemon's
        /// log.  Clients that cannot send descriptors leave this false and the
        /// command inherits the daemon's own stdio.
        #[serde(default)]
        wants_stdio: bool,
    },
    /// Run an init system in a sandbox.
    Boot {
        /// Optional init command override.
        init: Option<String>,
        /// Arguments for the init command.
        args: Vec<String>,
    },
    /// Ask which privilege providers are usable.
    Providers,
    /// Stop the daemon.
    Shutdown,
}

/// A daemon response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Response {
    /// Handshake accepted.
    Hello {
        /// Daemon protocol version.
        version: u32,
        /// Whether the daemon has verified root.
        root: bool,
        /// Which filesystem layout is active.
        layout: String,
    },
    /// Generic success with an optional human readable message.
    Ok {
        /// Message.
        message: String,
    },
    /// Status payload.
    Status(Box<Status>),
    /// Configuration payload.
    Config(Box<Config>),
    /// Profile list.
    Profiles(Vec<Profile>),
    /// Directory listing.
    Listing(Vec<String>),
    /// File contents.
    File(Vec<u8>),
    /// Privilege provider report.
    Providers(Vec<ProviderReport>),
    /// A command was granted and executed; carries its exit status.
    Executed {
        /// Exit code, or `None` when killed by a signal.
        code: Option<i32>,
    },
    /// The request failed.
    Error {
        /// Human readable reason.
        message: String,
    },
}

/// One entry in a [`Response::Providers`] report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderReport {
    /// Provider name.
    pub name: String,
    /// `root-solution` or `kernel-exploit`.
    pub kind: String,
    /// Whether the provider is usable on this device.
    pub available: bool,
    /// Why, when it is not usable.
    pub reason: Option<String>,
}

/// A snapshot of daemon state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    /// Protocol version.
    pub version: u32,
    /// Whether root is verified.
    pub root: bool,
    /// Effective uid of the daemon.
    pub euid: u32,
    /// Active layout, `root` or `fuse`.
    pub layout: String,
    /// UserFS root path.
    pub userfs: String,
    /// Active profile name.
    pub profile: String,
    /// Kernel release.
    pub kernel: String,
    /// Machine architecture.
    pub arch: String,
    /// Whether an init sandbox is currently running.
    pub init_running: bool,
}

impl Response {
    /// Serializes this response as JSON, for clients that cannot speak bincode.
    ///
    /// The manager app uses this encoding.  Each variant is tagged by name so a
    /// Kotlin client can pattern-match without a bincode implementation.
    pub fn to_json(&self) -> String {
        let tagged = match self {
            Response::Hello {
                version,
                root,
                layout,
            } => serde_json::json!({
                "response": "hello",
                "version": version,
                "root": root,
                "layout": layout,
            }),
            Response::Ok { message } => serde_json::json!({
                "response": "ok",
                "message": message,
            }),
            Response::Status(status) => serde_json::json!({
                "response": "status",
                "status": status,
            }),
            Response::Config(config) => serde_json::json!({
                "response": "config",
                "config": config,
            }),
            Response::Profiles(profiles) => serde_json::json!({
                "response": "profiles",
                "profiles": profiles,
            }),
            Response::Listing(entries) => serde_json::json!({
                "response": "listing",
                "entries": entries,
            }),
            Response::File(data) => serde_json::json!({
                "response": "file",
                "data": data,
            }),
            Response::Providers(reports) => serde_json::json!({
                "response": "providers",
                "providers": reports,
            }),
            Response::Executed { code } => serde_json::json!({
                "response": "executed",
                "code": code,
            }),
            Response::Error { message } => serde_json::json!({
                "response": "error",
                "message": message,
            }),
        };
        tagged.to_string()
    }

    /// Convenience constructor for [`Response::Error`].
    pub fn error(message: impl Into<String>) -> Self {
        Response::Error {
            message: message.into(),
        }
    }
}

/// Writes a length-prefixed frame to `w`.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> crate::error::Result<()> {
    let body =
        bincode::serialize(value).map_err(|e| crate::error::Error::Serialization(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(crate::error::Error::Protocol(format!(
            "frame of {} bytes exceeds the {} byte limit",
            body.len(),
            MAX_FRAME
        )));
    }
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Reads a length-prefixed frame from `r`.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> crate::error::Result<T> {
    let body = read_raw_frame(r)?;
    bincode::deserialize(&body).map_err(|e| crate::error::Error::Serialization(e.to_string()))
}

/// Reads a length-prefixed frame and returns its raw bytes.
///
/// Used by the daemon, which decodes a frame as bincode or JSON depending on
/// the client: the manager app speaks JSON because it has no bincode
/// implementation.
pub fn read_raw_frame<R: Read>(r: &mut R) -> crate::error::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(crate::error::Error::Protocol(format!(
            "declared frame of {len} bytes exceeds the {MAX_FRAME} byte limit"
        )));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Writes already-encoded bytes as a length-prefixed frame.
pub fn write_raw_frame<W: Write>(w: &mut W, body: &[u8]) -> crate::error::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(crate::error::Error::Protocol(format!(
            "frame of {} bytes exceeds the {} byte limit",
            body.len(),
            MAX_FRAME
        )));
    }
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// Which encoding a connection uses.
///
/// The framing is identical either way; only the payload differs.  The daemon
/// pins the encoding for the life of a connection, decided by the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// bincode; used by the `usud` CLI and the `su` symlink.
    Bincode,
    /// JSON; used by the manager app.
    Json,
}

/// Decodes a request frame using `encoding`.
pub fn decode_request(body: &[u8], encoding: Encoding) -> crate::error::Result<Request> {
    match encoding {
        Encoding::Bincode => bincode::deserialize(body)
            .map_err(|e| crate::error::Error::Serialization(e.to_string())),
        Encoding::Json => serde_json::from_slice(body)
            .map_err(|e| crate::error::Error::Serialization(e.to_string())),
    }
}

/// Encodes a response frame using `encoding`.
pub fn encode_response(response: &Response, encoding: Encoding) -> crate::error::Result<Vec<u8>> {
    match encoding {
        Encoding::Bincode => bincode::serialize(response)
            .map_err(|e| crate::error::Error::Serialization(e.to_string())),
        // The JSON form is the same tagged document `to_json` produces, so the
        // manager app parses responses with one code path.
        Encoding::Json => Ok(response.to_json().into_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_roundtrips() {
        let req = Request::Su {
            command: vec!["id".into()],
            uid: 0,
            gid: 0,
            keep_env: false,
            wants_stdio: true,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded: Request = read_frame(&mut cursor).unwrap();
        match decoded {
            Request::Su {
                command,
                uid,
                wants_stdio,
                ..
            } => {
                assert_eq!(command, vec!["id".to_string()]);
                assert_eq!(uid, 0);
                assert!(wants_stdio, "the stdio flag must survive a round trip");
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn response_roundtrips() {
        let resp = Response::Status(Box::new(Status {
            version: PROTOCOL_VERSION,
            root: false,
            euid: 1000,
            layout: "fuse".into(),
            userfs: "/data/data/me.usersu/files/mnt/userfs".into(),
            profile: "default".into(),
            kernel: "6.1.0".into(),
            arch: "aarch64".into(),
            init_running: false,
        }));
        let mut buf = Vec::new();
        write_frame(&mut buf, &resp).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded: Response = read_frame(&mut cursor).unwrap();
        match decoded {
            Response::Status(s) => assert_eq!(s.euid, 1000),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn oversized_frame_is_rejected_on_write() {
        let big = Response::File(vec![0u8; MAX_FRAME + 1]);
        let mut buf = Vec::new();
        assert!(matches!(
            write_frame(&mut buf, &big),
            Err(crate::error::Error::Protocol(_))
        ));
    }

    #[test]
    fn oversized_length_prefix_is_rejected_on_read() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(u32::MAX).to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        let mut cursor = Cursor::new(buf);
        let res: crate::error::Result<Response> = read_frame(&mut cursor);
        assert!(matches!(res, Err(crate::error::Error::Protocol(_))));
    }

    #[test]
    fn json_encoding_is_available_for_the_manager() {
        let resp = Response::error("nope");
        let json = resp.to_json();
        assert!(json.contains("error"));
        assert!(json.contains("nope"));
    }
}
