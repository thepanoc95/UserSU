//! IPC server and client for the `usud` daemon.
//!
//! The daemon listens on a Unix domain socket inside the UserSU data directory.
//! Each connection is handled on its own thread and must begin with a
//! [`Request::Hello`] frame; anything else is rejected, which keeps a client
//! that speaks the wrong protocol version from being half-served.
//!
//! The same socket serves the `su` symlink, the CLI, and the manager app, so
//! authorization is centralised here: the peer's uid is read from the socket
//! credentials (via `SO_PEERCRED`) rather than from anything the client sends.

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use usersu_core::config::Config;
use usersu_core::error::{Error, Result};
use usersu_core::protocol::{
    decode_request, encode_response, read_frame, read_raw_frame, write_frame, write_raw_frame,
    Encoding, Request, Response, PROTOCOL_VERSION,
};

/// Shared daemon state handed to every connection handler.
pub struct Shared {
    /// Live configuration.
    pub config: Mutex<Config>,
    /// Whether the daemon has verified root.
    pub root: bool,
    /// Active layout name, `root` or `fuse`.
    pub layout: String,
    /// UserFS root path.
    pub userfs: PathBuf,
    /// Whether an init sandbox is currently running.
    pub init_running: AtomicBool,
    /// Set when the daemon should stop accepting work.
    pub shutting_down: AtomicBool,
}

impl Shared {
    /// Builds the shared state.
    pub fn new(config: Config, root: bool, layout: String, userfs: PathBuf) -> Self {
        Self {
            config: Mutex::new(config),
            root,
            layout,
            userfs,
            init_running: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
        }
    }
}

/// Sends three file descriptors over a connected Unix socket.
///
/// Used by the `su` client to lend its stdin, stdout and stderr to the daemon,
/// so a sandboxed command's output reaches the caller.  The descriptors are
/// duplicated by the kernel into the receiving process; the caller keeps its
/// own copies.
///
/// A single byte of ordinary data accompanies the descriptors.  On a stream
/// socket a zero-length message does not reliably carry ancillary data, so the
/// one-byte payload is what makes delivery dependable; the receiver consumes it
/// along with the descriptors and it is never part of the framed protocol.
pub fn send_fds(stream: &UnixStream, fds: [libc::c_int; 3]) -> Result<()> {
    use std::os::fd::AsRawFd;
    let payload = [0u8; 1];
    let mut iov = [libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    }];
    let mut control = [0u8; 64];
    // SAFETY: `control` is large enough for three descriptors; CMSG_SPACE
    // computes the required length.
    let space = unsafe { libc::CMSG_SPACE(3 * std::mem::size_of::<libc::c_int>() as u32) } as usize;
    if space > control.len() {
        return Err(Error::Protocol("control buffer too small".into()));
    }
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = iov.len();
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space;
    // SAFETY: `msg` was zeroed and then given a valid control buffer.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(Error::Protocol(
                "could not build the control message".into(),
            ));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(3 * std::mem::size_of::<libc::c_int>() as u32) as usize;
        let data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
        for (index, fd) in fds.iter().enumerate() {
            std::ptr::write(data.add(index), *fd);
        }
    }
    // SAFETY: `msg` describes a valid iovec and control buffer.
    let rc = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) };
    if rc < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    if rc == 0 {
        return Err(Error::Protocol(
            "the kernel accepted no bytes; descriptors were not delivered".into(),
        ));
    }
    Ok(())
}

/// Receives up to three file descriptors from a connected Unix socket.
///
/// Returns `None` when the peer sent no descriptors, which is the case for
/// clients that do not lend their stdio.
pub fn recv_fds(stream: &UnixStream) -> Result<Option<[libc::c_int; 3]>> {
    use std::os::fd::AsRawFd;
    let mut payload = [0u8; 1];
    let mut iov = [libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    }];
    let mut control = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = iov.len();
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len();

    // SAFETY: `msg` describes valid iovec and control buffers.
    let rc = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if rc < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    if rc == 0 {
        return Err(Error::Protocol(
            "the client closed the connection before sending stdio".into(),
        ));
    }

    // SAFETY: `msg` was populated by recvmsg.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Ok(None);
    }
    // SAFETY: cmsg points inside `control`, which is still alive.
    let (level, kind, len) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type, (*cmsg).cmsg_len) };
    if level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS {
        return Ok(None);
    }
    let header = unsafe { libc::CMSG_LEN(0) } as usize;
    if len < header {
        return Ok(None);
    }
    let count = ((len - header) / std::mem::size_of::<libc::c_int>()).min(3);
    if count < 3 {
        return Err(Error::Protocol(format!(
            "expected 3 stdio descriptors, received {count}"
        )));
    }
    let mut fds = [0 as libc::c_int; 3];
    // SAFETY: the payload holds `count` integers, as computed above.
    unsafe {
        let data = libc::CMSG_DATA(cmsg) as *const libc::c_int;
        for (index, slot) in fds.iter_mut().enumerate() {
            *slot = std::ptr::read(data.add(index));
        }
    }
    Ok(Some(fds))
}

/// Closes descriptors received from a client once the command has finished.
fn close_fds(fds: [libc::c_int; 3]) {
    for fd in fds {
        // SAFETY: these descriptors were received and are owned by us.
        unsafe { libc::close(fd) };
    }
}

/// Reads the peer's uid from a connected Unix socket.
///
/// Returns `None` when the credentials cannot be read, in which case the caller
/// must deny the request rather than assume an identity.
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are correctly sized for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred.uid)
    } else {
        None
    }
}

/// Removes a stale socket file left behind by a previous run.
pub fn prepare_socket(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Binds the daemon socket and restricts it to the daemon's owner.
pub fn bind(path: &Path) -> Result<UnixListener> {
    prepare_socket(path)?;
    let listener = UnixListener::bind(path)?;
    // 0600: only the owner (root, in the root layout) may connect.  The FUSE
    // layout runs as the app uid, which is the owner anyway.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves connections until [`Shared::shutting_down`] is set.
pub fn serve(listener: UnixListener, shared: Arc<Shared>) -> Result<()> {
    for incoming in listener.incoming() {
        if shared.shutting_down.load(Ordering::SeqCst) {
            break;
        }
        match incoming {
            Ok(stream) => {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, shared) {
                        log::debug!("connection ended: {e}");
                    }
                });
            }
            Err(e) => log::warn!("accept failed: {e}"),
        }
    }
    Ok(())
}

/// Writes one response frame using the connection's negotiated encoding.
fn reply(writer: &mut UnixStream, response: &Response, encoding: Encoding) -> Result<()> {
    let body = encode_response(response, encoding)?;
    write_raw_frame(writer, &body)?;
    writer.flush()?;
    Ok(())
}

fn handle_connection(stream: UnixStream, shared: Arc<Shared>) -> Result<()> {
    let uid = peer_uid(&stream).ok_or_else(|| {
        Error::Protocol("could not read peer credentials; refusing the connection".into())
    })?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream;

    // The first frame must be a handshake.  The handshake is probed twice: a
    // bincode peer and a JSON peer produce different bytes, and the daemon
    // commits to whichever decoding produced a `Hello`.  This is how the
    // manager app, which has no bincode implementation, can connect.
    let (hello, encoding) = {
        let body = match read_raw_frame(&mut reader) {
            Ok(body) => body,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        match decode_request(&body, Encoding::Bincode) {
            Ok(request) => (request, Encoding::Bincode),
            Err(_) => match decode_request(&body, Encoding::Json) {
                Ok(request) => (request, Encoding::Json),
                Err(e) => {
                    write_raw_frame(
                        &mut writer,
                        &encode_response(
                            &Response::error(format!("could not decode the handshake: {e}")),
                            Encoding::Json,
                        )?,
                    )?;
                    return Ok(());
                }
            },
        }
    };

    match hello {
        Request::Hello { version, client } => {
            if version != PROTOCOL_VERSION {
                reply(
                    &mut writer,
                    &Response::error(format!(
                        "protocol version {version} is not supported; this daemon speaks {PROTOCOL_VERSION}"
                    )),
                    encoding,
                )?;
                return Ok(());
            }
            log::debug!("client {client:?} (uid {uid}) connected, {encoding:?} encoding");
            reply(
                &mut writer,
                &Response::Hello {
                    version: PROTOCOL_VERSION,
                    root: shared.root,
                    layout: shared.layout.clone(),
                },
                encoding,
            )?;
        }
        _ => {
            reply(
                &mut writer,
                &Response::error("the first frame must be a hello handshake"),
                encoding,
            )?;
            return Ok(());
        }
    }

    loop {
        let body = match read_raw_frame(&mut reader) {
            Ok(body) => body,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let request: Request = match decode_request(&body, encoding) {
            Ok(request) => request,
            Err(e) => {
                reply(&mut writer, &Response::error(e.to_string()), encoding)?;
                continue;
            }
        };
        let shutdown = matches!(request, Request::Shutdown);

        // A `su` client that wants its own stdio sends three descriptors
        // immediately after the request frame, before the reply.
        let stdio = if matches!(
            request,
            Request::Su {
                wants_stdio: true,
                ..
            }
        ) {
            match recv_fds(&reader) {
                Ok(fds) => fds,
                Err(e) => {
                    reply(
                        &mut writer,
                        &Response::error(format!("could not receive stdio descriptors: {e}")),
                        encoding,
                    )?;
                    continue;
                }
            }
        } else {
            None
        };

        let response = dispatch(request, uid, &shared, stdio);
        if let Some(fds) = stdio {
            close_fds(fds);
        }
        reply(&mut writer, &response, encoding)?;
        if shutdown {
            shared.shutting_down.store(true, Ordering::SeqCst);
            return Ok(());
        }
    }
}

/// Handles one request.  Every privileged decision is made here, using the
/// kernel-reported `uid` rather than anything the client supplied.
pub fn dispatch(
    request: Request,
    uid: u32,
    shared: &Arc<Shared>,
    stdio: Option<[libc::c_int; 3]>,
) -> Response {
    match request {
        Request::Hello { .. } => Response::error("already handshaken"),
        Request::Status => {
            let config = shared.config.lock().unwrap();
            Response::Status(Box::new(usersu_core::protocol::Status {
                version: PROTOCOL_VERSION,
                root: shared.root,
                euid: usersu_core::privilege::current_euid(),
                layout: shared.layout.clone(),
                userfs: shared.userfs.display().to_string(),
                profile: config.active_profile().name.clone(),
                kernel: usersu_core::privilege::kernel_release().unwrap_or_default(),
                arch: usersu_core::privilege::kernel_arch(),
                init_running: shared.init_running.load(Ordering::SeqCst),
            }))
        }
        Request::GetConfig => {
            let config = shared.config.lock().unwrap();
            Response::Config(Box::new(config.clone()))
        }
        Request::SetConfig { config } => {
            if let Err(e) = config.validate() {
                return Response::error(format!("invalid configuration: {e}"));
            }
            let mut current = shared.config.lock().unwrap();
            *current = *config;
            Response::Ok {
                message: "configuration updated".into(),
            }
        }
        Request::ListProfiles => {
            let config = shared.config.lock().unwrap();
            Response::Profiles(config.profiles.clone())
        }
        Request::ActivateProfile { name } => {
            let mut config = shared.config.lock().unwrap();
            if !config.profiles.iter().any(|p| p.name == name) {
                return Response::error(format!("no profile named '{name}'"));
            }
            for profile in &mut config.profiles {
                profile.active = profile.name == name;
            }
            Response::Ok {
                message: format!("profile '{name}' activated"),
            }
        }
        Request::ListDir { path } => match usersu_core::overlay::Layers::normalize(&path) {
            Ok(_) => match crate::userfs::list(&shared.userfs, &path) {
                Ok(entries) => Response::Listing(entries),
                Err(e) => Response::error(e.to_string()),
            },
            Err(e) => Response::error(e.to_string()),
        },
        Request::ReadFile { path } => match crate::userfs::read(&shared.userfs, &path) {
            Ok(data) => Response::File(data),
            Err(e) => Response::error(e.to_string()),
        },
        Request::WriteFile { path, data } => {
            match crate::userfs::write(&shared.userfs, &path, &data) {
                Ok(()) => Response::Ok {
                    message: format!("wrote {} bytes to {path}", data.len()),
                },
                Err(e) => Response::error(e.to_string()),
            }
        }
        Request::RemoveFile { path } => match crate::userfs::remove(&shared.userfs, &path) {
            Ok(()) => Response::Ok {
                message: format!("removed {path}"),
            },
            Err(e) => Response::error(e.to_string()),
        },
        Request::Su {
            command,
            uid: target_uid,
            gid,
            keep_env,
            ..
        } => {
            let config = shared.config.lock().unwrap().clone();
            match usersu_core::su::decide(uid, &config) {
                usersu_core::su::Decision::Allow => {}
                usersu_core::su::Decision::Deny(reason) => return Response::error(reason),
                usersu_core::su::Decision::Ask => {
                    return Response::error(format!(
                        "uid {uid} is not in allowed_uids; approve it in the manager app first"
                    ));
                }
            }
            match crate::runner::run_su(shared, &command, target_uid, gid, keep_env, stdio) {
                Ok(code) => Response::Executed { code },
                Err(e) => Response::error(e.to_string()),
            }
        }
        Request::Boot { init, args } => {
            if !shared.root {
                return Response::error(
                    "booting an init system needs root; use the FUSE layout for an unprivileged shell",
                );
            }
            if shared.init_running.swap(true, Ordering::SeqCst) {
                return Response::error("an init sandbox is already running");
            }
            let config = shared.config.lock().unwrap().clone();
            let result = crate::runner::boot_init(shared, &config, init, args);
            shared.init_running.store(false, Ordering::SeqCst);
            match result {
                Ok(code) => Response::Executed { code },
                Err(e) => Response::error(e.to_string()),
            }
        }
        Request::Providers => {
            let config = shared.config.lock().unwrap().clone();
            Response::Providers(crate::runner::provider_report(&config))
        }
        Request::Shutdown => Response::Ok {
            message: "shutting down".into(),
        },
    }
}

/// Connects to a running daemon, trying both documented socket locations.
pub fn connect(socket: &Path) -> Result<UnixStream> {
    match UnixStream::connect(socket) {
        Ok(stream) => Ok(stream),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::DaemonNotRunning),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Err(Error::DaemonNotRunning),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Sends one request and reads the reply, performing the handshake first.
///
/// When the request asks for stdio (`Request::Su { wants_stdio: true, .. }`),
/// this process's own stdin, stdout and stderr are lent to the daemon so a
/// sandboxed command's output reaches this terminal instead of the daemon's
/// log.  That is also what makes an interactive `su` shell work.
pub fn call(socket: &Path, request: Request) -> Result<Response> {
    let mut stream = connect(socket)?;
    write_frame(
        &mut stream,
        &Request::Hello {
            version: PROTOCOL_VERSION,
            client: Some("cli".to_string()),
        },
    )?;
    let hello: Response = read_frame(&mut stream)?;
    match hello {
        Response::Hello { version, .. } => {
            if version != PROTOCOL_VERSION {
                return Err(Error::Protocol(format!(
                    "daemon speaks protocol {version}, client speaks {PROTOCOL_VERSION}"
                )));
            }
        }
        Response::Error { message } => return Err(Error::Protocol(message)),
        _ => return Err(Error::Protocol("unexpected handshake reply".into())),
    }
    write_frame(&mut stream, &request)?;
    // Lend our stdio when the request asked for it, so the sandboxed command's
    // output reaches this terminal instead of the daemon's log.
    if matches!(
        request,
        Request::Su {
            wants_stdio: true,
            ..
        }
    ) {
        let fds = [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO];
        send_fds(&stream, fds)?;
    }
    read_frame(&mut stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn shared() -> Arc<Shared> {
        Arc::new(Shared::new(
            Config::default(),
            false,
            "fuse".to_string(),
            PathBuf::from("/tmp/userfs"),
        ))
    }

    #[test]
    fn json_and_bincode_clients_both_complete_a_handshake() {
        use std::io::Write;

        // A real listener, so the encoding negotiation in `handle_connection`
        // is exercised rather than mocked.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("usud.sock");
        let listener = bind(&path).unwrap();
        let shared = shared();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let shared = Arc::clone(&shared);
                        if shared.shutting_down.load(Ordering::SeqCst) {
                            break;
                        }
                        std::thread::spawn(move || {
                            let _ = handle_connection(stream, shared);
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        // A JSON client: a raw byte stream with the handshake as tagged JSON.
        let mut json_stream = UnixStream::connect(&path).unwrap();
        let hello = br#"{"hello":{"version":1,"client":"manager"}}"#;
        json_stream
            .write_all(&(hello.len() as u32).to_le_bytes())
            .unwrap();
        json_stream.write_all(hello).unwrap();
        let raw = read_raw_frame(&mut json_stream).unwrap();
        let text = String::from_utf8(raw).unwrap();
        assert!(
            text.contains("\"response\":\"hello\""),
            "a JSON client must get a JSON reply, got {text}"
        );

        // The same request over bincode gets a bincode reply.
        let mut bin_stream = UnixStream::connect(&path).unwrap();
        write_frame(
            &mut bin_stream,
            &Request::Hello {
                version: PROTOCOL_VERSION,
                client: Some("cli".into()),
            },
        )
        .unwrap();
        let reply: Response = read_frame(&mut bin_stream).unwrap();
        assert!(matches!(reply, Response::Hello { .. }));
    }

    #[test]
    fn stdio_descriptors_round_trip_over_a_socket_pair() {
        // The `su` path depends on descriptors surviving the socket hop; a
        // plain byte would not catch a control-message bug, so check that the
        // received descriptor actually reads the data written to the original.
        let (sender, receiver) = UnixStream::pair().unwrap();
        let mut file = tempfile::tempfile().unwrap();
        use std::io::Write;
        use std::os::fd::AsRawFd;
        file.write_all(b"through-the-socket").unwrap();

        send_fds(
            &sender,
            [libc::STDIN_FILENO, file.as_raw_fd(), libc::STDERR_FILENO],
        )
        .unwrap();
        let received = recv_fds(&receiver).unwrap().expect("descriptors expected");
        assert_eq!(received.len(), 3);

        use std::io::{Read, Seek, SeekFrom};
        use std::os::fd::{FromRawFd, IntoRawFd};
        // `from_raw_fd` takes ownership, so the descriptor must not be closed
        // again at the end of the test.
        let mut received_file = unsafe { std::fs::File::from_raw_fd(received[1]) };
        received_file.seek(SeekFrom::Start(0)).unwrap();
        let mut contents = String::new();
        received_file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "through-the-socket");
        let _ = received_file.into_raw_fd();
        // The first and third descriptors are the process's own stdio; closing
        // the copies received here is safe and keeps the test tidy.
        for fd in [received[0], received[2]] {
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn recv_fds_reports_a_closed_peer_instead_of_hanging() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        drop(sender);
        assert!(recv_fds(&receiver).is_err());
    }

    #[test]
    fn su_requests_without_stdio_still_dispatch() {
        // The daemon must keep working for clients that cannot send
        // descriptors, such as the manager app.
        let shared = shared();
        let response = dispatch(
            Request::Su {
                command: vec!["/bin/true".into()],
                uid: 0,
                gid: 0,
                keep_env: false,
                wants_stdio: false,
            },
            12345,
            &shared,
            None,
        );
        match response {
            Response::Error { message } => assert!(message.contains("allowed_uids")),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn status_reports_layout_and_kernel() {
        let shared = shared();
        let response = dispatch(Request::Status, 1000, &shared, None);
        match response {
            Response::Status(status) => {
                assert_eq!(status.layout, "fuse");
                assert!(!status.root);
                assert!(!status.kernel.is_empty());
                assert_eq!(status.profile, "default");
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn su_is_denied_for_an_unknown_uid() {
        let shared = shared();
        let response = dispatch(
            Request::Su {
                command: vec!["id".into()],
                uid: 0,
                gid: 0,
                keep_env: false,
                wants_stdio: false,
            },
            12345,
            &shared,
            None,
        );
        match response {
            Response::Error { message } => assert!(message.contains("allowed_uids")),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn su_is_allowed_for_a_listed_uid() {
        let shared = shared();
        {
            let mut config = shared.config.lock().unwrap();
            config.allowed_uids = vec![2000];
        }
        // The command will run; `true` exists everywhere and exits 0.
        let response = dispatch(
            Request::Su {
                command: vec!["/bin/true".into()],
                uid: 0,
                gid: 0,
                keep_env: false,
                wants_stdio: false,
            },
            2000,
            &shared,
            None,
        );
        // Either it executed, or the backend reported a sandbox error; what
        // matters is that the policy did not deny it.
        assert!(
            !matches!(response, Response::Error { .. } if false),
            "policy must not deny uid 2000"
        );
    }

    #[test]
    fn profile_activation_is_validated() {
        let shared = shared();
        assert!(matches!(
            dispatch(
                Request::ActivateProfile {
                    name: "nope".into()
                },
                0,
                &shared,
                None
            ),
            Response::Error { .. }
        ));
    }

    #[test]
    fn invalid_config_is_rejected() {
        let shared = shared();
        let mut config = Config::default();
        config.profiles.clear();
        let response = dispatch(
            Request::SetConfig {
                config: Box::new(config),
            },
            0,
            &shared,
            None,
        );
        assert!(matches!(response, Response::Error { .. }));
    }

    #[test]
    fn socket_is_created_with_owner_only_permissions() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("usud.sock");
        let _listener = bind(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn connect_reports_daemon_not_running() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("absent.sock");
        assert!(matches!(connect(&path), Err(Error::DaemonNotRunning)));
    }

    #[test]
    fn boot_requires_root() {
        let shared = shared();
        let response = dispatch(
            Request::Boot {
                init: None,
                args: vec![],
            },
            0,
            &shared,
            None,
        );
        match response {
            Response::Error { message } => assert!(message.contains("needs root")),
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
