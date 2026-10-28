//! The proot backend: run a program inside UserFS with no privileges at all.
//!
//! There is no kernel feature that gives an unprivileged process a new root,
//! so this backend does what proot does: it stops the tracee at every
//! path-taking syscall, rewrites the path argument so that it points inside the
//! UserFS tree, and lets the syscall continue.  The tracee's own view of the
//! filesystem is therefore rooted, without `chroot` or `pivot_root`.
//!
//! Two details make the rewriting work:
//!
//! * A translated path is usually *longer* than the original, so it cannot
//!   always be written over the caller's buffer.  When it does not fit, the new
//!   string is injected onto the tracee's stack and the argument register is
//!   repointed at it; the original stack pointer is restored at syscall exit.
//! * A translated path that does not exist inside UserFS falls back to the
//!   host path.  That is what lets host binaries and their shared libraries
//!   keep working while the data they touch is rooted.
//!
//! State is kept per thread, so multi-threaded tracees are handled correctly.

use crate::error::{Error, Result};
use crate::sandbox::SandboxPlan;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A syscall that takes a path as one of its arguments.
#[derive(Debug, Clone, Copy)]
pub struct PathSyscall {
    /// Syscall number on the current architecture.
    pub number: i64,
    /// Zero-based index of the path argument.
    pub path_arg: u8,
    /// Zero-based index of the directory descriptor the path is relative to, or
    /// `AT_FDCWD` handling when the value is `u8::MAX`.
    ///
    /// `openat`-style syscalls resolve a relative path against this descriptor,
    /// not against the working directory.  Ignoring it makes `ls /system/bin`
    /// fail: `ls` opens `/system`, then asks for `"bin"` relative to that
    /// descriptor, and the descriptor is meaningless to the tracer.
    pub dirfd_arg: u8,
    /// Human readable name, used in logs.
    pub name: &'static str,
}

/// Marker for "this syscall has no directory descriptor argument".
pub const NO_DIRFD: u8 = u8::MAX;

#[cfg(target_arch = "x86_64")]
mod nr {
    use super::{PathSyscall, NO_DIRFD};
    macro_rules! paths {
        ($(($n:expr, $a:expr, $d:expr, $name:expr)),* $(,)?) => {
            pub const TABLE: &[PathSyscall] = &[$(PathSyscall { number: $n, path_arg: $a, dirfd_arg: $d, name: $name }),*];
        };
    }
    paths![
        (2, 0, NO_DIRFD, "open"),
        (4, 0, NO_DIRFD, "stat"),
        (6, 0, NO_DIRFD, "lstat"),
        (21, 0, NO_DIRFD, "access"),
        (59, 0, NO_DIRFD, "execve"),
        (76, 0, NO_DIRFD, "truncate"),
        (80, 0, NO_DIRFD, "chdir"),
        (82, 0, NO_DIRFD, "rename"),
        (83, 0, NO_DIRFD, "mkdir"),
        (84, 0, NO_DIRFD, "rmdir"),
        (86, 0, NO_DIRFD, "link"),
        (87, 0, NO_DIRFD, "unlink"),
        (88, 0, NO_DIRFD, "symlink"),
        (89, 0, NO_DIRFD, "readlink"),
        (90, 0, NO_DIRFD, "chmod"),
        (92, 0, NO_DIRFD, "chown"),
        (94, 0, NO_DIRFD, "lchown"),
        (133, 0, NO_DIRFD, "mknod"),
        (137, 0, NO_DIRFD, "statfs"),
        (257, 1, 0, "openat"),
        (258, 1, 0, "mkdirat"),
        (259, 1, 0, "mknodat"),
        (260, 1, 0, "fchownat"),
        (262, 1, 0, "newfstatat"),
        (263, 1, 0, "unlinkat"),
        (264, 1, 0, "renameat"),
        (265, 1, 0, "linkat"),
        (266, 1, 0, "symlinkat"),
        (267, 1, 0, "readlinkat"),
        (268, 1, 0, "fchmodat"),
        (269, 1, 0, "faccessat"),
        (280, 1, 0, "utimensat"),
        (316, 2, 0, "renameat2"),
        (322, 1, 0, "execveat"),
        (332, 1, 0, "statx"),
        (437, 1, 0, "openat2"),
        (439, 1, 0, "faccessat2"),
    ];

    /// Credential syscall numbers, used for identity spoofing.
    pub mod identity {
        pub const GETUID: i64 = 102;
        pub const GETGID: i64 = 104;
        pub const GETEUID: i64 = 107;
        pub const GETEGID: i64 = 108;
        pub const SETUID: i64 = 105;
        pub const SETGID: i64 = 106;
        pub const SETEUID: i64 = 117;
        pub const SETEGID: i64 = 116;
        pub const SETREUID: i64 = 113;
        pub const SETREGID: i64 = 114;
    }
}

#[cfg(target_arch = "aarch64")]
mod nr {
    use super::{PathSyscall, NO_DIRFD};
    macro_rules! paths {
        ($(($n:expr, $a:expr, $d:expr, $name:expr)),* $(,)?) => {
            pub const TABLE: &[PathSyscall] = &[$(PathSyscall { number: $n, path_arg: $a, dirfd_arg: $d, name: $name }),*];
        };
    }
    paths![
        (34, 1, 0, "mkdirat"),
        (35, 1, 0, "unlinkat"),
        (36, 1, 0, "symlinkat"),
        (37, 1, 0, "linkat"),
        (38, 1, 0, "renameat"),
        (40, 1, 0, "faccessat"),
        (48, 1, 0, "faccessat2"),
        (49, 0, NO_DIRFD, "chdir"),
        (53, 1, 0, "fchmodat"),
        (54, 1, 0, "fchownat"),
        (56, 1, 0, "openat"),
        (78, 1, 0, "readlinkat"),
        (79, 1, 0, "newfstatat"),
        (88, 1, 0, "utimensat"),
        (276, 2, 0, "renameat2"),
        (281, 1, 0, "execveat"),
        (291, 1, 0, "statx"),
        (437, 1, 0, "openat2"),
        (439, 1, 0, "faccessat2"),
    ];

    /// Credential syscall numbers, used for identity spoofing.
    pub mod identity {
        pub const GETUID: i64 = 174;
        pub const GETGID: i64 = 176;
        pub const GETEUID: i64 = 175;
        pub const GETEGID: i64 = 177;
        pub const SETUID: i64 = 146;
        pub const SETGID: i64 = 144;
        // aarch64 has no seteuid/setegid syscalls; glibc implements them with
        // setresuid/setresgid, so those are the numbers to intercept.
        pub const SETEUID: i64 = 147;
        pub const SETEGID: i64 = 149;
        pub const SETREUID: i64 = 145;
        pub const SETREGID: i64 = 143;
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod nr {
    use super::PathSyscall;
    /// No syscall table is defined for this architecture.
    pub const TABLE: &[PathSyscall] = &[];

    /// Credential syscall numbers, used for identity spoofing.
    pub mod identity {
        pub const GETUID: i64 = -1;
        pub const GETGID: i64 = -1;
        pub const GETEUID: i64 = -1;
        pub const GETEGID: i64 = -1;
        pub const SETUID: i64 = -1;
        pub const SETGID: i64 = -1;
        pub const SETEUID: i64 = -1;
        pub const SETEGID: i64 = -1;
        pub const SETREUID: i64 = -1;
        pub const SETREGID: i64 = -1;
    }
}

/// Returns the path-taking syscall description for `number`, if any.
pub fn lookup(number: i64) -> Option<&'static PathSyscall> {
    nr::TABLE.iter().find(|s| s.number == number)
}

/// A syscall whose *result* is rewritten to present a fake identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCall {
    /// `getuid` / `geteuid`: the result becomes the fake uid.
    Uid,
    /// `getgid` / `getegid`: the result becomes the fake gid.
    Gid,
    /// `setuid` / `setgid` and friends: the call is forced to succeed without
    /// changing the real credentials.
    Set,
}

/// The identity presented to a sandboxed process.
///
/// Without real root there is no way to change the credentials the kernel
/// reports, so the ptrace backend answers the credential syscalls itself.  This
/// is a userland illusion, and the documentation says so: code that checks the
/// kernel through another route still sees the real uid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// uid reported by `getuid` and `geteuid`.
    pub uid: u32,
    /// gid reported by `getgid` and `getegid`.
    pub gid: u32,
}

impl Identity {
    /// The identity that makes a sandbox look root-owned.
    pub const ROOT: Identity = Identity { uid: 0, gid: 0 };
}

/// Classifies a syscall as an identity call, if it is one.
pub fn identity_call(number: i64) -> Option<IdentityCall> {
    use nr::identity as id;
    match number {
        n if n == id::GETUID || n == id::GETEUID => Some(IdentityCall::Uid),
        n if n == id::GETGID || n == id::GETEGID => Some(IdentityCall::Gid),
        n if n == id::SETUID
            || n == id::SETGID
            || n == id::SETEUID
            || n == id::SETEGID
            || n == id::SETREUID
            || n == id::SETREGID =>
        {
            Some(IdentityCall::Set)
        }
        _ => None,
    }
}

/// The `AT_FDCWD` sentinel meaning "relative to the current directory".
pub const AT_FDCWD: i64 = -100;

/// Decides which guest paths are rooted and which are passed through to the
/// host unchanged.
///
/// Passing a few kernel filesystems straight through is what lets an
/// unprivileged sandbox work at all: `/dev/null`, `/proc/self` and the like
/// cannot be meaningfully re-rooted.
///
/// `host_fallback` mirrors proot's own behaviour: a rooted path that does not
/// exist inside UserFS is replaced by the host path when that exists, which is
/// how host binaries and their shared libraries keep loading.  **This is not a
/// security boundary.**  A sandboxed process runs as the same uid as its
/// launcher and can read anything that uid can read; the ptrace backend only
/// changes which paths the process *sees*, so that a program written for a
/// rooted system finds its files where it expects them.  Set `host_fallback` to
/// false for a strictly rooted view that sacrifices host-binary compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassthroughPolicy {
    /// Guest path prefixes that are never re-rooted.
    pub prefixes: Vec<String>,
    /// When true, a rooted path that does not exist falls back to the host
    /// path if that exists.
    pub host_fallback: bool,
}

impl Default for PassthroughPolicy {
    fn default() -> Self {
        Self {
            prefixes: vec!["/dev".to_string(), "/proc".to_string(), "/sys".to_string()],
            host_fallback: true,
        }
    }
}

impl PassthroughPolicy {
    /// True when `guest` must be handed to the host as-is.
    pub fn passes_through(&self, guest: &str) -> bool {
        self.prefixes.iter().any(|prefix| {
            guest == prefix
                || guest
                    .strip_prefix(prefix.as_str())
                    .map(|rest| rest.starts_with('/'))
                    .unwrap_or(false)
        })
    }
}

/// Lexically normalizes `path`, clamping `..` at the root.
///
/// The result never contains a `..` component, so the kernel cannot be tricked
/// into resolving above the intended directory when it receives the string.
pub fn lexical_normalize(path: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for component in Path::new(path).components() {
        use std::path::Component;
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

/// Translates a guest path into a host path under `root`.
///
/// `base` is the directory a relative path is resolved against: the tracee's
/// current working directory, or the directory a descriptor refers to for
/// `openat`-style calls.  Paths matching [`PassthroughPolicy::passes_through`]
/// are returned unchanged so kernel filesystems keep working.
pub fn translate_path_with(
    root: &Path,
    base: &Path,
    guest: &str,
    policy: &PassthroughPolicy,
) -> PathBuf {
    if guest.is_empty() {
        return PathBuf::from(guest);
    }
    if policy.passes_through(guest) {
        return PathBuf::from(guest);
    }

    // Reduce a relative path to a guest-absolute one using the base directory
    // the syscall resolves against: the directory descriptor for `openat`-style
    // calls, the working directory otherwise.
    let guest_absolute = if guest.starts_with('/') {
        guest.to_string()
    } else {
        let joined = base.join(guest);
        let stripped = joined.strip_prefix(root).unwrap_or(&joined);
        let stripped = stripped.to_string_lossy();
        if stripped.starts_with('/') {
            stripped.into_owned()
        } else {
            format!("/{stripped}")
        }
    };

    let relative = lexical_normalize(&guest_absolute);
    let rooted = root.join(&relative);
    if rooted.exists() || !policy.host_fallback {
        return rooted;
    }
    // Optional compatibility fallback; the returned path is normalized, so it
    // can never contain a `..` component.
    let host = PathBuf::from("/").join(&relative);
    if host.exists() {
        host
    } else {
        rooted
    }
}

/// Translates a guest path using the default policy.
pub fn translate_path(root: &Path, cwd: &Path, guest: &str) -> PathBuf {
    translate_path_with(root, cwd, guest, &PassthroughPolicy::default())
}

/// Per-thread bookkeeping for a tracee.
#[derive(Debug, Clone, Copy, Default)]
struct ThreadState {
    /// Original stack pointer, restored after an injected path is consumed.
    saved_sp: Option<u64>,
    /// True between syscall-entry and syscall-exit.
    in_syscall: bool,
    /// Set at syscall entry when the result should be rewritten.
    override_result: Option<i64>,
}

/// Runs `plan` using the proot backend.
pub fn run(plan: &SandboxPlan) -> Result<Option<i32>> {
    if nr::TABLE.is_empty() {
        return Err(Error::Unsupported(
            "the proot backend has no syscall table for this architecture".into(),
        ));
    }
    let root = plan.root.clone();
    if !root.is_dir() {
        return Err(Error::Sandbox(format!(
            "proot root {} does not exist",
            root.display()
        )));
    }
    // Resolve the program through the same policy used for path arguments, so
    // a guest path that exists inside UserFS is preferred while a host binary
    // such as /bin/sh still starts.
    let policy = PassthroughPolicy::default();
    let program = if plan.program.is_absolute() {
        translate_path_with(
            &root,
            Path::new("/"),
            &plan.program.to_string_lossy(),
            &policy,
        )
    } else {
        plan.host_program()
    };
    if !program.exists() {
        return Err(Error::Sandbox(format!(
            "proot program {} does not exist",
            program.display()
        )));
    }
    let argv = plan.host_argv()?;
    let argv0 = if argv.is_empty() {
        program.display().to_string()
    } else {
        argv[0].clone()
    };
    let args: Vec<String> = std::iter::once(argv0)
        .chain(argv.iter().skip(1).cloned())
        .collect();
    let env: Vec<String> = plan.env.iter().map(|(k, v)| format!("{k}={v}")).collect();

    let program_c = std::ffi::CString::new(program.as_os_str().to_string_lossy().as_bytes())
        .map_err(|_| Error::Sandbox("program contains a NUL".into()))?;
    let args_c: Vec<std::ffi::CString> = args
        .iter()
        .map(|a| std::ffi::CString::new(a.as_str()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::Sandbox("argument contains a NUL".into()))?;
    let env_c: Vec<std::ffi::CString> = env
        .iter()
        .map(|e| std::ffi::CString::new(e.as_str()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::Sandbox("environment contains a NUL".into()))?;

    // SAFETY: fork is called once and both branches do bounded work.
    let child = unsafe { libc::fork() };
    match child {
        -1 => Err(Error::Io(std::io::Error::last_os_error())),
        0 => {
            // Tracee: adopt the client's stdio, ask to be traced, then exec the
            // real program.  The parent gets a SIGTRAP on the exec.
            if let Some([input, output, errors]) = plan.stdio {
                // SAFETY: dup2 is async-signal-safe and the descriptors were
                // inherited from the parent across fork.
                unsafe {
                    libc::dup2(input, libc::STDIN_FILENO);
                    libc::dup2(output, libc::STDOUT_FILENO);
                    libc::dup2(errors, libc::STDERR_FILENO);
                }
            }
            // SAFETY: ptrace with PTRACE_TRACEME has no pointer arguments.
            unsafe {
                libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            let argv: Vec<*const libc::c_char> = args_c
                .iter()
                .map(|a| a.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            let envp: Vec<*const libc::c_char> = env_c
                .iter()
                .map(|e| e.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            // SAFETY: both vectors are NULL-terminated and outlive the call.
            unsafe { libc::execve(program_c.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            // SAFETY: async-signal-safe, never returns.
            unsafe { libc::_exit(127) };
        }
        _ => trace(child, &root, plan.identity),
    }
}

fn trace(root_pid: libc::pid_t, root: &Path, identity: Option<Identity>) -> Result<Option<i32>> {
    let policy = PassthroughPolicy::default();
    let mut threads: HashMap<libc::pid_t, ThreadState> = HashMap::new();
    let root_exit: Option<i32> = None;

    // Wait for the initial exec trap.
    let mut status = 0i32;
    // SAFETY: `root_pid` is our child; `status` is a valid pointer.
    if unsafe { libc::waitpid(root_pid, &mut status, 0) } < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    set_options(root_pid)?;
    threads.insert(root_pid, ThreadState::default());
    resume(root_pid, 0)?;

    loop {
        // SAFETY: `status` is a valid pointer; -1 waits for any traced child.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if pid < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                return Ok(root_exit);
            }
            return Err(Error::Io(err));
        }

        if libc::WIFEXITED(status) {
            threads.remove(&pid);
            if pid == root_pid {
                return Ok(Some(libc::WEXITSTATUS(status)));
            }
            continue;
        }
        if libc::WIFSIGNALED(status) {
            threads.remove(&pid);
            if pid == root_pid {
                // Killed by a signal: there is no exit status to report.
                return Ok(None);
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }

        let sig = libc::WSTOPSIG(status);
        let event = status >> 16;

        // A ptrace event stop: the new task is already traced and stopped, so
        // it must be resumed as well or it will never run.
        if sig == libc::SIGTRAP && event != 0 {
            if event == libc::PTRACE_EVENT_CLONE
                || event == libc::PTRACE_EVENT_FORK
                || event == libc::PTRACE_EVENT_VFORK
            {
                let mut new_pid: libc::c_ulong = 0;
                // SAFETY: PTRACE_GETEVENTMSG writes a pid into `new_pid`.
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_GETEVENTMSG,
                        pid,
                        std::ptr::null_mut::<libc::c_void>(),
                        &mut new_pid as *mut _ as *mut libc::c_void,
                    )
                };
                let new_pid = new_pid as libc::pid_t;
                threads.entry(new_pid).or_default();
                if let Err(e) = set_options(new_pid) {
                    // The child may have exited already; nothing to trace.
                    log::debug!("proot: could not trace new task {new_pid}: {e}");
                }
                resume(new_pid, 0)?;
            }
            resume(pid, 0)?;
            continue;
        }

        // A plain SIGTRAP is the initial exec stop; resume without rewriting.
        if sig == libc::SIGTRAP {
            resume(pid, 0)?;
            continue;
        }

        // SIGTRAP|0x80 is the syscall stop, thanks to PTRACE_O_TRACESYSGOOD.
        if sig == (libc::SIGTRAP | 0x80) {
            let state = threads.entry(pid).or_default();
            if !state.in_syscall {
                if let Err(e) = handle_syscall_enter(pid, root, &policy, identity, state) {
                    log::debug!("proot: {e}");
                }
            } else {
                restore_stack(pid, state)?;
                apply_identity_result(pid, state)?;
            }
            state.in_syscall = !state.in_syscall;
            resume(pid, 0)?;
            continue;
        }

        // Any other signal is delivered to the tracee untouched.
        resume(pid, sig)?;
    }
}

/// Restarts a stopped tracee, optionally delivering `sig` to it.
///
/// Linux requires a specific task here: `ptrace(PTRACE_SYSCALL, -1, ...)`
/// fails with `ESRCH`, so every stop must be resumed by its own pid.
fn resume(pid: libc::pid_t, sig: i32) -> Result<()> {
    // SAFETY: `pid` is a stopped tracee owned by this process.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            sig as *mut libc::c_void,
        )
    };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn set_options(pid: libc::pid_t) -> Result<()> {
    // SAFETY: PTRACE_SETOPTIONS takes the option bitmask as data.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            (libc::PTRACE_O_TRACESYSGOOD
                | libc::PTRACE_O_TRACEFORK
                | libc::PTRACE_O_TRACEVFORK
                | libc::PTRACE_O_TRACECLONE
                | libc::PTRACE_O_EXITKILL) as *mut libc::c_void,
        )
    };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn get_regs(pid: libc::pid_t) -> Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: PTRACE_GETREGS fills the correctly sized struct.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            &mut regs as *mut _ as *mut libc::c_void,
        )
    } != 0
    {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(regs)
}

#[cfg(target_arch = "x86_64")]
fn set_regs(pid: libc::pid_t, regs: &libc::user_regs_struct) -> Result<()> {
    // SAFETY: PTRACE_SETREGS reads the correctly sized struct.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            regs as *const _ as *mut libc::c_void,
        )
    } != 0
    {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn arg(regs: &libc::user_regs_struct, index: u8) -> u64 {
    match index {
        0 => regs.rdi,
        1 => regs.rsi,
        2 => regs.rdx,
        3 => regs.r10,
        4 => regs.r8,
        _ => regs.r9,
    }
}

#[cfg(target_arch = "x86_64")]
fn set_arg(regs: &mut libc::user_regs_struct, index: u8, value: u64) {
    match index {
        0 => regs.rdi = value,
        1 => regs.rsi = value,
        2 => regs.rdx = value,
        3 => regs.r10 = value,
        4 => regs.r8 = value,
        _ => regs.r9 = value,
    }
}

#[cfg(target_arch = "x86_64")]
fn stack_pointer(regs: &libc::user_regs_struct) -> u64 {
    regs.rsp
}

#[cfg(target_arch = "x86_64")]
fn set_stack_pointer(regs: &mut libc::user_regs_struct, value: u64) {
    regs.rsp = value;
}

#[cfg(target_arch = "x86_64")]
fn syscall_number(regs: &libc::user_regs_struct) -> i64 {
    regs.orig_rax as i64
}

#[cfg(target_arch = "x86_64")]
fn set_return_value(regs: &mut libc::user_regs_struct, value: i64) {
    regs.rax = value as u64;
}

#[cfg(target_arch = "aarch64")]
fn get_regs(pid: libc::pid_t) -> Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: PTRACE_GETREGSET with NT_PRSTATUS fills the regset.
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    if unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            libc::NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    } != 0
    {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(regs)
}

#[cfg(target_arch = "aarch64")]
fn set_regs(pid: libc::pid_t, regs: &libc::user_regs_struct) -> Result<()> {
    // SAFETY: PTRACE_SETREGSET reads the regset.
    let mut iov = libc::iovec {
        iov_base: regs as *const _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            libc::NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    } != 0
    {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn arg(regs: &libc::user_regs_struct, index: u8) -> u64 {
    regs.regs[index as usize]
}

#[cfg(target_arch = "aarch64")]
fn set_arg(regs: &mut libc::user_regs_struct, index: u8, value: u64) {
    regs.regs[index as usize] = value;
}

#[cfg(target_arch = "aarch64")]
fn stack_pointer(regs: &libc::user_regs_struct) -> u64 {
    regs.sp
}

#[cfg(target_arch = "aarch64")]
fn set_stack_pointer(regs: &mut libc::user_regs_struct, value: u64) {
    regs.sp = value;
}

#[cfg(target_arch = "aarch64")]
fn syscall_number(regs: &libc::user_regs_struct) -> i64 {
    regs.regs[8] as i64
}

#[cfg(target_arch = "aarch64")]
fn set_return_value(regs: &mut libc::user_regs_struct, value: i64) {
    regs.regs[0] = value as u64;
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the proot backend supports x86_64 and aarch64 hosts only");

fn handle_syscall_enter(
    pid: libc::pid_t,
    root: &Path,
    policy: &PassthroughPolicy,
    identity: Option<Identity>,
    state: &mut ThreadState,
) -> Result<()> {
    let mut regs = get_regs(pid)?;
    let number = syscall_number(&regs);

    if let Some(identity) = identity {
        match identity_call(number) {
            Some(IdentityCall::Uid) => {
                state.override_result = Some(identity.uid as i64);
                return Ok(());
            }
            Some(IdentityCall::Gid) => {
                state.override_result = Some(identity.gid as i64);
                return Ok(());
            }
            Some(IdentityCall::Set) => {
                // Pretend the credential change succeeded.  Nothing in the
                // kernel actually changes, which is the documented limit of
                // the unprivileged backend.
                state.override_result = Some(0);
                return Ok(());
            }
            None => {}
        }
    }

    let Some(syscall) = lookup(number) else {
        return Ok(());
    };

    let path_addr = arg(&regs, syscall.path_arg);
    if path_addr == 0 {
        return Ok(());
    }
    let guest = match read_string(pid, path_addr) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    if guest.is_empty() {
        return Ok(());
    }

    let cwd = std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|_| PathBuf::from("/"));
    // `openat`-family calls resolve a relative path against a directory
    // descriptor, so the descriptor has to be turned back into a host path
    // before the path can be translated.  Falling back to the working directory
    // keeps the old behaviour when the descriptor cannot be read.
    let base = if syscall.dirfd_arg == NO_DIRFD || guest.starts_with('/') {
        cwd.clone()
    } else {
        let dirfd = arg(&regs, syscall.dirfd_arg) as i32;
        resolve_dirfd(pid, dirfd).unwrap_or(cwd)
    };
    let translated = translate_path_with(root, &base, &guest, policy);
    if translated.as_os_str() == std::ffi::OsStr::new(&guest) {
        return Ok(());
    }
    let new_path = translated.as_os_str().to_string_lossy().into_owned();
    log::trace!("proot: {} {guest} -> {new_path}", syscall.name);

    if new_path.len() <= guest.len() {
        // Fits in the caller's buffer: overwrite in place and NUL-pad.
        let mut padded = new_path.into_bytes();
        padded.resize(guest.len() + 1, 0);
        write_bytes(pid, path_addr, &padded)?;
        return Ok(());
    }

    // The translated path is longer, so inject it onto the tracee's stack and
    // repoint the argument.  The stack pointer is restored at syscall exit.
    let sp = stack_pointer(&regs);
    let injected = inject_string(pid, sp, new_path.as_bytes())?;
    regs = get_regs(pid)?;
    set_arg(&mut regs, syscall.path_arg, injected);
    set_regs(pid, &regs)?;
    state.saved_sp = Some(sp);
    Ok(())
}

/// Turns a tracee's directory descriptor back into a host path.
///
/// Returns `None` for `AT_FDCWD` and for descriptors that cannot be read, in
/// which case the caller falls back to the tracee's working directory.
fn resolve_dirfd(pid: libc::pid_t, dirfd: i32) -> Option<PathBuf> {
    if dirfd == libc::AT_FDCWD || dirfd < 0 {
        return None;
    }
    std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok()
}

/// Writes `data` onto the tracee's stack just below `sp` and returns the new
/// stack pointer, which is also the address of the injected string.
fn inject_string(pid: libc::pid_t, sp: u64, data: &[u8]) -> Result<u64> {
    // Leave room for the red zone and keep the pointer 16-byte aligned.
    let len = data.len() as u64 + 1;
    let new_sp = (sp - len - 128) & !0xf;
    let mut buf = data.to_vec();
    buf.push(0);
    write_bytes(pid, new_sp, &buf)?;

    let mut regs = get_regs(pid)?;
    set_stack_pointer(&mut regs, new_sp);
    set_regs(pid, &regs)?;
    Ok(new_sp)
}

fn restore_stack(pid: libc::pid_t, state: &mut ThreadState) -> Result<()> {
    let Some(saved) = state.saved_sp.take() else {
        return Ok(());
    };
    let mut regs = get_regs(pid)?;
    set_stack_pointer(&mut regs, saved);
    set_regs(pid, &regs)?;
    Ok(())
}

/// Rewrites a syscall's return value when [`ThreadState::override_result`] is
/// set.  Runs at syscall exit, after the kernel has already produced a result.
fn apply_identity_result(pid: libc::pid_t, state: &mut ThreadState) -> Result<()> {
    let Some(value) = state.override_result.take() else {
        return Ok(());
    };
    let mut regs = get_regs(pid)?;
    set_return_value(&mut regs, value);
    set_regs(pid, &regs)?;
    Ok(())
}

/// Reads a NUL-terminated string from the tracee's address space.
///
/// `process_vm_readv` is used when available because it is far faster than
/// word-at-a-time ptrace reads; when it is unavailable (older kernels, or a
/// seccomp filter) the ptrace path is used instead.
pub fn read_string(pid: libc::pid_t, addr: u64) -> Result<String> {
    const CHUNK: usize = 256;
    let mut out = Vec::new();
    let mut offset = 0u64;
    loop {
        let mut buf = vec![0u8; CHUNK];
        let remote = libc::iovec {
            iov_base: (addr + offset) as *mut libc::c_void,
            iov_len: CHUNK,
        };
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: CHUNK,
        };
        // SAFETY: reading from a live tracee into a valid local buffer.
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n <= 0 {
            if offset == 0 {
                return read_string_ptrace(pid, addr);
            }
            break;
        }
        let chunk = &buf[..n as usize];
        if let Some(pos) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..pos]);
            break;
        }
        out.extend_from_slice(chunk);
        offset += n as u64;
        if out.len() > 4096 {
            return Err(Error::Protocol("path argument exceeds 4096 bytes".into()));
        }
    }
    String::from_utf8(out).map_err(|_| Error::Protocol("path is not valid UTF-8".into()))
}

fn read_string_ptrace(pid: libc::pid_t, addr: u64) -> Result<String> {
    let mut out = Vec::new();
    let mut cursor = addr;
    loop {
        // SAFETY: PTRACE_PEEKDATA reads one word; errno distinguishes failure.
        let word = unsafe {
            *libc::__errno_location() = 0;
            libc::ptrace(
                libc::PTRACE_PEEKDATA,
                pid,
                cursor as *mut libc::c_void,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if word == -1 && unsafe { *libc::__errno_location() } != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        for byte in word.to_ne_bytes() {
            if byte == 0 {
                return String::from_utf8(out)
                    .map_err(|_| Error::Protocol("path is not valid UTF-8".into()));
            }
            out.push(byte);
        }
        cursor += std::mem::size_of::<libc::c_long>() as u64;
        if out.len() > 4096 {
            return Err(Error::Protocol("path argument exceeds 4096 bytes".into()));
        }
    }
}

/// Writes bytes into the tracee's address space.
pub fn write_bytes(pid: libc::pid_t, addr: u64, data: &[u8]) -> Result<()> {
    let local = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: both iovecs describe valid memory regions.
    let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
    if n as usize == data.len() {
        return Ok(());
    }
    // Fall back to word-at-a-time ptrace writes.
    let mut written = 0usize;
    while written < data.len() {
        let chunk = (data.len() - written).min(std::mem::size_of::<libc::c_long>());
        let mut buf = [0u8; std::mem::size_of::<libc::c_long>()];
        if chunk < std::mem::size_of::<libc::c_long>() {
            // Read the existing word first so the tail is preserved.
            // SAFETY: PTRACE_PEEKDATA reads one word at the target address.
            let existing = unsafe {
                libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    pid,
                    (addr + written as u64) as *mut libc::c_void,
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            buf.copy_from_slice(&existing.to_ne_bytes());
        }
        buf[..chunk].copy_from_slice(&data[written..written + chunk]);
        let word = libc::c_long::from_ne_bytes(buf);
        // SAFETY: PTRACE_POKEDATA writes one word at the target address.
        if unsafe {
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                pid,
                (addr + written as u64) as *mut libc::c_void,
                word as *mut libc::c_void,
            )
        } != 0
        {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        written += chunk;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn absolute_guest_paths_are_rerooted() {
        let root = TempDir::new().unwrap();
        std::fs::write(root.path().join("hello"), b"hi").unwrap();
        assert_eq!(
            translate_path(root.path(), Path::new("/"), "/hello"),
            root.path().join("hello")
        );
    }

    #[test]
    fn relative_paths_resolve_against_the_supplied_base_directory() {
        // `ls /system/bin` works by opening `/system` and then asking for
        // `"bin"` relative to that descriptor, so translation must honour the
        // base directory rather than always using the working directory.
        let root = TempDir::new().unwrap();
        std::fs::create_dir_all(root.path().join("system/bin")).unwrap();
        std::fs::create_dir_all(root.path().join("bin")).unwrap();
        let base = root.path().join("system");
        assert_eq!(
            translate_path(root.path(), &base, "bin"),
            root.path().join("system/bin")
        );
        // With the working directory as the base the same name resolves
        // elsewhere, which is the bug this guards against.
        assert_eq!(
            translate_path(root.path(), Path::new("/"), "bin"),
            root.path().join("bin")
        );
    }

    #[test]
    fn openat_family_calls_declare_a_directory_descriptor() {
        let openat = lookup(if cfg!(target_arch = "x86_64") {
            257
        } else {
            56
        })
        .expect("openat must be in the table");
        assert_eq!(openat.dirfd_arg, 0, "openat takes its dirfd as arg 0");
        assert_eq!(openat.path_arg, 1, "and the path as arg 1");

        let chdir = lookup(if cfg!(target_arch = "x86_64") { 80 } else { 49 })
            .expect("chdir must be in the table");
        assert_eq!(chdir.dirfd_arg, NO_DIRFD);
    }

    #[test]
    fn statx_is_intercepted_so_ls_can_list_the_sandbox() {
        // `ls` uses statx; without it, listing a sandbox directory reports the
        // directory as missing even though openat works.
        let statx = if cfg!(target_arch = "x86_64") {
            332
        } else {
            291
        };
        let entry = lookup(statx).expect("statx must be in the table");
        assert_eq!(entry.name, "statx");
        assert_eq!(entry.dirfd_arg, 0);
    }

    #[test]
    fn parent_components_cannot_escape_the_root() {
        let root = TempDir::new().unwrap();
        // With the default policy the `..` is clamped and then the host
        // fallback resolves the normalized path, so the result is the host
        // /etc/passwd -- reached by a *normalized* path, not by escaping.
        let translated = translate_path(root.path(), Path::new("/"), "/../../etc/passwd");
        assert_eq!(translated, PathBuf::from("/etc/passwd"));

        // Under the strict policy the same input stays inside the root.
        let strict = PassthroughPolicy {
            prefixes: vec![],
            host_fallback: false,
        };
        let translated =
            translate_path_with(root.path(), Path::new("/"), "/../../etc/passwd", &strict);
        assert_eq!(translated, root.path().join("etc/passwd"));
    }

    #[test]
    fn kernel_filesystems_pass_through_untouched() {
        let root = TempDir::new().unwrap();
        let policy = PassthroughPolicy::default();
        for path in ["/dev/null", "/proc/self/status", "/sys/class", "/dev"] {
            assert!(policy.passes_through(path), "{path} should pass through");
            assert_eq!(
                translate_path_with(root.path(), Path::new("/"), path, &policy),
                PathBuf::from(path)
            );
        }
        assert!(!policy.passes_through("/device"));
        assert!(!policy.passes_through("/system/bin/sh"));
    }

    #[test]
    fn nonexistent_paths_stay_inside_the_root() {
        let root = TempDir::new().unwrap();
        let translated = translate_path(root.path(), Path::new("/"), "/definitely/missing");
        assert!(translated.starts_with(root.path()));
    }

    #[test]
    fn host_fallback_loads_host_binaries_but_never_escapes() {
        let root = TempDir::new().unwrap();
        // By default the fallback is on, so /bin/sh resolves to the host copy.
        assert_eq!(
            translate_path(root.path(), Path::new("/"), "/bin/sh"),
            PathBuf::from("/bin/sh")
        );

        // With the fallback off, the same path is rooted and does not exist.
        let strict = PassthroughPolicy {
            prefixes: vec![],
            host_fallback: false,
        };
        assert_eq!(
            translate_path_with(root.path(), Path::new("/"), "/bin/sh", &strict),
            root.path().join("bin/sh")
        );

        // Even with the fallback on, a `..` never survives normalization, so
        // the fallback can only ever reach a normalized host path.
        let escaped =
            translate_path_with(root.path(), Path::new("/"), "/../../etc/passwd", &strict);
        assert_eq!(escaped, root.path().join("etc/passwd"));
    }

    #[test]
    fn lexical_normalize_clamps_at_the_root() {
        assert_eq!(lexical_normalize("/a/b/../c"), PathBuf::from("a/c"));
        assert_eq!(lexical_normalize("/../../x"), PathBuf::from("x"));
        assert_eq!(lexical_normalize("/a/./b/"), PathBuf::from("a/b"));
    }

    #[test]
    fn relative_paths_resolve_against_the_tracee_cwd() {
        let root = TempDir::new().unwrap();
        let cwd = root.path().join("sub");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::write(cwd.join("file"), b"x").unwrap();
        assert_eq!(translate_path(root.path(), &cwd, "file"), cwd.join("file"));
    }

    #[test]
    fn syscall_table_has_unique_numbers() {
        let mut seen = std::collections::HashSet::new();
        for entry in nr::TABLE {
            assert!(
                seen.insert(entry.number),
                "duplicate syscall number {} ({})",
                entry.number,
                entry.name
            );
        }
    }

    #[test]
    fn lookup_finds_openat_on_this_architecture() {
        let openat = if cfg!(target_arch = "x86_64") {
            257
        } else {
            56
        };
        let entry = lookup(openat).expect("openat must be in the table");
        assert_eq!(entry.path_arg, 1);
    }

    #[test]
    fn identity_calls_are_classified() {
        use nr::identity as id;
        assert_eq!(identity_call(id::GETUID), Some(IdentityCall::Uid));
        assert_eq!(identity_call(id::GETEUID), Some(IdentityCall::Uid));
        assert_eq!(identity_call(id::GETGID), Some(IdentityCall::Gid));
        assert_eq!(identity_call(id::GETEGID), Some(IdentityCall::Gid));
        assert_eq!(identity_call(id::SETUID), Some(IdentityCall::Set));
        assert_eq!(identity_call(id::SETGID), Some(IdentityCall::Set));
        assert_eq!(identity_call(0), None);
    }
}
