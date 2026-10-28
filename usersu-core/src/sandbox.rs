//! Sandbox backends: how usud runs an init system or a command tree.
//!
//! Four backends are supported, in decreasing order of strength:
//!
//! * [`Backend::Um`] boots a user-mode Linux kernel (`linux-um-aarch64` on
//!   arm64, the plain UML target on amd64) with the UserFS tree as its root via
//!   hostfs.  The sandboxed kernel is a real kernel, so it provides its own
//!   syscall table and device model.
//! * [`Backend::PivotRoot`] bind-mounts UserFS and `pivot_root(2)`s into it.
//! * [`Backend::Chroot`] is `chroot(2)` with the pseudo-filesystems mounted.
//! * [`Backend::Proot`] needs no privileges at all; see [`crate::proot`].
//!
//! Selection is driven by [`SandboxBackend`] plus a capability probe, never by
//! assumption.  [`select`] is pure and therefore unit-tested; [`Sandbox::spawn`]
//! performs the work.

use crate::config::SandboxBackend;
use crate::error::{Error, Result};
use crate::privilege;
use std::ffi::CString;
use std::path::{Path, PathBuf};

/// A concrete backend, resolved from configuration and capability probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Boot a user-mode Linux kernel.
    Um,
    /// `pivot_root(2)` into UserFS.
    PivotRoot,
    /// `chroot(2)` into UserFS.
    Chroot,
    /// ptrace-based path rewriting; no privileges required.
    Proot,
}

impl Backend {
    /// Stable string form used in IPC and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Um => "um",
            Backend::PivotRoot => "pivot-root",
            Backend::Chroot => "chroot",
            Backend::Proot => "proot",
        }
    }

    /// Whether the backend needs real root on the host.
    pub fn needs_root(self) -> bool {
        !matches!(self, Backend::Proot)
    }
}

/// What the host can actually do, gathered by [`probe`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// Real root is available.
    pub root: bool,
    /// A user-mode Linux kernel image was found.
    pub uml_kernel: Option<PathBuf>,
    /// `CLONE_NEWUSER` appears usable, which lets an unprivileged process
    /// create a mount namespace and `pivot_root` inside it.
    pub user_namespaces: bool,
}

/// Gathers host capabilities.
pub fn probe(uml_kernel: Option<PathBuf>) -> Capabilities {
    Capabilities {
        root: privilege::has_root(),
        uml_kernel: uml_kernel.filter(|p| p.is_file()),
        user_namespaces: user_namespaces_enabled(),
    }
}

/// Best-effort check for unprivileged user namespaces.
///
/// Android disables these from Android 10 onward, which is precisely why the
/// ptrace backend exists; a `true` here is only a hint and the actual
/// `unshare(2)` is still allowed to fail.
pub fn user_namespaces_enabled() -> bool {
    for path in [
        "/proc/sys/kernel/unprivileged_userns_clone",
        "/proc/sys/user/max_user_namespaces",
    ] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let text = text.trim();
            if let Ok(value) = text.parse::<i64>() {
                return value > 0;
            }
        }
    }
    false
}

/// Chooses a backend from the configured preference and probed capabilities.
pub fn select(preference: SandboxBackend, caps: &Capabilities) -> Backend {
    match preference {
        SandboxBackend::Um => Backend::Um,
        SandboxBackend::PivotRoot => {
            if caps.root {
                Backend::PivotRoot
            } else if caps.user_namespaces {
                // pivot_root is available inside a user namespace.
                Backend::PivotRoot
            } else {
                Backend::Proot
            }
        }
        SandboxBackend::Chroot => {
            if caps.root {
                Backend::Chroot
            } else {
                Backend::Proot
            }
        }
        SandboxBackend::Proot => Backend::Proot,
        SandboxBackend::Auto => {
            if caps.uml_kernel.is_some() {
                Backend::Um
            } else if caps.root {
                Backend::PivotRoot
            } else {
                Backend::Proot
            }
        }
    }
}

/// A pseudo-filesystem to mount inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudoMount {
    /// Mount source.
    pub source: String,
    /// Mount point, relative to the sandbox root.
    pub target: String,
    /// Filesystem type.
    pub fstype: String,
    /// Mount options.
    pub options: String,
}

/// The standard pseudo-filesystems an init system expects.
pub fn default_pseudo_mounts() -> Vec<PseudoMount> {
    vec![
        PseudoMount {
            source: "proc".into(),
            target: "/proc".into(),
            fstype: "proc".into(),
            options: "nosuid,nodev,noexec".into(),
        },
        PseudoMount {
            source: "sysfs".into(),
            target: "/sys".into(),
            fstype: "sysfs".into(),
            options: "nosuid,nodev,noexec".into(),
        },
        PseudoMount {
            source: "devpts".into(),
            target: "/dev/pts".into(),
            fstype: "devpts".into(),
            options: "nosuid,noexec,mode=620".into(),
        },
        PseudoMount {
            source: "tmpfs".into(),
            target: "/tmp".into(),
            fstype: "tmpfs".into(),
            options: "nosuid,nodev,mode=1777".into(),
        },
        PseudoMount {
            source: "tmpfs".into(),
            target: "/run".into(),
            fstype: "tmpfs".into(),
            options: "nosuid,nodev,mode=755".into(),
        },
    ]
}

/// Everything needed to start a sandboxed process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    /// Chosen backend.
    pub backend: Backend,
    /// UserFS root that becomes `/` inside the sandbox.
    pub root: PathBuf,
    /// Program to execute, as seen from inside the sandbox.
    pub program: PathBuf,
    /// Arguments, including `argv[0]`.
    pub args: Vec<String>,
    /// Environment for the sandboxed process.
    pub env: Vec<(String, String)>,
    /// Pseudo-filesystems to mount.
    pub mounts: Vec<PseudoMount>,
    /// Host-side UML kernel image, for [`Backend::Um`].
    pub uml_kernel: Option<PathBuf>,
    /// Guest memory size for [`Backend::Um`], in mebibytes.
    pub uml_memory_mib: u32,
    /// Whether to create a mount namespace before pivoting.
    pub new_mount_namespace: bool,
    /// Whether to create a user namespace first (unprivileged pivot_root).
    pub new_user_namespace: bool,
    /// Fake identity presented by the ptrace backend.  `None` means report the
    /// real credentials.
    pub identity: Option<crate::proot::Identity>,
    /// File descriptors the sandboxed process should use for stdin, stdout and
    /// stderr.  `None` means inherit the launcher's own descriptors.
    ///
    /// These are the descriptors received from the `su` client over the daemon
    /// socket, so the sandboxed command's output goes back to whoever ran `su`
    /// rather than into the daemon's log.
    pub stdio: Option<[libc::c_int; 3]>,
}

impl SandboxPlan {
    /// Builds a plan for running `program` inside `root`.
    pub fn new(
        backend: Backend,
        root: impl Into<PathBuf>,
        program: impl Into<PathBuf>,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> Self {
        let backend_kind = backend;
        Self {
            backend,
            root: root.into(),
            program: program.into(),
            args,
            env,
            mounts: if backend_kind == Backend::Proot {
                Vec::new()
            } else {
                default_pseudo_mounts()
            },
            uml_kernel: None,
            uml_memory_mib: 512,
            new_mount_namespace: true,
            new_user_namespace: backend_kind == Backend::PivotRoot && !privilege::has_root(),
            identity: if backend_kind == Backend::Proot {
                Some(crate::proot::Identity::ROOT)
            } else {
                None
            },
            stdio: None,
        }
    }

    /// Sets the descriptors the sandboxed process should use for stdio.
    pub fn with_stdio(mut self, stdio: Option<[libc::c_int; 3]>) -> Self {
        self.stdio = stdio;
        self
    }

    /// Overrides the fake identity presented by the ptrace backend.
    pub fn with_identity(mut self, identity: Option<crate::proot::Identity>) -> Self {
        self.identity = identity;
        self
    }

    /// Sets the UML kernel image and memory size.
    pub fn with_uml(mut self, kernel: PathBuf, memory_mib: u32) -> Self {
        self.uml_kernel = Some(kernel);
        self.uml_memory_mib = memory_mib;
        self
    }

    /// The argv to hand to `execve` on the host.
    ///
    /// For every backend except [`Backend::Um`] this is the guest program; the
    /// UML backend instead executes the kernel and passes the guest init as a
    /// kernel command line argument.
    pub fn host_argv(&self) -> Result<Vec<String>> {
        match self.backend {
            Backend::Um => {
                let kernel = self
                    .uml_kernel
                    .as_ref()
                    .ok_or_else(|| Error::Sandbox("no UML kernel image configured".into()))?;
                let init = if self.args.is_empty() {
                    self.program.display().to_string()
                } else {
                    self.args[0].clone()
                };
                let mut argv = vec![kernel.display().to_string()];
                // hostfs makes the UserFS tree the sandboxed kernel's root, so
                // no block device or image file is required.
                argv.push("rootfstype=hostfs".to_string());
                argv.push(format!("rootflags={}", self.root.display()));
                argv.push("rw".to_string());
                argv.push(format!("mem={}M", self.uml_memory_mib));
                argv.push(format!("init={init}"));
                argv.push("con0=fd:0,fd:1".to_string());
                for arg in self.args.iter().skip(1) {
                    argv.push(arg.clone());
                }
                Ok(argv)
            }
            _ => {
                let program = if self.program.is_absolute() {
                    self.program.display().to_string()
                } else {
                    format!("/{}", self.program.display())
                };
                let mut argv = vec![program];
                // args[0] is argv[0]; keep the guest spelling.
                argv.extend(self.args.iter().skip(1).cloned());
                Ok(argv)
            }
        }
    }

    /// Host-side path of the program, for backends that exec directly.
    pub fn host_program(&self) -> PathBuf {
        match self.backend {
            Backend::Um => self.uml_kernel.clone().unwrap_or_default(),
            _ => self
                .root
                .join(self.program.strip_prefix("/").unwrap_or(&self.program)),
        }
    }
}

/// Runs sandboxed processes.
pub struct Sandbox {
    plan: SandboxPlan,
}

impl Sandbox {
    /// Creates a sandbox for `plan`.
    pub fn new(plan: SandboxPlan) -> Self {
        Self { plan }
    }

    /// The plan this sandbox will execute.
    pub fn plan(&self) -> &SandboxPlan {
        &self.plan
    }

    /// Spawns the sandboxed process and waits for it.
    ///
    /// Returns the exit code, or `None` when the process was signalled.
    pub fn run(&self) -> Result<Option<i32>> {
        match self.plan.backend {
            Backend::Proot => crate::proot::run(&self.plan),
            Backend::Um => self.run_um(),
            Backend::Chroot | Backend::PivotRoot => self.run_rooted(),
        }
    }

    fn run_um(&self) -> Result<Option<i32>> {
        let argv = self.plan.host_argv()?;
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd.env_clear();
        for (k, v) in &self.plan.env {
            cmd.env(k, v);
        }
        let status = cmd.status()?;
        Ok(status.code())
    }

    fn run_rooted(&self) -> Result<Option<i32>> {
        if !privilege::has_root() && !self.plan.new_user_namespace {
            return Err(Error::NotRoot(
                "the chroot and pivot_root backends need CAP_SYS_ADMIN",
            ));
        }
        let argv = self.plan.host_argv()?;
        let program = CString::new(argv[0].clone())
            .map_err(|_| Error::Sandbox("program contains a NUL".into()))?;
        let c_args: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(a.as_str()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| Error::Sandbox("argument contains a NUL".into()))?;
        let c_env: Vec<CString> = self
            .plan
            .env
            .iter()
            .map(|(k, v)| CString::new(format!("{k}={v}")))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| Error::Sandbox("environment contains a NUL".into()))?;
        let root = self.plan.root.clone();
        let pivot = self.plan.backend == Backend::PivotRoot;
        let new_mnt = self.plan.new_mount_namespace;
        let new_usr = self.plan.new_user_namespace;
        let mounts = self.plan.mounts.clone();

        // SAFETY: the child performs only async-signal-safe work before exec.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => Err(Error::Io(std::io::Error::last_os_error())),
            0 => {
                let code = child_main(
                    &root, pivot, new_mnt, new_usr, &mounts, &program, &c_args, &c_env,
                );
                // SAFETY: _exit is async-signal-safe and never returns.
                unsafe { libc::_exit(code) };
            }
            child => {
                let mut status = 0i32;
                // SAFETY: `child` is a live pid and `status` is a valid pointer.
                if unsafe { libc::waitpid(child, &mut status, 0) } < 0 {
                    return Err(Error::Io(std::io::Error::last_os_error()));
                }
                if libc::WIFEXITED(status) {
                    Ok(Some(libc::WEXITSTATUS(status)))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn child_main(
    root: &Path,
    pivot: bool,
    new_mnt: bool,
    new_usr: bool,
    mounts: &[PseudoMount],
    program: &CString,
    args: &[CString],
    env: &[CString],
) -> i32 {
    if new_usr {
        // Map our uid to root inside the new namespace so that chroot and
        // mount are permitted.  Writing these files is itself only allowed
        // once the namespace exists.
        // SAFETY: unshare is called once, before any other work.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            return 1;
        }
        if !write_id_maps() {
            return 1;
        }
    }
    if new_mnt {
        // SAFETY: called before chroot; propagates mount events nowhere.
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
            return 1;
        }
        let slash = c"/";
        // SAFETY: valid C string constant.
        unsafe {
            libc::mount(
                std::ptr::null(),
                slash.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        };
    }

    if pivot {
        if !do_pivot_root(root) {
            return 1;
        }
    } else {
        let c_root = match CString::new(root.as_os_str().to_string_lossy().as_bytes()) {
            Ok(c) => c,
            Err(_) => return 1,
        };
        // SAFETY: `c_root` is a valid NUL-terminated path.
        if unsafe { libc::chroot(c_root.as_ptr()) } != 0 {
            return 1;
        }
        let dot = c"/";
        // SAFETY: valid C string constant.
        if unsafe { libc::chdir(dot.as_ptr()) } != 0 {
            return 1;
        }
    }

    for mount in mounts {
        let Ok(source) = CString::new(mount.source.as_str()) else {
            return 1;
        };
        let Ok(target) = CString::new(mount.target.as_str()) else {
            return 1;
        };
        let Ok(fstype) = CString::new(mount.fstype.as_str()) else {
            return 1;
        };
        let Ok(options) = CString::new(mount.options.as_str()) else {
            return 1;
        };
        // Best effort: a missing /dev/pts must not abort a boot.
        // SAFETY: all pointers are valid NUL-terminated strings.
        unsafe {
            libc::mkdir(target.as_ptr(), 0o755);
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                options.as_ptr() as *const libc::c_void,
            );
        }
    }

    let argv: Vec<*const libc::c_char> = args
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp: Vec<*const libc::c_char> = env
        .iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // SAFETY: both vectors are NULL-terminated and outlive the call.
    unsafe { libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    127
}

fn write_id_maps() -> bool {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let setgroups = std::fs::write("/proc/self/setgroups", b"deny").is_ok();
    let uid_ok = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).is_ok();
    let gid_ok = std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).is_ok();
    uid_ok && gid_ok && (setgroups || true)
}

fn do_pivot_root(root: &Path) -> bool {
    let Ok(c_root) = CString::new(root.as_os_str().to_string_lossy().as_bytes()) else {
        return false;
    };
    // A bind mount makes `root` its own mount point, which pivot_root requires.
    // SAFETY: pointers are valid; MS_BIND needs no data argument.
    unsafe {
        if libc::mount(
            c_root.as_ptr(),
            c_root.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        ) != 0
        {
            return false;
        }
    }
    let old = root.join(".usersu-oldroot");
    if std::fs::create_dir_all(&old).is_err() {
        return false;
    }
    let Ok(c_old) = CString::new(old.as_os_str().to_string_lossy().as_bytes()) else {
        return false;
    };
    let dot = c"/";
    // SAFETY: `c_root` and `c_old` are valid paths inside the new mount ns.
    unsafe {
        if libc::chdir(c_root.as_ptr()) != 0 {
            return false;
        }
        if libc::syscall(libc::SYS_pivot_root, c_root.as_ptr(), c_old.as_ptr()) != 0 {
            return false;
        }
        libc::chdir(dot.as_ptr());
        libc::umount2(c_old.as_ptr(), libc::MNT_DETACH);
    }
    let _ = std::fs::remove_dir(&old);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(root: bool, uml: bool, userns: bool) -> Capabilities {
        Capabilities {
            root,
            uml_kernel: uml.then(|| PathBuf::from("/vmlinux")),
            user_namespaces: userns,
        }
    }

    #[test]
    fn auto_prefers_um_then_pivot_then_proot() {
        assert_eq!(
            select(SandboxBackend::Auto, &caps(true, true, false)),
            Backend::Um
        );
        assert_eq!(
            select(SandboxBackend::Auto, &caps(true, false, false)),
            Backend::PivotRoot
        );
        assert_eq!(
            select(SandboxBackend::Auto, &caps(false, false, false)),
            Backend::Proot
        );
    }

    #[test]
    fn explicit_preference_is_honoured_and_downgraded_honestly() {
        assert_eq!(
            select(SandboxBackend::Um, &caps(false, false, false)),
            Backend::Um
        );
        assert_eq!(
            select(SandboxBackend::Chroot, &caps(true, false, false)),
            Backend::Chroot
        );
        assert_eq!(
            select(SandboxBackend::Chroot, &caps(false, false, true)),
            Backend::Proot
        );
        assert_eq!(
            select(SandboxBackend::PivotRoot, &caps(false, false, true)),
            Backend::PivotRoot
        );
        assert_eq!(
            select(SandboxBackend::Proot, &caps(true, true, true)),
            Backend::Proot
        );
    }

    #[test]
    fn um_plan_uses_hostfs_root() {
        let plan = SandboxPlan::new(
            Backend::Um,
            "/userfs",
            "/system/bin/usud-init",
            vec!["/system/bin/usud-init".into(), "--boot".into()],
            vec![],
        )
        .with_uml("/system/bin/linux-um".into(), 1024);
        let argv = plan.host_argv().unwrap();
        assert_eq!(argv[0], "/system/bin/linux-um");
        assert!(argv.contains(&"rootfstype=hostfs".to_string()));
        assert!(argv.contains(&"rootflags=/userfs".to_string()));
        assert!(argv.contains(&"mem=1024M".to_string()));
        assert!(argv.contains(&"init=/system/bin/usud-init".to_string()));
        assert!(argv.contains(&"--boot".to_string()));
    }

    #[test]
    fn um_without_kernel_is_an_error() {
        let plan = SandboxPlan::new(Backend::Um, "/userfs", "/init", vec![], vec![]);
        assert!(plan.host_argv().is_err());
    }

    #[test]
    fn chroot_plan_execs_the_guest_program() {
        let plan = SandboxPlan::new(
            Backend::Chroot,
            "/userfs",
            "/system/bin/usud-init",
            vec!["/system/bin/usud-init".into(), "-v".into()],
            vec![("PATH".into(), "/system/bin".into())],
        );
        let argv = plan.host_argv().unwrap();
        assert_eq!(argv[0], "/system/bin/usud-init");
        assert_eq!(argv[1], "-v");
        assert_eq!(
            plan.host_program(),
            PathBuf::from("/userfs/system/bin/usud-init")
        );
    }

    #[test]
    fn proot_plan_has_no_pseudo_mounts() {
        let plan = SandboxPlan::new(Backend::Proot, "/userfs", "/bin/sh", vec![], vec![]);
        assert!(plan.mounts.is_empty());
    }

    #[test]
    fn default_mounts_cover_the_init_essentials() {
        let mounts = default_pseudo_mounts();
        let targets: Vec<&str> = mounts.iter().map(|m| m.target.as_str()).collect();
        for expected in ["/proc", "/sys", "/dev/pts", "/tmp"] {
            assert!(targets.contains(&expected), "missing {expected}");
        }
    }
}
