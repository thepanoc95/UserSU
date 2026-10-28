//! End-to-end tests for the unprivileged sandbox path.
//!
//! These exercise the real ptrace backend on the real host: a process is
//! started inside a temporary UserFS root and its view of the filesystem and
//! identity is observed through files it writes.  Nothing here needs root, and
//! nothing is mocked.
//!
//! Two properties of the backend shape how these tests are written:
//!
//! * the tracer reaps with `waitpid(-1)`, so two sandboxes must not run at the
//!   same time or one test would reap the other's children.  [`serial`] guards
//!   every test with a process-wide mutex.
//! * the sandboxed process inherits the launcher's stdout, so assertions read
//!   files that the sandboxed process wrote instead of captured output.  That
//!   also avoids redirecting process-global descriptors, which would corrupt
//!   any test running in parallel.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;
use usersu_core::proot::{Identity, PassthroughPolicy};
use usersu_core::sandbox::{Backend, Sandbox, SandboxPlan};

/// Serializes the sandbox tests.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// True when the ptrace backend can run on this host.
fn ptrace_usable() -> bool {
    std::fs::metadata("/proc/self/mem").is_ok()
}

fn write_script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Builds a plan that runs `script` with a usable PATH.
fn plan_for(root: &Path, script: &Path) -> SandboxPlan {
    SandboxPlan::new(
        Backend::Proot,
        root,
        script.to_string_lossy().to_string(),
        vec![script.to_string_lossy().to_string()],
        vec![
            ("PATH".to_string(), "/system/bin:/bin:/usr/bin".to_string()),
            ("HOME".to_string(), "/root".to_string()),
        ],
    )
}

#[test]
fn proot_runs_a_host_binary_inside_the_sandbox() {
    let _guard = serial();
    if !ptrace_usable() {
        eprintln!("skipping: ptrace is not usable on this host");
        return;
    }
    let root = TempDir::new().unwrap();
    let bin = root.path().join("system/bin");
    std::fs::create_dir_all(&bin).unwrap();

    let plan = SandboxPlan::new(
        Backend::Proot,
        root.path(),
        "/bin/echo",
        vec!["/bin/echo".to_string(), "hello".to_string()],
        vec![("PATH".to_string(), "/system/bin:/bin".to_string())],
    );
    let code = Sandbox::new(plan)
        .run()
        .expect("the sandbox should start")
        .expect("echo should exit with a status");
    assert_eq!(code, 0);
}

#[test]
fn proot_lets_a_script_read_a_file_from_the_sandbox_root() {
    let _guard = serial();
    if !ptrace_usable() {
        eprintln!("skipping: ptrace is not usable on this host");
        return;
    }
    let root = TempDir::new().unwrap();
    let bin = root.path().join("system/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("greeting"), b"sandbox-file-contents\n").unwrap();

    // The script reads a path that exists only inside the sandbox and writes
    // what it read back into the sandbox, where the test can inspect it.
    let script = write_script(
        &bin,
        "read-greeting",
        "#!/bin/sh\ncat /system/bin/greeting > /system/bin/observed\n",
    );

    let code = Sandbox::new(plan_for(root.path(), &script))
        .run()
        .expect("the sandbox should start")
        .expect("the script should exit with a status");
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read(bin.join("observed")).unwrap(),
        b"sandbox-file-contents\n",
        "the sandboxed process should have read the sandbox's own file"
    );
}

#[test]
fn proot_reports_the_requested_identity() {
    let _guard = serial();
    if !ptrace_usable() {
        eprintln!("skipping: ptrace is not usable on this host");
        return;
    }
    let root = TempDir::new().unwrap();
    let bin = root.path().join("system/bin");
    std::fs::create_dir_all(&bin).unwrap();

    let script = write_script(&bin, "whoami", "#!/bin/sh\nid -u > /system/bin/observed\n");
    let plan = plan_for(root.path(), &script).with_identity(Some(Identity::ROOT));

    let code = Sandbox::new(plan)
        .run()
        .expect("the sandbox should start")
        .expect("the script should exit with a status");
    assert_eq!(code, 0);
    let observed = std::fs::read_to_string(bin.join("observed")).unwrap();
    assert_eq!(observed.trim(), "0");
}

#[test]
fn proot_can_present_a_non_root_identity_too() {
    let _guard = serial();
    if !ptrace_usable() {
        eprintln!("skipping: ptrace is not usable on this host");
        return;
    }
    let root = TempDir::new().unwrap();
    let bin = root.path().join("system/bin");
    std::fs::create_dir_all(&bin).unwrap();

    let script = write_script(&bin, "whoami", "#!/bin/sh\nid -u > /system/bin/observed\n");
    let plan = plan_for(root.path(), &script).with_identity(Some(Identity {
        uid: 4242,
        gid: 4242,
    }));

    let code = Sandbox::new(plan)
        .run()
        .expect("the sandbox should start")
        .expect("the script should exit with a status");
    assert_eq!(code, 0);
    let observed = std::fs::read_to_string(bin.join("observed")).unwrap();
    assert_eq!(observed.trim(), "4242");
}

#[test]
fn proot_propagates_a_nonzero_exit_code() {
    let _guard = serial();
    if !ptrace_usable() {
        eprintln!("skipping: ptrace is not usable on this host");
        return;
    }
    let root = TempDir::new().unwrap();
    let bin = root.path().join("system/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = write_script(&bin, "fail", "#!/bin/sh\nexit 42\n");

    let code = Sandbox::new(plan_for(root.path(), &script))
        .run()
        .expect("the sandbox should start")
        .expect("the script should exit with a status");
    assert_eq!(code, 42);
}

#[test]
fn proot_refuses_a_root_that_does_not_exist() {
    let plan = SandboxPlan::new(
        Backend::Proot,
        "/definitely/not/a/real/userfs",
        "/bin/true",
        vec!["/bin/true".to_string()],
        vec![],
    );
    let error = Sandbox::new(plan)
        .run()
        .expect_err("a missing root must be refused");
    assert!(error.to_string().contains("does not exist"), "{error}");
}

#[test]
fn passthrough_policy_defaults_are_documented() {
    let policy = PassthroughPolicy::default();
    assert!(policy.passes_through("/dev/null"));
    assert!(policy.passes_through("/proc/self/status"));
    assert!(policy.passes_through("/sys/class"));
    assert!(!policy.passes_through("/system/bin/sh"));
    assert!(policy.host_fallback, "host binaries must load by default");
}
