//! Executing commands and init systems inside a UserFS sandbox.
//!
//! This module is the bridge between the policy decisions made in [`crate::ipc`]
//! and the backends in [`usersu_core::sandbox`].  It decides *how* to run
//! something (which backend, which identity, which environment) and then hands
//! off to the backend that actually performs the work.

use crate::ipc::Shared;
use crate::userfs;
use std::path::{Path, PathBuf};
use usersu_core::config::{Config, PrivilegeMode, SandboxBackend};
use usersu_core::error::{Error, Result};
use usersu_core::paths::Layout;
use usersu_core::privilege::{self, acquire_first, DirtyPipe, Outcome, Provider, SuDelegation};
use usersu_core::protocol::ProviderReport;
use usersu_core::sandbox::{self, Backend, Capabilities, Sandbox, SandboxPlan};
use usersu_core::su::{self, SuRequest};

/// Where the user-mode Linux kernel image is looked up, in order.
const UML_KERNEL_CANDIDATES: [&str; 3] = [
    "/userfs/system/bin/linux-um",
    "/data/data/me.usersu/files/mnt/userfs/system/bin/linux-um",
    "/system/bin/linux-um",
];

/// Finds a user-mode Linux kernel image, if one is installed.
pub fn find_uml_kernel() -> Option<PathBuf> {
    UML_KERNEL_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// Gathers capabilities and selects a backend for `preference`.
pub fn select_backend(preference: SandboxBackend) -> (Backend, Capabilities) {
    let caps = sandbox::probe(find_uml_kernel());
    (sandbox::select(preference, &caps), caps)
}

/// Builds the privilege providers named by `config`.
pub fn providers(config: &Config) -> Vec<Box<dyn Provider>> {
    let mut providers: Vec<Box<dyn Provider>> = Vec::new();
    for name in &config.privilege_order {
        match name.as_str() {
            "magisk" => providers.push(Box::new(SuDelegation::new("magisk", "/system/bin/su"))),
            "kernelsu" => {
                providers.push(Box::new(SuDelegation::new("kernelsu", "/system/bin/ksud")))
            }
            "apatch" => providers.push(Box::new(SuDelegation::new("apatch", "/data/adb/apd"))),
            "vendor-su" => {
                providers.push(Box::new(SuDelegation::new("vendor-su", "/vendor/bin/su")))
            }
            "kernel-exploit" => providers.push(Box::new(DirtyPipe)),
            // "existing-root" is handled by `has_root` and needs no provider.
            _ => {}
        }
    }
    providers
}

/// Produces the provider report shown by `usud providers` and the manager app.
pub fn provider_report(config: &Config) -> Vec<ProviderReport> {
    let mut report = Vec::new();
    if privilege::has_root() {
        report.push(ProviderReport {
            name: "existing-root".to_string(),
            kind: "root-solution".to_string(),
            available: true,
            reason: None,
        });
    }
    for provider in providers(config) {
        let available = provider.available();
        report.push(ProviderReport {
            name: provider.name().to_string(),
            kind: provider.kind().to_string(),
            available,
            reason: if available {
                None
            } else {
                Some(format!(
                    "{} is not usable on this device or kernel",
                    provider.name()
                ))
            },
        });
    }
    report
}

/// Attempts privilege acquisition, honouring [`PrivilegeMode`].
///
/// Returns the winning provider name, if any.  The per-provider log is written
/// to the debug log so a failure can be diagnosed without guessing.
pub fn acquire(config: &Config) -> Option<String> {
    match config.privilege_mode {
        PrivilegeMode::None => None,
        PrivilegeMode::KernelExploit => {
            let providers: Vec<Box<dyn Provider>> = vec![Box::new(DirtyPipe)];
            let (winner, log) = acquire_first(&providers);
            log_outcomes(&log);
            winner
        }
        PrivilegeMode::RootSolution => {
            let providers: Vec<Box<dyn Provider>> = providers(config)
                .into_iter()
                .filter(|p| p.kind() == usersu_core::privilege::ProviderKind::RootSolution)
                .collect();
            let (winner, log) = acquire_first(&providers);
            log_outcomes(&log);
            winner
        }
        PrivilegeMode::Auto => {
            if privilege::has_root() {
                return Some("existing-root".to_string());
            }
            let (winner, log) = acquire_first(&providers(config));
            log_outcomes(&log);
            winner
        }
    }
}

fn log_outcomes(log: &[(String, Outcome)]) {
    for (name, outcome) in log {
        match outcome {
            Outcome::Acquired { euid } => log::info!("{name}: acquired root (euid {euid})"),
            Outcome::AlreadyRoot => log::info!("{name}: already root"),
            Outcome::Unavailable { reason } => log::info!("{name}: unavailable ({reason})"),
            Outcome::Failed { reason } => log::warn!("{name}: failed ({reason})"),
        }
    }
}

/// Finds a usable shell for a sandbox with no command given.
///
/// The sandbox's own shell is preferred, then the host's.  This matters on a
/// freshly provisioned UserFS: `/system/bin/sh` only exists after
/// `usud install-toolchain` has run, and until then falling back to the host
/// shell keeps `su` usable instead of failing with a missing-file error.
pub fn resolve_shell(root: &Path) -> Result<PathBuf> {
    const CANDIDATES: [&str; 4] = [
        "/system/bin/sh",
        "/bin/sh",
        "/usr/bin/sh",
        "/system/bin/busybox",
    ];
    for candidate in CANDIDATES {
        let in_sandbox = root.join(candidate.trim_start_matches('/'));
        if in_sandbox.is_file() {
            return Ok(PathBuf::from(candidate));
        }
        if Path::new(candidate).is_file() {
            return Ok(PathBuf::from(candidate));
        }
    }
    if let Ok(shell) = std::env::var("SHELL") {
        if Path::new(&shell).is_file() {
            return Ok(PathBuf::from(shell));
        }
    }
    Err(Error::Sandbox(
        "no shell found; run 'usud install-toolchain' to provision one, \
         or pass an explicit command"
            .into(),
    ))
}

/// Runs a command as `su` requested.
///
/// The command is executed through the selected sandbox backend so that it sees
/// the UserFS tree as `/`.  When the daemon has real root the strongest backend
/// is used; otherwise the ptrace backend presents the fake identity.
pub fn run_su(
    shared: &Shared,
    command: &[String],
    target_uid: u32,
    target_gid: u32,
    keep_env: bool,
    stdio: Option<[libc::c_int; 3]>,
) -> Result<Option<i32>> {
    let config = shared.config.lock().unwrap().clone();
    let layout = if shared.root {
        Layout::Root
    } else {
        Layout::Fuse
    };
    let root = userfs::sandbox_root(layout, &config);

    let request = SuRequest {
        command: command.to_vec(),
        uid: target_uid,
        gid: target_gid,
        login: false,
        keep_env,
        shell: None,
    };

    let base: std::collections::HashMap<String, String> = std::env::vars().collect();
    let env = su::build_env(&request, &root, &base);

    // A shell when no command was given, and a real shell substituted for a
    // guest shell path that the sandbox does not have yet.
    let mut command = if request.command.is_empty() {
        vec![resolve_shell(&root)?.to_string_lossy().to_string()]
    } else {
        request.command.clone()
    };
    let program_exists = if command[0].starts_with('/') {
        root.join(command[0].trim_start_matches('/')).is_file() || Path::new(&command[0]).is_file()
    } else {
        true
    };
    if !program_exists && su::is_shell_program(&command[0]) {
        let replacement = resolve_shell(&root)?.to_string_lossy().to_string();
        log::debug!("replacing missing shell {} with {replacement}", command[0]);
        command[0] = replacement;
    }

    let (backend, caps) = select_backend(config.sandbox_backend);
    let program = command[0].clone();
    let mut plan =
        SandboxPlan::new(backend, &root, program.clone(), command, env).with_stdio(stdio);
    if let Some(kernel) = caps.uml_kernel {
        plan = plan.with_uml(kernel, 512);
    }
    if !shared.root {
        // Without root there is no way to change credentials, so present the
        // requested identity through the ptrace backend.
        plan = plan.with_identity(Some(usersu_core::proot::Identity {
            uid: target_uid,
            gid: target_gid,
        }));
    } else {
        plan = plan.with_identity(None);
    }

    log::info!(
        "running {program} via the {} backend (uid {target_uid}, gid {target_gid})",
        backend.as_str()
    );
    Sandbox::new(plan).run()
}

/// Boots an init system in a sandbox.
pub fn boot_init(
    shared: &Shared,
    config: &Config,
    init_override: Option<String>,
    args: Vec<String>,
) -> Result<Option<i32>> {
    let layout = Layout::Root;
    let root = layout.userfs_root();
    let init = init_override.unwrap_or_else(|| config.init_command.clone());
    if init.is_empty() {
        return Err(Error::Sandbox("no init command configured".into()));
    }
    let host_init = root.join(init.trim_start_matches('/'));
    if !host_init.exists() {
        return Err(Error::Sandbox(format!(
            "init program {} does not exist inside UserFS",
            init
        )));
    }

    let (backend, caps) = select_backend(config.sandbox_backend);
    let mut argv = vec![init.clone()];
    argv.extend(config.init_args.iter().cloned());
    argv.extend(args);

    let env = vec![
        ("PATH".to_string(), "/system/bin:/system/xbin".to_string()),
        ("HOME".to_string(), "/root".to_string()),
        ("TERM".to_string(), "linux".to_string()),
        ("USERSU".to_string(), "1".to_string()),
    ];
    let mut plan = SandboxPlan::new(backend, &root, init, argv, env);
    if let Some(kernel) = caps.uml_kernel {
        plan = plan.with_uml(kernel, 1024);
    }

    log::info!(
        "booting init {host_init:?} via the {} backend",
        backend.as_str()
    );
    let result = Sandbox::new(plan).run();
    // A pivot_root leaves a mount point behind; clean it up best-effort.
    if matches!(backend, Backend::PivotRoot) {
        let _ = userfs::clean_pivot_artifacts(&root);
    }
    let _ = shared;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_shell_prefers_a_shell_inside_the_sandbox() {
        let root = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(root.path().join("system/bin")).unwrap();
        std::fs::write(root.path().join("system/bin/sh"), b"#!/bin/sh\n").unwrap();
        let shell = resolve_shell(root.path()).unwrap();
        assert_eq!(shell, PathBuf::from("/system/bin/sh"));
    }

    #[test]
    fn resolve_shell_falls_back_to_a_host_shell() {
        // A freshly provisioned UserFS has no shell yet; `su` must still work,
        // so the host's shell is used through the passthrough policy.
        let root = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(root.path().join("system/bin")).unwrap();
        let shell = resolve_shell(root.path()).unwrap();
        assert!(
            shell.exists(),
            "the resolved shell must exist somewhere: {shell:?}"
        );
    }

    #[test]
    fn provider_report_always_lists_configured_providers() {
        let config = Config::default();
        let report = provider_report(&config);
        let names: Vec<&str> = report.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"magisk"));
        assert!(names.contains(&"kernelsu"));
        assert!(names.contains(&"kernel-exploit"));
    }

    #[test]
    fn providers_are_built_in_configured_order() {
        let config = Config {
            privilege_order: vec!["kernelsu".into(), "magisk".into()],
            ..Default::default()
        };
        let names: Vec<&str> = providers(&config).iter().map(|p| p.name()).collect();
        assert_eq!(names, vec!["kernelsu", "magisk"]);
    }

    #[test]
    fn privilege_mode_none_never_escalates() {
        let config = Config {
            privilege_mode: PrivilegeMode::None,
            ..Default::default()
        };
        assert!(acquire(&config).is_none());
    }

    #[test]
    fn select_backend_reports_capabilities_consistently() {
        let (backend, caps) = select_backend(SandboxBackend::Auto);
        if caps.root {
            assert_ne!(backend, Backend::Proot);
        } else if caps.uml_kernel.is_none() {
            assert_eq!(backend, Backend::Proot);
        }
    }
}
