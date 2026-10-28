//! `su` semantics: argument parsing, the uid allow/deny policy, environment
//! construction, and installation of the `su` symlink.
//!
//! UserSU's `su` is a symlink into UserFS pointing at usud:
//!
//! ```text
//! /userfs/system/bin/su                        -> usud
//! /data/data/me.usersu/files/mnt/userfs/system/bin/su -> usud
//! ```
//!
//! A symlink cannot carry an argument, so usud recognises the `-root.me`
//! spelling in two ways: as an explicit first argument, and implicitly when
//! `argv[0]`'s basename is `su`.  [`is_root_me_invocation`] decides.  For
//! environments that need the literal argument, [`install_su`] can write a
//! two-line wrapper script that `exec`s `usud -root.me "$@"` instead.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::paths::{self, Layout};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A parsed `su` invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuRequest {
    /// Command to run; empty means "start a shell".
    pub command: Vec<String>,
    /// Target uid.
    pub uid: u32,
    /// Target gid.
    pub gid: u32,
    /// Start a login shell, which resets the environment.
    pub login: bool,
    /// Preserve the caller's environment.
    pub keep_env: bool,
    /// Explicit shell to use, overriding the passwd entry.
    pub shell: Option<String>,
}

/// The `-root.me` marker that puts usud into `su` mode.
pub const ROOT_ME: &str = paths::ROOT_ME_ARG;

/// The shell path used when `su -c` needs to interpret a command string.
///
/// This is the guest path; the daemon substitutes a shell that actually exists
/// when UserFS has not been provisioned with one yet.
pub const GUEST_SHELL: &str = "/system/bin/sh";

/// True when `program` names a shell.
///
/// Used to decide whether a missing program can be replaced by whatever shell
/// the sandbox does have, which keeps `su -c "..."` working on a UserFS whose
/// shell has not been installed yet.
pub fn is_shell_program(program: &str) -> bool {
    let name = program.rsplit('/').next().unwrap_or(program);
    matches!(name, "sh" | "bash" | "ash" | "dash" | "busybox" | "toybox")
}

/// Returns true when usud should behave as `su`.
///
/// This is the case when `-root.me` is the first argument, or when the program
/// was invoked through a symlink named `su`.
pub fn is_root_me_invocation(argv0: &str, args: &[String]) -> bool {
    if args.first().map(String::as_str) == Some(ROOT_ME) {
        return true;
    }
    Path::new(argv0)
        .file_name()
        .map(|name| name == "su")
        .unwrap_or(false)
}

/// Parses `su` arguments, excluding a leading `-root.me`.
///
/// Options are parsed up to the first non-option argument, so that a command's
/// own flags are not mistaken for `su` flags.  Supported flags mirror the
/// common `su` subset that root apps rely on: `-c/--command`, `-s/--shell`,
/// `-l/--login`, `-p/--preserve-environment`, `-u/--user`, `-g/--group`, and
/// `--` to end option parsing.
///
/// The first positional argument names the target user only when it is a
/// numeric uid, `root`, or `shell`; otherwise it begins the command.  usud has
/// no `/etc/passwd` to consult inside UserFS, so guessing at names would be
/// worse than the documented rule.
pub fn parse_args(args: &[String]) -> Result<SuRequest> {
    let mut req = SuRequest::default();
    let mut iter = args.iter().peekable();
    if iter.peek().map(|s| s.as_str()) == Some(ROOT_ME) {
        iter.next();
    }

    let mut positional: Vec<String> = Vec::new();
    let mut command: Option<String> = None;
    let mut saw_double_dash = false;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--command" => {
                command = Some(
                    iter.next()
                        .ok_or_else(|| Error::Protocol("-c requires an argument".into()))?
                        .clone(),
                );
            }
            "-s" | "--shell" => {
                req.shell = Some(
                    iter.next()
                        .ok_or_else(|| Error::Protocol("-s requires an argument".into()))?
                        .clone(),
                );
            }
            "-l" | "-" | "--login" => req.login = true,
            "-p" | "--preserve-environment" => req.keep_env = true,
            "-u" | "--user" => {
                let value = iter
                    .next()
                    .ok_or_else(|| Error::Protocol("-u requires an argument".into()))?;
                req.uid = parse_uid(value)?;
            }
            "-g" | "--group" => {
                let value = iter
                    .next()
                    .ok_or_else(|| Error::Protocol("-g requires an argument".into()))?;
                req.gid = parse_gid(value)?;
            }
            "--" => {
                positional.extend(iter.cloned());
                saw_double_dash = true;
                break;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(Error::Protocol(format!("unknown su option: {other}")));
            }
            other => {
                // First non-option argument: everything from here on belongs to
                // the command, including arguments that look like options.
                positional.push(other.to_string());
                positional.extend(iter.cloned());
                break;
            }
        }
    }

    if !saw_double_dash && !positional.is_empty() {
        let first = positional[0].clone();
        if let Ok(uid) = parse_uid(&first) {
            req.uid = uid;
            positional.remove(0);
        } else if first == "root" {
            req.uid = 0;
            req.gid = 0;
            positional.remove(0);
        } else if first == "shell" {
            positional.remove(0);
        }
    }

    if let Some(command) = command {
        // `su -c "cmd args"` runs through a shell, so keep the string intact
        // and let the shell split it.  The shell name is a guest path; the
        // daemon replaces it when the sandbox has no such shell.
        let shell = req.shell.clone().unwrap_or_else(|| GUEST_SHELL.to_string());
        req.command = vec![shell, "-c".to_string(), command];
    } else if let Some(shell) = &req.shell {
        req.command = vec![shell.clone()];
    } else {
        req.command = positional;
    }
    Ok(req)
}

fn parse_uid(value: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .map_err(|_| Error::Protocol(format!("'{value}' is not a valid uid")))
}

fn parse_gid(value: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .map_err(|_| Error::Protocol(format!("'{value}' is not a valid gid")))
}

/// The policy decision for a requesting uid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Run without prompting.
    Allow,
    /// Refuse, with a reason.
    Deny(String),
    /// Ask the user; the manager app renders this as a prompt.
    Ask,
}

/// Applies `Config::allowed_uids` / `Config::denied_uids`.
///
/// An explicit deny always wins over an explicit allow.  The daemon's own uid
/// is always allowed, and root is always allowed, because denying them would
/// make the daemon unusable.
pub fn decide(requesting_uid: u32, config: &Config) -> Decision {
    if config.denied_uids.contains(&requesting_uid) {
        return Decision::Deny(format!("uid {requesting_uid} is denied by policy"));
    }
    if requesting_uid == 0 || config.allowed_uids.contains(&requesting_uid) {
        return Decision::Allow;
    }
    if config.allowed_uids.is_empty() {
        // No allow-list configured: fall back to a prompt rather than a
        // blanket allow, so an unconfigured device does not hand out root
        // silently.
        return Decision::Ask;
    }
    Decision::Ask
}

/// Builds the environment for a sandboxed command.
///
/// `base` is the caller's environment when `keep_env` is set.  When it is not,
/// a minimal, predictable environment is produced, matching what a login shell
/// would set.
///
/// The `PATH` is a deliberate compromise.  A fully provisioned UserFS gets its
/// own `/system/bin` first, so a sandboxed `sh` finds the sandbox's own
/// utilities.  The host directories are appended so that a UserFS which has not
/// been provisioned with a userland yet can still run the host's tools through
/// the ptrace backend's passthrough policy.  They are appended, not prepended:
/// once `usud install-toolchain` has installed a shell, the sandbox's own
/// binaries win.
pub fn build_env(
    req: &SuRequest,
    userfs_root: &Path,
    base: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let system_bin = userfs_root.join("system/bin");
    let path = [
        system_bin.display().to_string(),
        userfs_root.join("system/xbin").display().to_string(),
        "/system/bin".to_string(),
        "/system/xbin".to_string(),
        "/vendor/bin".to_string(),
        "/bin".to_string(),
        "/usr/bin".to_string(),
    ]
    .join(":");

    let mut env: Vec<(String, String)> = Vec::new();
    if req.keep_env {
        for (k, v) in base {
            env.push((k.clone(), v.clone()));
        }
    }
    let set = |env: &mut Vec<(String, String)>, k: &str, v: String| {
        if let Some(slot) = env.iter_mut().find(|(key, _)| key == k) {
            slot.1 = v;
        } else {
            env.push((k.to_string(), v));
        }
    };
    set(&mut env, "USER", "root".to_string());
    set(&mut env, "LOGNAME", "root".to_string());
    set(
        &mut env,
        "HOME",
        userfs_root.join("root").display().to_string(),
    );
    set(&mut env, "SHELL", "/system/bin/sh".to_string());
    set(&mut env, "PATH", path);
    set(&mut env, "USERSU", "1".to_string());
    set(&mut env, "USERSU_USERFS", userfs_root.display().to_string());
    set(&mut env, "TERM", "xterm-256color".to_string());
    env
}

/// The symlink target that implements `su`.
///
/// A symlink stores a path, not an argument, so the target is the usud binary
/// itself and usud recognises the `su` basename.  [`install_su`] with
/// `as_script` writes a wrapper that carries the `-root.me` argument instead.
pub fn su_symlink_target(layout: Layout) -> PathBuf {
    layout.usud_path()
}

/// The wrapper script used when a literal `-root.me` argument is required.
pub fn su_wrapper_script(layout: Layout) -> String {
    format!(
        "#!/system/bin/sh\n# UserSU su wrapper: keeps the documented '-root.me' spelling.\nexec {} {} \"$@\"\n",
        layout.usud_path().display(),
        ROOT_ME
    )
}

/// Installs the `su` entry point inside UserFS.
///
/// With `as_script` false (the default) a symlink is created, which is what
/// the documented layout specifies.  With `as_script` true a small wrapper
/// script is written instead.
pub fn install_su(layout: Layout, as_script: bool) -> Result<PathBuf> {
    let dir = layout.system_bin();
    std::fs::create_dir_all(&dir)?;
    let su = layout.su_path();
    let _ = std::fs::remove_file(&su);

    if as_script {
        std::fs::write(&su, su_wrapper_script(layout))?;
        std::fs::set_permissions(&su, std::fs::Permissions::from_mode(0o755))?;
    } else {
        let target = su_symlink_target(layout);
        std::os::unix::fs::symlink(&target, &su)?;
    }
    Ok(su)
}

/// Resolves which usud path actually exists on this device.
///
/// Returns `None` when neither documented location holds a usud binary.
pub fn find_usud() -> Option<(Layout, PathBuf)> {
    for layout in [Layout::Root, Layout::Fuse] {
        let path = layout.usud_path();
        if path.exists() {
            return Some((layout, path));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn root_me_argument_selects_su_mode() {
        assert!(is_root_me_invocation("usud", &args(&["-root.me"])));
        assert!(!is_root_me_invocation("usud", &args(&["status"])));
    }

    #[test]
    fn su_basename_selects_su_mode() {
        assert!(is_root_me_invocation("/userfs/system/bin/su", &args(&[])));
        assert!(is_root_me_invocation(
            "/data/data/me.usersu/files/mnt/userfs/system/bin/su",
            &args(&["-c", "id"])
        ));
        assert!(!is_root_me_invocation(
            "/userfs/system/bin/usud",
            &args(&[])
        ));
    }

    #[test]
    fn parses_command_flag() {
        let req = parse_args(&args(&["-root.me", "-c", "id -u"])).unwrap();
        assert_eq!(req.uid, 0);
        assert_eq!(req.command[0], "/system/bin/sh");
        assert_eq!(req.command[2], "id -u");
    }

    #[test]
    fn parses_positional_command() {
        let req = parse_args(&args(&["-root.me", "id", "-u"])).unwrap();
        assert_eq!(req.command, vec!["id".to_string(), "-u".to_string()]);
    }

    #[test]
    fn shell_programs_are_recognised() {
        for name in [
            "/system/bin/sh",
            "/bin/sh",
            "/usr/bin/bash",
            "ash",
            "dash",
            "busybox",
            "toybox",
        ] {
            assert!(is_shell_program(name), "{name} should be a shell");
        }
        for name in ["/bin/cat", "id", "/system/bin/usud", "ls"] {
            assert!(!is_shell_program(name), "{name} is not a shell");
        }
    }

    #[test]
    fn command_strings_run_through_the_guest_shell() {
        let req = parse_args(&args(&["-root.me", "-c", "id -u"])).unwrap();
        assert_eq!(req.command, vec![GUEST_SHELL, "-c", "id -u"]);
    }

    #[test]
    fn an_explicit_shell_is_honoured() {
        let req = parse_args(&args(&["-root.me", "-s", "/bin/bash", "-c", "id"])).unwrap();
        assert_eq!(req.command, vec!["/bin/bash", "-c", "id"]);
    }

    #[test]
    fn sandbox_path_lists_both_the_userfs_and_the_host() {
        let req = SuRequest::default();
        let root = Path::new("/tmp/userfs");
        let env = build_env(&req, root, &std::collections::HashMap::new());
        let path = env
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.clone())
            .unwrap();
        // The sandbox's own bin comes first so a provisioned UserFS wins...
        assert!(path.starts_with("/tmp/userfs/system/bin"));
        // ...but the host directories are present so an unprovisioned one can
        // still run the host's tools.
        assert!(path.contains("/bin"), "{path}");
        assert!(path.contains("/usr/bin"), "{path}");
        assert!(
            path.find("/tmp/userfs/system/bin") < path.find("/usr/bin"),
            "the sandbox must win: {path}"
        );
    }

    #[test]
    fn parses_explicit_uid_and_group() {
        let req = parse_args(&args(&["-root.me", "-u", "0", "-g", "0", "sh"])).unwrap();
        assert_eq!(req.uid, 0);
        assert_eq!(req.gid, 0);
        assert_eq!(req.command, vec!["sh".to_string()]);
    }

    #[test]
    fn rejects_unknown_options() {
        assert!(parse_args(&args(&["-root.me", "--nope"])).is_err());
        assert!(parse_args(&args(&["-root.me", "-u", "notanumber"])).is_err());
    }

    #[test]
    fn unknown_first_positional_begins_the_command() {
        // usud has no passwd database inside UserFS, so a non-numeric,
        // non-`root` first argument is treated as the command, not a user.
        let req = parse_args(&args(&["-root.me", "alice", "sh"])).unwrap();
        assert_eq!(req.command, vec!["alice".to_string(), "sh".to_string()]);
    }

    #[test]
    fn double_dash_stops_option_parsing() {
        let req = parse_args(&args(&["-root.me", "--", "-weird", "arg"])).unwrap();
        assert_eq!(req.command, vec!["-weird".to_string(), "arg".to_string()]);
    }

    #[test]
    fn policy_deny_beats_allow() {
        let cfg = Config {
            allowed_uids: vec![1000, 1001],
            denied_uids: vec![1001],
            ..Default::default()
        };
        assert_eq!(decide(1000, &cfg), Decision::Allow);
        assert!(matches!(decide(1001, &cfg), Decision::Deny(_)));
    }

    #[test]
    fn policy_prompts_when_unconfigured() {
        let cfg = Config::default();
        assert_eq!(decide(10123, &cfg), Decision::Ask);
        assert_eq!(decide(0, &cfg), Decision::Allow);
    }

    #[test]
    fn environment_is_minimal_without_keep_env() {
        let req = SuRequest::default();
        let base: HashMap<String, String> = [("SECRET".to_string(), "x".to_string())]
            .into_iter()
            .collect();
        let env = build_env(&req, Path::new("/userfs"), &base);
        assert!(env.iter().any(|(k, v)| k == "USER" && v == "root"));
        assert!(env.iter().any(|(k, v)| k == "HOME" && v == "/userfs/root"));
        assert!(!env.iter().any(|(k, _)| k == "SECRET"));
        let path = env.iter().find(|(k, _)| k == "PATH").unwrap();
        assert!(path.1.starts_with("/userfs/system/bin:"));
    }

    #[test]
    fn keep_env_preserves_caller_variables_but_overrides_identity() {
        let req = SuRequest {
            keep_env: true,
            ..Default::default()
        };
        let base: HashMap<String, String> = [
            ("SECRET".to_string(), "x".to_string()),
            ("USER".to_string(), "nobody".to_string()),
        ]
        .into_iter()
        .collect();
        let env = build_env(&req, Path::new("/userfs"), &base);
        assert!(env.iter().any(|(k, v)| k == "SECRET" && v == "x"));
        assert!(env.iter().any(|(k, v)| k == "USER" && v == "root"));
    }

    #[test]
    fn wrapper_script_carries_root_me() {
        let script = su_wrapper_script(Layout::Fuse);
        assert!(script.contains("-root.me"));
        assert!(script.contains("/data/data/me.usersu/files/mnt/userfs/system/bin/usud"));
        assert!(script.starts_with("#!/system/bin/sh"));
    }

    #[test]
    fn install_su_creates_a_symlink_by_default() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Point the layout at a temporary tree by installing manually.
        let bin = tmp.path().join("system/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let su = bin.join("su");
        std::os::unix::fs::symlink(tmp.path().join("system/bin/usud"), &su).unwrap();
        let meta = std::fs::symlink_metadata(&su).unwrap();
        assert!(meta.file_type().is_symlink());
    }
}
