//! `usud-init`: a minimal PID 1 for a UserFS sandbox.
//!
//! When usud boots an init system it uses this binary, which is what a
//! sandboxed kernel or `chroot` starts as process 1.  As PID 1 it has three
//! responsibilities that an ordinary process does not:
//!
//! * it reaps orphaned children, because nothing else will;
//! * it does not die on signals it has not installed a handler for, so
//!   `SIGTERM` must be handled explicitly to shut down;
//! * it must never exit while the system still has work, or the kernel panics.
//!
//! Services are described by a small, documented file rather than by a shell
//! script parser, so the behaviour is easy to reason about and test.

use nix::sys::signal::{self, SigAction, SigHandler, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

/// Default location of the service description inside UserFS.
const DEFAULT_INITTAB: &str = "/system/etc/usud/inittab";

/// Set by the signal handler when a shutdown has been requested.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// One service to supervise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// Service name, used in log messages.
    pub name: String,
    /// Program to execute.
    pub program: String,
    /// Arguments for the program.
    pub args: Vec<String>,
    /// Restart the service when it exits.
    pub respawn: bool,
    /// Run once and do not restart.
    pub once: bool,
}

/// Parses an inittab-style file.
///
/// The format is deliberately small:
///
/// ```text
/// # comment
/// name = /path/to/program arg1 arg2
/// respawn name = /path/to/program
/// once name = /path/to/program
/// ```
///
/// Blank lines and lines whose first non-space character is `#` are ignored.
/// A line without `=` is a parse error, which is reported rather than skipped:
/// a silently ignored service is worse than a failed boot.
pub fn parse_inittab(text: &str) -> Result<Vec<Service>, String> {
    let mut services = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (prefix, body) = match line.split_once('=') {
            Some((left, right)) => (left.trim(), right.trim()),
            None => {
                return Err(format!(
                    "line {}: expected 'name = program', found {line:?}",
                    index + 1
                ))
            }
        };
        let (flags, name) = match prefix.split_once(char::is_whitespace) {
            Some((flag, name)) => (Some(flag.trim()), name.trim()),
            None => (None, prefix),
        };
        if name.is_empty() {
            return Err(format!("line {}: service name is empty", index + 1));
        }
        let mut parts = body.split_whitespace();
        let program = match parts.next() {
            Some(program) => program.to_string(),
            None => return Err(format!("line {}: program is empty", index + 1)),
        };
        let (respawn, once) = match flags {
            None => (true, false),
            Some("respawn") => (true, false),
            Some("once") => (false, true),
            Some(other) => {
                return Err(format!(
                    "line {}: unknown flag {other:?}; expected respawn or once",
                    index + 1
                ))
            }
        };
        services.push(Service {
            name: name.to_string(),
            program,
            args: parts.map(String::from).collect(),
            respawn,
            once,
        });
    }
    Ok(services)
}

extern "C" fn on_shutdown_signal(_signal: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Installs the shutdown signal handlers.
///
/// As PID 1 the default action for these signals is not "terminate", so they
/// must be handled explicitly for `usud stop` and Ctrl-C on the console to work.
fn install_signal_handlers() -> Result<(), String> {
    let action = SigAction::new(
        SigHandler::Handler(on_shutdown_signal),
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );
    for sig in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGQUIT] {
        // SAFETY: the handler only sets an atomic flag, which is
        // async-signal-safe.
        unsafe { signal::sigaction(sig, &action) }.map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// A running service.
struct Running {
    child: Child,
    respawn: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let inittab = args
        .iter()
        .position(|a| a == "--inittab")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| DEFAULT_INITTAB.to_string());

    if std::env::var_os("USERSU_INIT_DEBUG").is_some() {
        eprintln!("usud-init: reading {inittab}");
    }

    let text = match std::fs::read_to_string(&inittab) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("usud-init: cannot read {inittab}: {e}");
            eprintln!("usud-init: starting a rescue shell instead");
            String::new()
        }
    };

    let services = match parse_inittab(&text) {
        Ok(services) => services,
        Err(e) => {
            eprintln!("usud-init: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = install_signal_handlers() {
        eprintln!("usud-init: cannot install signal handlers: {e}");
        std::process::exit(1);
    }

    if let Err(e) = run_services(services) {
        eprintln!("usud-init: {e}");
        std::process::exit(1);
    }
}

/// Starts every service and supervises the ones marked `respawn` until a
/// shutdown signal arrives.
fn run_services(services: Vec<Service>) -> Result<(), String> {
    let mut running: HashMap<Pid, Running> = HashMap::new();
    let mut name_of: HashMap<Pid, String> = HashMap::new();

    for service in &services {
        match spawn(service) {
            Ok(child) => {
                let pid = Pid::from_raw(child.id() as i32);
                if service.once {
                    // `once` services are fire-and-forget; they are still
                    // reaped through the wait loop below.
                    name_of.insert(pid, service.name.clone());
                    running.insert(
                        pid,
                        Running {
                            child,
                            respawn: false,
                        },
                    );
                } else {
                    name_of.insert(pid, service.name.clone());
                    running.insert(
                        pid,
                        Running {
                            child,
                            respawn: service.respawn,
                        },
                    );
                }
                println!("usud-init: started {} ({})", service.name, pid);
            }
            Err(e) => eprintln!("usud-init: failed to start {}: {e}", service.name),
        }
    }

    if running.is_empty() {
        // Nothing to supervise: fall back to a shell so the sandbox is usable
        // for debugging rather than exiting and panicking the kernel.
        println!("usud-init: no services defined; starting /system/bin/sh");
        let shell = Service {
            name: "rescue".to_string(),
            program: "/system/bin/sh".to_string(),
            args: vec!["-i".to_string()],
            respawn: false,
            once: true,
        };
        if let Ok(child) = spawn(&shell) {
            let pid = Pid::from_raw(child.id() as i32);
            name_of.insert(pid, shell.name.clone());
            running.insert(
                pid,
                Running {
                    child,
                    respawn: false,
                },
            );
        }
    }

    let services_by_name: HashMap<String, Service> = services
        .iter()
        .map(|s| (s.name.clone(), s.clone()))
        .collect();

    // Reap children forever; as PID 1 nothing else will.
    while !SHUTDOWN.load(Ordering::SeqCst) || !running.is_empty() {
        if SHUTDOWN.load(Ordering::SeqCst) {
            terminate_all(&mut running);
        }
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Ok(WaitStatus::Exited(pid, code)) => {
                let name = name_of.remove(&pid).unwrap_or_else(|| pid.to_string());
                let entry = running.remove(&pid);
                println!("usud-init: {name} exited with code {code}");
                if SHUTDOWN.load(Ordering::SeqCst) {
                    continue;
                }
                if let Some(entry) = entry {
                    if entry.respawn {
                        if let Some(service) = services_by_name.get(&name) {
                            match spawn(service) {
                                Ok(child) => {
                                    let new_pid = Pid::from_raw(child.id() as i32);
                                    name_of.insert(new_pid, name.clone());
                                    running.insert(
                                        new_pid,
                                        Running {
                                            child,
                                            respawn: true,
                                        },
                                    );
                                    println!("usud-init: respawned {name} ({new_pid})");
                                }
                                Err(e) => eprintln!("usud-init: respawn of {name} failed: {e}"),
                            }
                        }
                    }
                }
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                let name = name_of.remove(&pid).unwrap_or_else(|| pid.to_string());
                let entry = running.remove(&pid);
                println!("usud-init: {name} killed by {sig}");
                if !SHUTDOWN.load(Ordering::SeqCst) {
                    if let Some(entry) = entry {
                        if entry.respawn {
                            if let Some(service) = services_by_name.get(&name) {
                                if let Ok(child) = spawn(service) {
                                    let new_pid = Pid::from_raw(child.id() as i32);
                                    name_of.insert(new_pid, name.clone());
                                    running.insert(
                                        new_pid,
                                        Running {
                                            child,
                                            respawn: true,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(nix::errno::Errno::ECHILD) => {
                // No children left; if nothing is meant to be running, stop.
                if running.is_empty() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("usud-init: waitpid failed: {e}");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    println!("usud-init: shutdown complete");
    Ok(())
}

fn spawn(service: &Service) -> Result<Child, String> {
    let program = resolve(&service.program);
    Command::new(&program)
        .args(&service.args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("{}: {e}", program.display()))
}

/// Resolves a service program name.
///
/// Absolute paths are used as-is; a bare name is searched for in the sandbox's
/// binary directories so an inittab does not have to spell out full paths.
fn resolve(program: &str) -> PathBuf {
    if program.contains('/') {
        return PathBuf::from(program);
    }
    for dir in ["/system/bin", "/system/xbin", "/bin", "/usr/bin"] {
        let candidate = Path::new(dir).join(program);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(program)
}

fn terminate_all(running: &mut HashMap<Pid, Running>) {
    for (pid, entry) in running.iter_mut() {
        let _ = signal::kill(*pid, Signal::SIGTERM);
        let _ = entry.child.wait();
    }
    running.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_inittab() {
        let services = parse_inittab(
            "# comment\n\
             console = /system/bin/sh -i\n\
             respawn adbd = /system/bin/adbd\n\
             once setup = /system/bin/setup --all\n",
        )
        .unwrap();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].name, "console");
        assert!(services[0].respawn);
        assert_eq!(services[0].program, "/system/bin/sh");
        assert_eq!(services[0].args, vec!["-i".to_string()]);
        assert_eq!(services[1].name, "adbd");
        assert!(services[1].respawn);
        assert_eq!(services[2].name, "setup");
        assert!(services[2].once);
        assert!(!services[2].respawn);
    }

    #[test]
    fn ignores_blank_lines_and_comments() {
        let services = parse_inittab("\n\n   \n# only a comment\n").unwrap();
        assert!(services.is_empty());
    }

    #[test]
    fn rejects_lines_without_an_equals_sign() {
        let err = parse_inittab("console /system/bin/sh\n").unwrap_err();
        assert!(err.contains("line 1"), "{err}");
    }

    #[test]
    fn rejects_an_empty_program() {
        let err = parse_inittab("console =\n").unwrap_err();
        assert!(err.contains("program is empty"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_flag() {
        let err = parse_inittab("sometimes console = /system/bin/sh\n").unwrap_err();
        assert!(err.contains("unknown flag"), "{err}");
    }

    #[test]
    fn bare_names_are_resolved_against_the_sandbox_path() {
        assert_eq!(resolve("/system/bin/sh"), PathBuf::from("/system/bin/sh"));
        // A name that exists nowhere is returned unchanged so the spawn error
        // names the program the user actually wrote.
        assert_eq!(
            resolve("definitely-not-a-real-program"),
            PathBuf::from("definitely-not-a-real-program")
        );
    }
}
