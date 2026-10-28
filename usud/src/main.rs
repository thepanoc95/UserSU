//! `usud`: the UserSU backend.
//!
//! usud has three faces, chosen by how it is invoked:
//!
//! * `usud <subcommand>` — the CLI: `daemon`, `status`, `providers`, `shell`,
//!   `exec`, `install`, `list`, `cat`, `write`, `rm`, `profile`, `boot`.
//! * `usud -root.me [args]` — `su`.  This is the spelling the documented `su`
//!   symlink relies on, and it is also selected automatically when the binary
//!   is invoked through a symlink named `su`.
//! * `usud su [args]` — the same thing, spelled explicitly.

mod fuse_fs;
mod ipc;
mod runner;
mod userfs;

use clap::{CommandFactory, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use usersu_core::config::Config;
use usersu_core::error::{Error, Result};
use usersu_core::modules::{self, Metamodule};
use usersu_core::paths::{self, Layout};
use usersu_core::protocol::{Request, Response};
use usersu_core::su;
use usersu_core::toolchain;

#[derive(Parser, Debug)]
#[command(
    name = "usud",
    version,
    about = "UserSU backend: su, UserFS and sandboxes"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the daemon in the foreground.
    Daemon,
    /// Print daemon and device status.
    Status,
    /// List privilege providers and whether they are usable.
    Providers,
    /// Start a root shell in UserFS.
    Shell {
        /// Command to run instead of an interactive shell.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Run a command as root in UserFS.
    Exec {
        /// The command and its arguments.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Install usud and the su entry point into UserFS.
    Install {
        /// Write a wrapper script instead of a symlink for su.
        #[arg(long)]
        as_script: bool,
    },
    /// Provision the optional UserFS components (shell, user-mode kernel, proot).
    InstallToolchain {
        /// Directory to copy components from, searched first.
        #[arg(long, default_value = "/data/local/tmp")]
        source: PathBuf,
    },
    /// List a directory inside UserFS.
    List {
        /// Path relative to the UserFS root.
        #[arg(default_value = "/")]
        path: String,
    },
    /// Print a file from UserFS.
    Cat {
        /// Path relative to the UserFS root.
        path: String,
    },
    /// Write a file into UserFS, reading the contents from stdin.
    Write {
        /// Path relative to the UserFS root.
        path: String,
    },
    /// Remove a path from UserFS.
    Rm {
        /// Path relative to the UserFS root.
        path: String,
    },
    /// Manage profiles.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Boot an init system in a sandbox.
    Boot {
        /// Init program to run instead of the configured one.
        #[arg(long)]
        init: Option<String>,
        /// Arguments for the init program.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Stop a running daemon.
    Stop,
    /// su-compatible entry point (same as `usud -root.me`).
    Su {
        /// Arguments forwarded to the su implementation.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ProfileAction {
    /// List profiles.
    List,
    /// Activate a profile.
    Use {
        /// Profile name.
        name: String,
    },
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let argv0 = argv.first().cloned().unwrap_or_default();
    let rest: Vec<String> = argv.iter().skip(1).cloned().collect();

    // `su` mode is decided before clap runs, because su arguments include
    // things clap would try to interpret as usud options.
    if su::is_root_me_invocation(&argv0, &rest) {
        return finish(su_main(&rest));
    }

    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Su { args }) => su_main(&args),
        Some(command) => run_command(command),
        None => {
            let mut cmd = Cli::command();
            cmd.print_help().ok();
            println!();
            Ok(0)
        }
    };
    finish(result)
}

fn finish(result: Result<i32>) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("usud: {e}");
            ExitCode::from(1)
        }
    }
}

fn init_logging(config: &Config) {
    let default = if config.debug { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();
}

/// The active layout and UserFS root for this invocation.
fn current_layout() -> Layout {
    paths::detect_layout(usersu_core::privilege::has_root())
}

fn socket_path() -> PathBuf {
    paths::socket_path(current_layout())
}

fn load_config() -> Result<Config> {
    Config::load(&Config::default_path())
}

fn run_command(command: Command) -> Result<i32> {
    match command {
        Command::Daemon => run_daemon(),
        Command::Status => print_status(),
        Command::Providers => print_providers(),
        Command::Shell { command } => run_via_daemon(command),
        Command::Exec { command } => run_via_daemon(command),
        Command::Install { as_script } => install(as_script),
        Command::InstallToolchain { source } => install_toolchain(&source),
        Command::List { path } => {
            let response = call(Request::ListDir { path })?;
            match response {
                Response::Listing(entries) => {
                    for entry in entries {
                        println!("{entry}");
                    }
                    Ok(0)
                }
                Response::Error { message } => Err(Error::Protocol(message)),
                other => Err(unexpected(other)),
            }
        }
        Command::Cat { path } => {
            let response = call(Request::ReadFile { path })?;
            match response {
                Response::File(data) => {
                    use std::io::Write;
                    std::io::stdout().write_all(&data)?;
                    Ok(0)
                }
                Response::Error { message } => Err(Error::Protocol(message)),
                other => Err(unexpected(other)),
            }
        }
        Command::Write { path } => {
            use std::io::Read;
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;
            expect_ok(call(Request::WriteFile { path, data })?)
        }
        Command::Rm { path } => expect_ok(call(Request::RemoveFile { path })?),
        Command::Profile { action } => match action {
            ProfileAction::List => {
                let response = call(Request::ListProfiles)?;
                match response {
                    Response::Profiles(profiles) => {
                        for profile in profiles {
                            let marker = if profile.active { "*" } else { " " };
                            println!("{marker} {}", profile.name);
                        }
                        Ok(0)
                    }
                    Response::Error { message } => Err(Error::Protocol(message)),
                    other => Err(unexpected(other)),
                }
            }
            ProfileAction::Use { name } => expect_ok(call(Request::ActivateProfile { name })?),
        },
        Command::Boot { init, args } => {
            let response = call(Request::Boot { init, args })?;
            match response {
                Response::Executed { code } => Ok(code.unwrap_or(0)),
                Response::Error { message } => Err(Error::Protocol(message)),
                other => Err(unexpected(other)),
            }
        }
        Command::Stop => expect_ok(call(Request::Shutdown)?),
        Command::Su { .. } => unreachable!("su is handled before dispatch"),
    }
}

fn call(request: Request) -> Result<Response> {
    ipc::call(&socket_path(), request)
}

fn expect_ok(response: Response) -> Result<i32> {
    match response {
        Response::Ok { message } => {
            println!("{message}");
            Ok(0)
        }
        Response::Error { message } => Err(Error::Protocol(message)),
        other => Err(unexpected(other)),
    }
}

fn unexpected(response: Response) -> Error {
    Error::Protocol(format!("unexpected response: {response:?}"))
}

fn print_status() -> Result<i32> {
    let response = call(Request::Status)?;
    match response {
        Response::Status(status) => {
            println!("usud {}", status.version);
            println!("layout:   {}", status.layout);
            println!("userfs:   {}", status.userfs);
            println!("profile:  {}", status.profile);
            println!("root:     {}", if status.root { "yes" } else { "no" });
            println!("euid:     {}", status.euid);
            println!("kernel:   {}", status.kernel);
            println!("arch:     {}", status.arch);
            println!(
                "init:     {}",
                if status.init_running {
                    "running"
                } else {
                    "stopped"
                }
            );
            Ok(0)
        }
        Response::Error { message } => Err(Error::Protocol(message)),
        other => Err(unexpected(other)),
    }
}

fn print_providers() -> Result<i32> {
    let response = call(Request::Providers)?;
    match response {
        Response::Providers(reports) => {
            for report in reports {
                let state = if report.available {
                    "available"
                } else {
                    "unavailable"
                };
                println!("{:<16} {:<16} {}", report.name, report.kind, state);
                if let Some(reason) = report.reason {
                    println!("{:<16} {reason}", "");
                }
            }
            Ok(0)
        }
        Response::Error { message } => Err(Error::Protocol(message)),
        other => Err(unexpected(other)),
    }
}

fn run_via_daemon(command: Vec<String>) -> Result<i32> {
    let response = call(Request::Su {
        command,
        uid: 0,
        gid: 0,
        keep_env: false,
        // The daemon inherits this process's stdio when it does not receive
        // descriptors, but lending them is what makes the output come back to
        // this terminal when the daemon is detached.
        wants_stdio: true,
    })?;
    match response {
        Response::Executed { code } => Ok(code.unwrap_or(0)),
        Response::Error { message } => Err(Error::Protocol(message)),
        other => Err(unexpected(other)),
    }
}

/// Implements `su` mode: parse the arguments, then ask the daemon to run them.
fn su_main(args: &[String]) -> Result<i32> {
    let request = su::parse_args(args)?;
    let config = load_config().unwrap_or_default();
    init_logging(&config);
    let response = call(Request::Su {
        command: request.command,
        uid: request.uid,
        gid: request.gid,
        keep_env: request.keep_env,
        wants_stdio: true,
    })?;
    match response {
        Response::Executed { code } => Ok(code.unwrap_or(0)),
        Response::Error { message } => Err(Error::Protocol(message)),
        other => Err(unexpected(other)),
    }
}

fn install(as_script: bool) -> Result<i32> {
    let layout = current_layout();
    let config = load_config()?;
    let source = std::env::current_exe()?;

    let layers = userfs::layers_for(layout, &config);
    userfs::ensure_skeleton(&layers)?;
    let su_path = userfs::install_usud(&layers, &source, as_script)?;
    println!(
        "installed usud at {}",
        layers.upper().join("system/bin/usud").display()
    );
    println!("installed su entry point at {}", su_path.display());

    // Also install into the other documented location when possible, so the
    // documented su path exists whichever layout is active.
    let other = match layout {
        Layout::Root => Layout::Fuse,
        Layout::Fuse => Layout::Root,
    };
    let other_layers = userfs::layers_for(other, &config);
    if other_layers.prepare().is_ok() && userfs::ensure_skeleton(&other_layers).is_ok() {
        let _ = userfs::install_usud(&other_layers, &source, as_script);
    }
    Ok(0)
}

fn run_daemon() -> Result<i32> {
    let config = load_config()?;
    init_logging(&config);
    let layout = current_layout();
    let root = usersu_core::privilege::has_root();

    let layers = userfs::layers_for(layout, &config);
    userfs::ensure_skeleton(&layers)?;

    // Try to bring up the root layout's mount points when root is available.
    if root {
        match bring_up_root_layout(&config) {
            Ok(()) => log::info!("overlayfs metamodule mounted /userfs and friends"),
            Err(e) => log::warn!("overlayfs metamodule unavailable, continuing: {e}"),
        }
    } else {
        log::info!("running unprivileged: UserFS will be served over FUSE");
    }

    let socket = socket_path();
    let listener = ipc::bind(&socket)?;
    let shared = Arc::new(ipc::Shared::new(
        config.clone(),
        root,
        if root { "root" } else { "fuse" }.to_string(),
        layout.userfs_root(),
    ));

    // Attempt privilege acquisition before serving, but never block startup on
    // it: the FUSE layout is useful without any elevation at all.
    if !root {
        if let Some(provider) = runner::acquire(&config) {
            log::info!("privilege provider '{provider}' reports a usable path");
        }
    }

    // Serve FUSE when the root layout is not active.
    let _fuse_session = if layout == Layout::Fuse {
        match start_fuse(&config, layout) {
            Ok(session) => session,
            Err(e) => {
                log::warn!("FUSE UserFS not mounted: {e}");
                None
            }
        }
    } else {
        None
    };

    println!("usud listening on {}", socket.display());
    println!("UserFS root: {}", layout.userfs_root().display());
    ipc::serve(listener, Arc::clone(&shared))?;
    Ok(0)
}

/// Mounts the root layout's mount points via the overlayfs metamodule.
fn bring_up_root_layout(config: &Config) -> Result<()> {
    let data_dir = paths::data_dir(Layout::Root);
    let metamodule = Metamodule::new(&data_dir, config.overlay_options.clone());
    let userfs = userfs::layers_for(Layout::Root, config);
    userfs.prepare()?;

    let profile = config.active_profile();
    let user_system = profile.rw_user_system.then(|| {
        // The read-write system layer stacks on top of the same lower layers.
        usersu_core::overlay::Layers::new(
            profile.upper_dir(&data_dir).join("user_system"),
            profile.work_dir(&data_dir).join("user_system"),
            profile.lower.clone(),
            usersu_core::overlay::WhiteoutStyle::for_euid(usersu_core::privilege::current_euid()),
        )
    });

    if let Some(layers) = &user_system {
        layers.prepare()?;
    }
    let plans = metamodule.plans(&userfs, user_system.as_ref());
    modules::apply_all(&plans)
}

/// Provisions the optional UserFS components from `source`.
fn install_toolchain(source: &Path) -> Result<i32> {
    let layout = current_layout();
    let config = load_config()?;
    let layers = userfs::layers_for(layout, &config);
    userfs::ensure_skeleton(&layers)?;
    let userfs_root = userfs::sandbox_root(layout, &config);

    let plan = toolchain::default_plan(source, source);
    let report = toolchain::provision_all(&userfs_root, &plan);
    for (component, outcome) in &report.entries {
        match outcome {
            toolchain::Provisioned::Installed(path) => {
                println!("{}: installed at {}", component.name(), path.display())
            }
            toolchain::Provisioned::AlreadyPresent(path) => {
                println!(
                    "{}: already present at {}",
                    component.name(),
                    path.display()
                )
            }
            toolchain::Provisioned::NotFound(reason) => {
                println!("{}: not found ({reason})", component.name())
            }
        }
    }
    if !report.complete() {
        eprintln!(
            "usud: {} component(s) still missing; push them to {} and re-run",
            report.missing().len(),
            source.display()
        );
        return Ok(1);
    }
    Ok(0)
}

/// Starts the FUSE mount for the current layout, returning the live session.
fn start_fuse(config: &Config, layout: Layout) -> Result<Option<fuser::BackgroundSession>> {
    if !fuse_fs::fuse_available() {
        return Err(Error::Unsupported("/dev/fuse is not available".into()));
    }
    let layers = userfs::layers_for(layout, config);
    layers.prepare()?;
    let options = fuse_fs::UserFsOptions::default();
    let fs = fuse_fs::UserFs::new(layers, options.clone());
    let session = fuse_fs::mount(fs, Path::new(paths::FUSE_USERFS_MOUNT), &options)?;
    log::info!("UserFS mounted over FUSE at {}", paths::FUSE_USERFS_MOUNT);
    Ok(Some(session))
}
