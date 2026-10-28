//! `usersu-core`: the shared foundation for every UserSU component.
//!
//! The crate is deliberately free of any dependency on a running daemon or on
//! root, so the filesystem, policy and protocol logic can all be unit tested on
//! a developer machine.  Privileged work is confined to [`modules`] and the
//! root-only branches of [`sandbox`]; every entry point there reports
//! [`error::Error::NotRoot`] instead of pretending to succeed.
//!
//! Module map:
//!
//! * [`paths`] — the canonical `/data/me.usersu`, `/userfs`, `/user_system`
//!   and FUSE fallback locations, and the [`paths::Layout`] that picks between
//!   them.
//! * [`config`] — the `usersu.toml` document, profiles, and backend choices.
//! * [`overlay`] — the layer stack (copy-up, whiteouts, merged listing) that
//!   both the overlayfs mount and the FUSE backend serve.
//! * [`modules`] — the overlayfs metamodule for the root-only mount points.
//! * [`privilege`] — honest privilege probing and acquisition providers.
//! * [`sandbox`] — backend selection and the chroot/pivot_root/UML executors.
//! * [`proot`] — the unprivileged ptrace path-rewriting backend.
//! * [`su`] — `su` argument parsing, policy, environment and installation.
//! * [`protocol`] — the framed IPC protocol spoken by usud.
//! * [`toolchain`] — provisioning the optional UserFS components (shell,
//!   user-mode kernel, proot).

pub mod config;
pub mod error;
pub mod modules;
pub mod overlay;
pub mod paths;
pub mod privilege;
pub mod proot;
pub mod protocol;
pub mod sandbox;
pub mod su;
pub mod toolchain;

pub use config::{Config, PrivilegeMode, Profile, SandboxBackend, UserfsBackend};
pub use error::{Error, Result};
pub use overlay::{Layers, Resolved, WhiteoutStyle};
pub use paths::Layout;
pub use privilege::{Outcome, Provider, ProviderKind};
pub use protocol::{Request, Response, Status};

/// Crate version, reported by the daemon and the manager app.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
