//! Canonical on-device paths used by every UserSU component.
//!
//! UserSU has two cooperating filesystem layers:
//!
//! * `/data/me.usersu` and `/user_system` are only usable with real root,
//!   because they are served by an overlayfs "metamodule" (see
//!   [`crate::modules`]).  The upper layer lives under the data directory.
//! * `/userfs` is the UserFS root.  With root it is a normal mount point.
//!   Without the ability to create and mount it, usud serves the exact same
//!   tree through FUSE at [`FUSE_USERFS_MOUNT`].

use std::path::{Path, PathBuf};

/// Root-only data directory (overlayfs upper/work lives here).
pub const DATA_DIR: &str = "/data/me.usersu";

/// Root-only UserFS mount point.
pub const USERFS_MOUNT: &str = "/userfs";

/// Root-only optional read-write system layer.
pub const USER_SYSTEM_MOUNT: &str = "/user_system";

/// App-private files directory.  The FUSE fallback mount lives underneath it.
pub const APP_FILES_DIR: &str = "/data/data/me.usersu/files";

/// Where UserFS is mounted when no mount capability is available.
pub const FUSE_USERFS_MOUNT: &str = "/data/data/me.usersu/files/mnt/userfs";

/// Suffix appended to the mount point to discover the usud binary.
pub const SYSTEM_BIN: &str = "system/bin";

/// Name of the usud binary.
pub const USUD_BIN: &str = "usud";

/// Marker argument that makes usud behave like `su`.
pub const ROOT_ME_ARG: &str = "-root.me";

/// Default IPC socket (abstract namespace name is derived from this path).
pub const DAEMON_SOCKET: &str = "/data/me.usersu/usud.sock";

/// Fallback IPC socket when the data directory is not writable.
pub const DAEMON_SOCKET_FALLBACK: &str = "/data/data/me.usersu/files/usud.sock";

/// Configuration file name inside the data directory.
pub const CONFIG_FILE: &str = "usersu.toml";

/// Environment variable that relocates the UserSU data directory.
///
/// Intended for development, tests and unusual devices where `/data` is not
/// writable by the usud uid.  Production installs leave it unset.
pub const DATA_DIR_ENV: &str = "USERSU_DATA_DIR";

/// Environment variable that relocates the daemon socket.
pub const SOCKET_ENV: &str = "USERSU_SOCKET";

/// Returns the data directory for `layout`, honouring [`DATA_DIR_ENV`].
pub fn data_dir(layout: Layout) -> PathBuf {
    match std::env::var_os(DATA_DIR_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => layout.data_dir(),
    }
}

/// Returns the daemon socket path, honouring [`SOCKET_ENV`].
pub fn socket_path(layout: Layout) -> PathBuf {
    if let Some(path) = std::env::var_os(SOCKET_ENV) {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    match layout {
        Layout::Root => PathBuf::from(DAEMON_SOCKET),
        Layout::Fuse => PathBuf::from(DAEMON_SOCKET_FALLBACK),
    }
}

/// Layout describes which of the two UserFS placements is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `/userfs` is a real mount point; `/data/me.usersu` and
    /// `/user_system` may be served by the overlayfs metamodule.
    Root,

    /// No mount capability: UserFS is served over FUSE at
    /// [`FUSE_USERFS_MOUNT`] and lives entirely inside the data directory.
    Fuse,
}

impl Layout {
    /// Returns the UserFS root for this layout.
    pub fn userfs_root(self) -> PathBuf {
        match self {
            Layout::Root => PathBuf::from(USERFS_MOUNT),
            Layout::Fuse => PathBuf::from(FUSE_USERFS_MOUNT),
        }
    }

    /// Returns the `system/bin` directory that holds usud inside UserFS.
    pub fn system_bin(self) -> PathBuf {
        self.userfs_root().join(SYSTEM_BIN)
    }

    /// Returns the canonical usud path inside UserFS.
    pub fn usud_path(self) -> PathBuf {
        self.system_bin().join(USUD_BIN)
    }

    /// Returns the canonical `su` symlink path inside UserFS.
    pub fn su_path(self) -> PathBuf {
        self.system_bin().join("su")
    }

    /// Returns the private data directory for this layout.
    pub fn data_dir(self) -> PathBuf {
        match self {
            Layout::Root => PathBuf::from(DATA_DIR),
            Layout::Fuse => PathBuf::from(APP_FILES_DIR),
        }
    }
}

/// Decide which layout to use for a device.
///
/// `is_root` should come from a real privilege probe (see
/// [`crate::privilege`]); it is never inferred from environment variables.
pub fn detect_layout(is_root: bool) -> Layout {
    if is_root && Path::new(USERFS_MOUNT).is_dir() {
        Layout::Root
    } else {
        Layout::Fuse
    }
}

/// Absolute path of the `su` binary, resolving the two documented spellings.
///
/// Both candidates are returned in priority order so callers can create the
/// symlink next to whichever usud binary actually exists.
pub fn su_candidates() -> [PathBuf; 2] {
    [Layout::Root.su_path(), Layout::Fuse.su_path()]
}

/// Absolute path of the usud binary, resolving the two documented spellings.
pub fn usud_candidates() -> [PathBuf; 2] {
    [Layout::Root.usud_path(), Layout::Fuse.usud_path()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuse_layout_uses_app_private_mount() {
        let layout = Layout::Fuse;
        assert_eq!(
            layout.usud_path(),
            PathBuf::from("/data/data/me.usersu/files/mnt/userfs/system/bin/usud")
        );
        assert_eq!(
            layout.su_path(),
            PathBuf::from("/data/data/me.usersu/files/mnt/userfs/system/bin/su")
        );
    }

    #[test]
    fn root_layout_uses_slash_userfs() {
        let layout = Layout::Root;
        assert_eq!(layout.usud_path(), PathBuf::from("/userfs/system/bin/usud"));
    }

    #[test]
    fn detect_layout_prefers_root_only_when_mounted() {
        // /userfs will not exist in a test environment, so this is Fuse.
        assert_eq!(detect_layout(false), Layout::Fuse);
    }
}
