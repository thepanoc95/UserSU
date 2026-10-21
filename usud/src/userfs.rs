//! High-level UserFS operations used by the IPC layer.
//!
//! Every operation goes through [`usersu_core::overlay::Layers`] rather than
//! through the mount point.  That is deliberate: the overlayfs mount and the
//! FUSE mount are both thin views over the same upper and lower directories, so
//! manipulating the layers directly gives identical results while remaining
//! testable without any mount privilege.

use std::path::{Path, PathBuf};
use usersu_core::config::Config;
use usersu_core::error::{Error, Result};
use usersu_core::overlay::{Layers, WhiteoutStyle};
use usersu_core::paths::Layout;
use usersu_core::su;

/// Builds the layer stack for `layout` using the active profile.
///
/// The data directory is taken from [`usersu_core::paths::data_dir`], so a
/// relocated data directory is honoured consistently by the daemon, the CLI and
/// the tests.
pub fn layers_for(layout: Layout, config: &Config) -> Layers {
    let data_dir = usersu_core::paths::data_dir(layout);
    let profile = config.active_profile();
    let whiteout = WhiteoutStyle::for_euid(usersu_core::privilege::current_euid());
    Layers::new(
        profile.upper_dir(&data_dir),
        profile.work_dir(&data_dir),
        profile.lower.clone(),
        whiteout,
    )
}

/// Convenience: the layer stack for the active layout and configuration.
pub fn active_layers(config: &Config) -> Layers {
    let layout = usersu_core::paths::detect_layout(usersu_core::privilege::has_root());
    layers_for(layout, config)
}

/// Lists a directory inside UserFS, merged across layers.
pub fn list(_root: &Path, path: &str) -> Result<Vec<String>> {
    let config = load_config()?;
    active_layers(&config).list(path)
}

/// Reads a file from UserFS.
pub fn read(_root: &Path, path: &str) -> Result<Vec<u8>> {
    let config = load_config()?;
    active_layers(&config).read(path)
}

/// Writes a file into UserFS, copying up from a lower layer when needed.
pub fn write(_root: &Path, path: &str, data: &[u8]) -> Result<()> {
    let config = load_config()?;
    active_layers(&config).write(path, data)?;
    Ok(())
}

/// Removes a path from UserFS, whiteout-ing a lower-only entry.
pub fn remove(_root: &Path, path: &str) -> Result<()> {
    let config = load_config()?;
    active_layers(&config).remove(path)
}

fn load_config() -> Result<Config> {
    Config::load(&Config::default_path())
}

/// The directory a sandbox backend should treat as `/`.
///
/// For the root layout that is `/userfs`.  For the FUSE layout it is the FUSE
/// mount point when it is actually mounted.  When FUSE could not be mounted
/// (no `/dev/fuse`, or the kernel refused it) the upper directory is used
/// instead: the sandbox then sees only the writable layer, which is a degraded
/// but honest view, and is what makes an unprivileged sandbox usable at all on
/// a device that forbids FUSE mounts.
pub fn sandbox_root(layout: Layout, config: &Config) -> PathBuf {
    match layout {
        Layout::Root => layout.userfs_root(),
        Layout::Fuse => {
            let mount = layout.userfs_root();
            if mount.is_dir() {
                mount
            } else {
                layers_for(layout, config).upper().to_path_buf()
            }
        }
    }
}

/// Creates the standard directory skeleton inside UserFS.
///
/// Only missing directories are created; an existing tree is left alone so that
/// re-running the bootstrap never clobbers user data.
pub fn ensure_skeleton(layers: &Layers) -> Result<()> {
    layers.prepare()?;
    const DIRS: [&str; 12] = [
        "system/bin",
        "system/xbin",
        "system/lib",
        "system/etc",
        "data",
        "dev",
        "proc",
        "sys",
        "tmp",
        "root",
        "run",
        "mnt",
    ];
    for dir in DIRS {
        let target = layers.upper().join(dir);
        std::fs::create_dir_all(&target)?;
        use std::os::unix::fs::PermissionsExt;
        let mode = if dir == "tmp" { 0o1777 } else { 0o755 };
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Installs the `usud` binary and its `su` entry point inside UserFS.
///
/// `source` is the on-disk usud binary.  When it already lives at the target
/// path the copy is skipped, which is the common case when usud is executing
/// from UserFS.
pub fn install_usud(layers: &Layers, source: &Path, as_script: bool) -> Result<PathBuf> {
    let target = layers.upper().join("system/bin/usud");
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let same_file = std::fs::canonicalize(source)
        .ok()
        .zip(std::fs::canonicalize(&target).ok())
        .map(|(a, b)| a == b)
        .unwrap_or(false);
    if !same_file {
        std::fs::copy(source, &target)?;
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;

    // The su symlink points at the usud path as seen *inside* the mount.
    let bin_dir = layers.upper().join("system/bin");
    let su_path = bin_dir.join("su");
    let _ = std::fs::remove_file(&su_path);
    if as_script {
        let usud_guest = PathBuf::from("/system/bin/usud");
        let script = format!(
            "#!/system/bin/sh\nexec {} {} \"$@\"\n",
            usud_guest.display(),
            su::ROOT_ME
        );
        std::fs::write(&su_path, script)?;
        std::fs::set_permissions(&su_path, std::fs::Permissions::from_mode(0o755))?;
    } else {
        // A relative symlink keeps working regardless of which of the two
        // documented mount points is active.
        std::os::unix::fs::symlink("usud", &su_path)?;
    }
    Ok(su_path)
}

/// Removes the temporary `.usersu-oldroot` directory left by `pivot_root`.
pub fn clean_pivot_artifacts(root: &Path) -> Result<()> {
    let old = root.join(".usersu-oldroot");
    match std::fs::remove_dir_all(&old) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_layers(root: &TempDir) -> Layers {
        let layers = Layers::new(
            root.path().join("upper"),
            root.path().join("work"),
            vec![],
            WhiteoutStyle::Marker,
        );
        layers.prepare().unwrap();
        layers
    }

    #[test]
    fn skeleton_creates_the_documented_directories() {
        let root = TempDir::new().unwrap();
        let layers = test_layers(&root);
        ensure_skeleton(&layers).unwrap();
        for dir in ["system/bin", "root", "tmp", "proc"] {
            assert!(
                layers.upper().join(dir).is_dir(),
                "{dir} should have been created"
            );
        }
    }

    #[test]
    fn skeleton_does_not_clobber_existing_files() {
        let root = TempDir::new().unwrap();
        let layers = test_layers(&root);
        ensure_skeleton(&layers).unwrap();
        std::fs::write(layers.upper().join("root/keepme"), b"precious").unwrap();
        ensure_skeleton(&layers).unwrap();
        assert_eq!(
            std::fs::read(layers.upper().join("root/keepme")).unwrap(),
            b"precious"
        );
    }

    #[test]
    fn install_usud_creates_a_relative_su_symlink() {
        let root = TempDir::new().unwrap();
        let layers = test_layers(&root);
        ensure_skeleton(&layers).unwrap();
        let source = root.path().join("usud-source");
        std::fs::write(&source, b"binary").unwrap();
        let su = install_usud(&layers, &source, false).unwrap();
        assert!(su.is_symlink());
        assert_eq!(std::fs::read_link(&su).unwrap(), PathBuf::from("usud"));
        assert!(layers.upper().join("system/bin/usud").is_file());
    }

    #[test]
    fn install_usud_can_write_a_wrapper_script() {
        let root = TempDir::new().unwrap();
        let layers = test_layers(&root);
        ensure_skeleton(&layers).unwrap();
        let source = root.path().join("usud-source");
        std::fs::write(&source, b"binary").unwrap();
        let su = install_usud(&layers, &source, true).unwrap();
        assert!(!su.is_symlink());
        let contents = std::fs::read_to_string(&su).unwrap();
        assert!(contents.contains(su::ROOT_ME));
        assert!(contents.contains("/system/bin/usud"));
    }

    #[test]
    fn layers_for_uses_the_active_profile_directories() {
        let config = Config::default();
        let layers = layers_for(Layout::Fuse, &config);
        assert_eq!(
            layers.upper(),
            Path::new("/data/data/me.usersu/files/upper")
        );
        assert_eq!(layers.work(), Path::new("/data/data/me.usersu/files/work"));
    }

    #[test]
    fn clean_pivot_artifacts_is_idempotent() {
        let root = TempDir::new().unwrap();
        std::fs::create_dir_all(root.path().join(".usersu-oldroot/sub")).unwrap();
        clean_pivot_artifacts(root.path()).unwrap();
        assert!(!root.path().join(".usersu-oldroot").exists());
        clean_pivot_artifacts(root.path()).unwrap();
    }
}
