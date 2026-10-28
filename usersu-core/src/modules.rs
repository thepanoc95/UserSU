//! The overlayfs "metamodule" that serves `/data/me.usersu` and the optional
//! read-write `/user_system`.
//!
//! Both of these mount points are root-only by design.  Without real root there
//! is nothing to mount *with*, so the metamodule reports
//! [`Error::NotRoot`] rather than silently degrading: the FUSE backend in
//! [`crate::paths::Layout::Fuse`] covers the unprivileged case instead.
//!
//! The metamodule is split into two halves so the interesting part is testable
//! without privileges: [`MountPlan`] is pure data describing exactly what
//! would be mounted, and [`apply`] performs the syscall.

use crate::error::{Error, Result};
use crate::overlay::Layers;
use crate::paths;
use std::ffi::CString;
use std::path::{Path, PathBuf};

/// A single overlayfs mount to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPlan {
    /// Mount source; `overlay` for overlayfs.
    pub source: String,
    /// Mount point.
    pub target: PathBuf,
    /// Filesystem type.
    pub fstype: String,
    /// `MS_*` flags.
    pub flags: u64,
    /// Comma separated mount options including `upperdir`, `workdir`,
    /// `lowerdir` and the metamodule's own options.
    pub options: String,
}

impl MountPlan {
    /// Builds an overlayfs plan for `layers` mounted at `target`.
    pub fn overlay(target: impl Into<PathBuf>, layers: &Layers, extra_options: &str) -> Self {
        let mut options = vec![
            format!("upperdir={}", layers.upper().display()),
            format!("workdir={}", layers.work().display()),
            format!("lowerdir={}", layers.lowerdir_option()),
        ];
        if !extra_options.is_empty() {
            options.push(extra_options.to_string());
        }
        Self {
            source: "overlay".to_string(),
            target: target.into(),
            fstype: "overlay".to_string(),
            flags: 0,
            options: options.join(","),
        }
    }

    /// Builds a read-only bind-style plan, used to expose a lower layer
    /// unchanged when no upper layer should be visible.
    pub fn bind_ro(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into().display().to_string(),
            target: target.into(),
            fstype: "none".to_string(),
            flags: libc::MS_BIND | libc::MS_RDONLY,
            options: String::new(),
        }
    }
}

/// The metamodule: the set of mounts UserSU manages for the root layout.
#[derive(Debug, Clone)]
pub struct Metamodule {
    data_dir: PathBuf,
    userfs_mount: PathBuf,
    user_system_mount: Option<PathBuf>,
    options: String,
}

impl Metamodule {
    /// Creates a metamodule rooted at `data_dir`.
    pub fn new(data_dir: impl Into<PathBuf>, options: impl Into<String>) -> Self {
        Self {
            data_dir: data_dir.into(),
            userfs_mount: PathBuf::from(paths::USERFS_MOUNT),
            user_system_mount: Some(PathBuf::from(paths::USER_SYSTEM_MOUNT)),
            options: options.into(),
        }
    }

    /// The `/data/me.usersu` directory this metamodule owns.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Enables or disables the optional read-write `/user_system` layer.
    pub fn with_user_system(mut self, enabled: bool) -> Self {
        self.user_system_mount = enabled.then(|| PathBuf::from(paths::USER_SYSTEM_MOUNT));
        self
    }

    /// Computes the mounts required to bring the root layout up.
    ///
    /// The order matters: `/data/me.usersu` must exist and be writable before
    /// it can host the upper and work directories of the other layers.
    pub fn plans(
        &self,
        userfs_layers: &Layers,
        user_system_layers: Option<&Layers>,
    ) -> Vec<MountPlan> {
        let mut plans = Vec::new();
        // The data directory itself is a plain directory, so no mount is
        // needed; its upper/work subdirectories are created by `prepare`.
        plans.push(MountPlan::overlay(
            &self.userfs_mount,
            userfs_layers,
            &self.options,
        ));
        if let (Some(target), Some(layers)) = (&self.user_system_mount, user_system_layers) {
            plans.push(MountPlan::overlay(target, layers, &self.options));
        }
        plans
    }

    /// Applies every plan, stopping at the first failure.
    pub fn apply(&self, plans: &[MountPlan]) -> Result<()> {
        for plan in plans {
            apply(plan)?;
        }
        Ok(())
    }
}

/// Applies every plan, stopping at the first failure.
pub fn apply_all(plans: &[MountPlan]) -> Result<()> {
    for plan in plans {
        apply(plan)?;
    }
    Ok(())
}

/// Performs one `mount(2)`.
///
/// Requires `CAP_SYS_ADMIN`; returns [`Error::NotRoot`] otherwise so callers
/// can fall back to the FUSE layout.
pub fn apply(plan: &MountPlan) -> Result<()> {
    if !crate::privilege::has_root() {
        return Err(Error::NotRoot("mounting UserFS requires CAP_SYS_ADMIN"));
    }
    std::fs::create_dir_all(&plan.target)?;

    let source = CString::new(plan.source.as_str())
        .map_err(|_| Error::Config("mount source contains a NUL".into()))?;
    let fstype = CString::new(plan.fstype.as_str())
        .map_err(|_| Error::Config("mount fstype contains a NUL".into()))?;
    let target = CString::new(plan.target.as_os_str().to_string_lossy().as_bytes())
        .map_err(|_| Error::Config("mount target contains a NUL".into()))?;
    let options = if plan.options.is_empty() {
        None
    } else {
        Some(
            CString::new(plan.options.as_str())
                .map_err(|_| Error::Config("mount options contain a NUL".into()))?,
        )
    };

    // SAFETY: all four pointers are valid NUL-terminated C strings (or null),
    // and the flags are plain integers.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            plan.flags,
            options
                .as_ref()
                .map(|o| o.as_ptr() as *const libc::c_void)
                .unwrap_or(std::ptr::null()),
        )
    };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    log::info!(
        "mounted {} on {} ({} {})",
        plan.source,
        plan.target.display(),
        plan.fstype,
        plan.options
    );
    Ok(())
}

/// Unmounts `target`, lazily on failure so a busy mount point still detaches.
pub fn unmount(target: &Path) -> Result<()> {
    if !crate::privilege::has_root() {
        return Err(Error::NotRoot("unmounting UserFS requires CAP_SYS_ADMIN"));
    }
    let path = CString::new(target.as_os_str().to_string_lossy().as_bytes())
        .map_err(|_| Error::Config("unmount path contains a NUL".into()))?;
    // SAFETY: `path` is a valid NUL-terminated C string.
    let rc = unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::WhiteoutStyle;
    use tempfile::TempDir;

    #[test]
    fn overlay_plan_contains_every_directory() {
        let root = TempDir::new().unwrap();
        let lower = root.path().join("lower");
        std::fs::create_dir_all(&lower).unwrap();
        let layers = Layers::new(
            root.path().join("upper"),
            root.path().join("work"),
            vec![lower.clone()],
            WhiteoutStyle::Marker,
        );
        let plan = MountPlan::overlay("/userfs", &layers, "index=off");
        assert_eq!(plan.fstype, "overlay");
        assert_eq!(plan.source, "overlay");
        assert!(plan.options.contains("upperdir="));
        assert!(plan.options.contains("workdir="));
        assert!(plan
            .options
            .contains(&format!("lowerdir={}", lower.display())));
        assert!(plan.options.contains("index=off"));
    }

    #[test]
    fn metamodule_plans_userfs_and_optional_user_system() {
        let root = TempDir::new().unwrap();
        let mk = |name: &str| {
            Layers::new(
                root.path().join(name).join("upper"),
                root.path().join(name).join("work"),
                vec![],
                WhiteoutStyle::Marker,
            )
        };
        let mm = Metamodule::new("/data/me.usersu", "index=off").with_user_system(true);
        let userfs = mk("userfs");
        let user_system = mk("user_system");
        let plans = mm.plans(&userfs, Some(&user_system));
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].target, PathBuf::from("/userfs"));
        assert_eq!(plans[1].target, PathBuf::from("/user_system"));

        let mm = mm.with_user_system(false);
        assert_eq!(mm.plans(&userfs, None).len(), 1);
    }

    #[test]
    fn apply_refuses_without_root() {
        if crate::privilege::has_root() {
            return; // skip when the test runner is actually root
        }
        let plan = MountPlan::bind_ro("/", "/tmp/usersu-should-not-mount");
        assert!(matches!(apply(&plan), Err(Error::NotRoot(_))));
        assert!(matches!(unmount(Path::new("/tmp")), Err(Error::NotRoot(_))));
    }
}
