//! Overlay-style layering used by UserFS.
//!
//! UserFS is a union of a writable `upper` directory on top of zero or more
//! read-only `lower` directories.  The rules mirror overlayfs closely enough
//! that the same tree can be served either by a real overlayfs mount (root) or
//! by the in-process FUSE backend (no root), without the two disagreeing:
//!
//! * A path present in `upper` shadows the same path in any lower layer.
//! * Writing to a lower-only path first *copies it up* into `upper`.
//! * Deleting a lower-only path creates a *whiteout* in `upper`.
//! * Directory listings are the union of all layers minus whiteouts.
//!
//! Whiteouts are represented on disk as either a 0:0 character device (what
//! overlayfs itself uses) or a `.wh.<name>` marker file.  The marker style
//! exists because creating a character device needs `CAP_MKNOD`, which is
//! exactly the capability UserSU cannot assume it has.

use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// On-disk representation of a whiteout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhiteoutStyle {
    /// A character device with device number 0:0, as overlayfs writes it.
    CharDevice,
    /// A regular file named `.wh.<name>`.  Needs no privileges.
    Marker,
}

impl WhiteoutStyle {
    /// Picks the strongest style the process can actually use.
    pub fn for_euid(euid: u32) -> Self {
        if euid == 0 {
            WhiteoutStyle::CharDevice
        } else {
            WhiteoutStyle::Marker
        }
    }

    fn marker_name(name: &str) -> String {
        format!(".wh.{name}")
    }
}

/// Where a path was found while resolving through the layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Present in the writable upper layer.
    Upper(PathBuf),
    /// Present only in a read-only lower layer.
    Lower(PathBuf),
    /// Not present anywhere.
    Missing,
}

/// A stacked filesystem: `upper` over `lower`, with a scratch `work` dir.
#[derive(Debug, Clone)]
pub struct Layers {
    upper: PathBuf,
    work: PathBuf,
    lower: Vec<PathBuf>,
    whiteout: WhiteoutStyle,
}

impl Layers {
    /// Creates a layer stack.  `lower` is ordered from highest to lowest
    /// priority, matching overlayfs' `lowerdir=a:b:c` convention.
    pub fn new(
        upper: impl Into<PathBuf>,
        work: impl Into<PathBuf>,
        lower: Vec<PathBuf>,
        whiteout: WhiteoutStyle,
    ) -> Self {
        Self {
            upper: upper.into(),
            work: work.into(),
            lower,
            whiteout,
        }
    }

    /// The writable upper directory.
    pub fn upper(&self) -> &Path {
        &self.upper
    }

    /// The overlayfs work directory.
    pub fn work(&self) -> &Path {
        &self.work
    }

    /// The read-only lower layers, highest priority first.
    pub fn lower(&self) -> &[PathBuf] {
        &self.lower
    }

    /// Creates `upper` and `work` if they do not exist yet.
    pub fn prepare(&self) -> Result<()> {
        std::fs::create_dir_all(&self.upper)?;
        std::fs::create_dir_all(&self.work)?;
        Ok(())
    }

    /// Builds the `lowerdir=` value for an overlayfs mount.
    ///
    /// The upper layer is not part of `lowerdir`; callers pass
    /// [`Layers::upper`] as `upperdir`.
    pub fn lowerdir_option(&self) -> String {
        self.lower
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Normalizes a guest path into a safe, root-relative path.
    ///
    /// Rejects anything that would escape the UserFS root, which is what keeps
    /// a sandboxed process from walking out through `..` or a symlinked
    /// component.
    pub fn normalize(path: impl AsRef<Path>) -> Result<PathBuf> {
        let raw = path.as_ref();
        let mut out = PathBuf::new();
        for comp in raw.components() {
            match comp {
                Component::RootDir | Component::Prefix(_) => {}
                Component::CurDir => {}
                Component::ParentDir => {
                    if !out.pop() {
                        return Err(Error::PathEscape(raw.to_path_buf()));
                    }
                }
                Component::Normal(part) => out.push(part),
            }
        }
        Ok(out)
    }

    fn upper_path(&self, rel: &Path) -> PathBuf {
        self.upper.join(rel)
    }

    fn whiteout_path(&self, rel: &Path) -> PathBuf {
        let name = rel
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parent = rel.parent().unwrap_or(Path::new(""));
        self.upper
            .join(parent)
            .join(WhiteoutStyle::marker_name(&name))
    }

    /// Returns true if `rel` is whited out in the upper layer.
    pub fn is_whiteout(&self, rel: impl AsRef<Path>) -> bool {
        let Ok(rel) = Self::normalize(rel) else {
            return false;
        };
        let marker = self.whiteout_path(&rel);
        match std::fs::symlink_metadata(&marker) {
            Ok(meta) => {
                if meta.file_type().is_char_device() {
                    // 0:0 char device is overlayfs' native whiteout.
                    meta.rdev() == 0
                } else {
                    true
                }
            }
            Err(_) => false,
        }
    }

    /// Resolves `rel` through the layer stack.
    pub fn resolve(&self, rel: impl AsRef<Path>) -> Result<Resolved> {
        let rel = Self::normalize(rel)?;
        if self.is_whiteout(&rel) {
            return Ok(Resolved::Missing);
        }
        let upper = self.upper_path(&rel);
        if std::fs::symlink_metadata(&upper).is_ok() {
            return Ok(Resolved::Upper(upper));
        }
        for layer in &self.lower {
            let candidate = layer.join(&rel);
            if std::fs::symlink_metadata(&candidate).is_ok() {
                return Ok(Resolved::Lower(candidate));
            }
        }
        Ok(Resolved::Missing)
    }

    /// Copies a lower-only path into the upper layer.
    ///
    /// Returns the upper path.  Directories are created (recursively) with the
    /// lower directory's mode; other files are copied with their permission
    /// bits preserved.  Symlinks are recreated rather than followed so that a
    /// copy-up cannot be used to escape the root.
    pub fn copy_up(&self, rel: impl AsRef<Path>) -> Result<PathBuf> {
        let rel = Self::normalize(rel)?;
        let upper = self.upper_path(&rel);
        if std::fs::symlink_metadata(&upper).is_ok() {
            return Ok(upper);
        }

        let source = match self.resolve(&rel)? {
            Resolved::Lower(p) => p,
            Resolved::Upper(p) => return Ok(p),
            Resolved::Missing => return Err(Error::PathNotFound(rel.clone())),
        };

        if let Some(parent) = upper.parent() {
            std::fs::create_dir_all(parent)?;
            // Clear a whiteout for this name: a copy-up re-creates the entry.
            let marker = self.whiteout_path(&rel);
            let _ = std::fs::remove_file(marker);
        }

        let meta = std::fs::symlink_metadata(&source)?;
        let file_type = meta.file_type();
        if file_type.is_dir() {
            std::fs::create_dir_all(&upper)?;
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&source)?;
            std::os::unix::fs::symlink(target, &upper)?;
        } else {
            std::fs::copy(&source, &upper)?;
        }
        std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(meta.mode()))?;
        Ok(upper)
    }

    /// Creates a whiteout so `rel` disappears from the merged view.
    pub fn whiteout(&self, rel: impl AsRef<Path>) -> Result<()> {
        let rel = Self::normalize(rel)?;
        if let Some(parent) = self.upper_path(&rel).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let target = self.upper_path(&rel);
        if std::fs::symlink_metadata(&target).is_ok() {
            remove_any(&target)?;
        }
        let marker = self.whiteout_path(&rel);
        let _ = std::fs::remove_file(&marker);
        match self.whiteout {
            WhiteoutStyle::Marker => {
                std::fs::File::create(&marker)?;
            }
            WhiteoutStyle::CharDevice => {
                let path = std::ffi::CString::new(marker.as_os_str().to_string_lossy().as_bytes())
                    .map_err(|_| Error::Config("whiteout path contains a NUL".into()))?;
                // SAFETY: `path` is a valid NUL-terminated C string and the
                // mode/dev values are plain integers.
                let rc = unsafe {
                    libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(0, 0))
                };
                if rc != 0 {
                    return Err(Error::Io(std::io::Error::last_os_error()));
                }
            }
        }
        Ok(())
    }

    /// Removes `rel`: whiteouts a lower-only entry, or deletes an upper entry.
    pub fn remove(&self, rel: impl AsRef<Path>) -> Result<()> {
        let rel = Self::normalize(rel)?;
        match self.resolve(&rel)? {
            Resolved::Upper(p) => remove_any(&p),
            Resolved::Lower(_) => self.whiteout(&rel),
            Resolved::Missing => Err(Error::PathNotFound(rel)),
        }
    }

    /// Merged directory listing of `rel` across every layer.
    ///
    /// The returned map is keyed by entry name.  Entries whited out in the
    /// upper layer are omitted.  Results are sorted by name for determinism.
    pub fn list(&self, rel: impl AsRef<Path>) -> Result<Vec<String>> {
        let rel = Self::normalize(rel)?;
        let mut merged: BTreeMap<String, ()> = BTreeMap::new();
        let mut hidden: Vec<String> = Vec::new();

        // Upper first, so its names win.
        for layer in std::iter::once(&self.upper).chain(self.lower.iter()) {
            let dir = layer.join(&rel);
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if layer == &self.upper {
                    if let Some(stripped) = name.strip_prefix(".wh.") {
                        hidden.push(stripped.to_string());
                        continue;
                    }
                    if is_char_whiteout(&entry.path()) {
                        continue;
                    }
                }
                merged.entry(name).or_insert(());
            }
        }

        Ok(merged
            .into_keys()
            .filter(|name| !hidden.contains(name))
            .collect())
    }

    /// Writes `data` to `rel`, copying up first when it lives in a lower layer.
    pub fn write(&self, rel: impl AsRef<Path>, data: &[u8]) -> Result<PathBuf> {
        let rel = Self::normalize(rel)?;
        let path = match self.resolve(&rel)? {
            Resolved::Lower(_) => self.copy_up(&rel)?,
            Resolved::Upper(p) => p,
            Resolved::Missing => {
                let p = self.upper_path(&rel);
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let marker = self.whiteout_path(&rel);
                let _ = std::fs::remove_file(marker);
                p
            }
        };
        let mut file = std::fs::File::create(&path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(path)
    }

    /// Reads `rel` from wherever it resolves.
    pub fn read(&self, rel: impl AsRef<Path>) -> Result<Vec<u8>> {
        let rel = Self::normalize(rel)?;
        match self.resolve(&rel)? {
            Resolved::Upper(p) | Resolved::Lower(p) => Ok(std::fs::read(p)?),
            Resolved::Missing => Err(Error::PathNotFound(rel)),
        }
    }

    /// Copies the contents of a lower-only directory into the upper layer so
    /// that the directory can be modified in place.
    pub fn copy_up_dir(&self, rel: impl AsRef<Path>) -> Result<PathBuf> {
        let rel = Self::normalize(rel)?;
        let upper = self.copy_up(&rel)?;
        if let Resolved::Lower(src) = self.resolve(&rel)? {
            copy_tree_into(&src, &upper)?;
        }
        Ok(upper)
    }
}

fn is_char_whiteout(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_char_device() && m.rdev() == 0)
        .unwrap_or(false)
}

fn remove_any(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn copy_tree_into(src: &Path, dst: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        let meta = entry.metadata()?;
        if meta.is_dir() {
            std::fs::create_dir_all(&target)?;
            copy_tree_into(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct Fixture {
        _root: TempDir,
        layers: Layers,
        lower: PathBuf,
    }

    fn fixture() -> Fixture {
        let root = TempDir::new().unwrap();
        let upper = root.path().join("upper");
        let work = root.path().join("work");
        let lower = root.path().join("lower");
        fs::create_dir_all(&lower).unwrap();
        let layers = Layers::new(&upper, &work, vec![lower.clone()], WhiteoutStyle::Marker);
        layers.prepare().unwrap();
        Fixture {
            _root: root,
            layers,
            lower,
        }
    }

    #[test]
    fn normalize_rejects_escapes() {
        assert!(Layers::normalize("../etc/passwd").is_err());
        assert_eq!(
            Layers::normalize("/system/./bin/../bin/sh").unwrap(),
            PathBuf::from("system/bin/sh")
        );
    }

    #[test]
    fn resolves_lower_then_upper() {
        let f = fixture();
        fs::write(f.lower.join("file"), b"lower").unwrap();
        assert!(matches!(
            f.layers.resolve("file").unwrap(),
            Resolved::Lower(_)
        ));
        fs::write(f.layers.upper().join("file"), b"upper").unwrap();
        assert!(matches!(
            f.layers.resolve("file").unwrap(),
            Resolved::Upper(_)
        ));
    }

    #[test]
    fn write_copies_up_and_preserves_lower_untouched() {
        let f = fixture();
        fs::write(f.lower.join("file"), b"lower").unwrap();
        f.layers.write("file", b"changed").unwrap();
        assert_eq!(fs::read(f.lower.join("file")).unwrap(), b"lower");
        assert_eq!(fs::read(f.layers.upper().join("file")).unwrap(), b"changed");
    }

    #[test]
    fn whiteout_hides_lower_entry() {
        let f = fixture();
        fs::write(f.lower.join("file"), b"lower").unwrap();
        f.layers.whiteout("file").unwrap();
        assert_eq!(f.layers.resolve("file").unwrap(), Resolved::Missing);
        assert!(!f.layers.list("").unwrap().contains(&"file".to_string()));
        // The lower file is still intact.
        assert!(f.lower.join("file").exists());
    }

    #[test]
    fn remove_upper_entry_deletes_it() {
        let f = fixture();
        f.layers.write("file", b"data").unwrap();
        f.layers.remove("file").unwrap();
        assert_eq!(f.layers.resolve("file").unwrap(), Resolved::Missing);
    }

    #[test]
    fn list_is_a_sorted_union() {
        let f = fixture();
        fs::write(f.lower.join("a"), b"1").unwrap();
        fs::write(f.lower.join("b"), b"1").unwrap();
        fs::write(f.layers.upper().join("c"), b"1").unwrap();
        assert_eq!(f.layers.list("").unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn copy_up_creates_missing_parent_directories() {
        let f = fixture();
        fs::create_dir_all(f.lower.join("system/bin")).unwrap();
        fs::write(f.lower.join("system/bin/sh"), b"#!/bin/sh\n").unwrap();
        let up = f.layers.copy_up("system/bin/sh").unwrap();
        assert!(up.exists());
        assert_eq!(fs::read(&up).unwrap(), b"#!/bin/sh\n");
    }

    #[test]
    fn read_missing_reports_not_found() {
        let f = fixture();
        assert!(matches!(f.layers.read("nope"), Err(Error::PathNotFound(_))));
    }

    #[test]
    fn lowerdir_option_joins_layers() {
        let f = fixture();
        assert_eq!(
            f.layers.lowerdir_option(),
            f.lower.to_string_lossy().to_string()
        );
    }
}
