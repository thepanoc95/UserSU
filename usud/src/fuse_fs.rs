//! The FUSE backend that serves UserFS when no mount capability is available.
//!
//! This is the unprivileged path: instead of asking the kernel to stack
//! overlayfs at `/userfs`, usud mounts its own filesystem at
//! `/data/data/me.usersu/files/mnt/userfs` and answers the same operations
//! through [`crate::fuse_fs::UserFs`].  The merged view is produced by
//! [`usersu_core::overlay::Layers`], so the FUSE tree and the overlayfs tree
//! follow identical copy-up and whiteout rules.
//!
//! Directory handles are stateless: the inode number *is* the handle.  Files
//! are opened by path on each request rather than through a retained
//! descriptor, which keeps copy-up correct when a lower-layer file is modified
//! while an open handle exists.

use fuser::{
    BackgroundSession, FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, Request, TimeOrNow,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use usersu_core::error::{Error, Result};
use usersu_core::overlay::{Layers, Resolved};

/// Maps inode numbers to paths inside the UserFS tree.
///
/// Entries are never evicted: keeping path-to-inode stable across a `forget`
/// is explicitly allowed by the protocol and avoids handing the kernel a new
/// inode number for a path it still has cached.  Renames rewrite the affected
/// prefixes so that a moved directory's children keep their identity.
#[derive(Debug, Default)]
struct InodeTable {
    next: u64,
    by_ino: HashMap<u64, PathBuf>,
    by_path: HashMap<PathBuf, u64>,
}

impl InodeTable {
    /// The inode number reserved for the filesystem root.
    const ROOT: u64 = 1;

    fn new() -> Self {
        let mut table = Self {
            next: Self::ROOT + 1,
            by_ino: HashMap::new(),
            by_path: HashMap::new(),
        };
        table.by_ino.insert(Self::ROOT, PathBuf::new());
        table.by_path.insert(PathBuf::new(), Self::ROOT);
        table
    }

    fn ino_for(&mut self, rel: &Path) -> u64 {
        if let Some(ino) = self.by_path.get(rel) {
            return *ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_ino.insert(ino, rel.to_path_buf());
        self.by_path.insert(rel.to_path_buf(), ino);
        ino
    }

    fn path_for(&self, ino: u64) -> Option<&Path> {
        self.by_ino.get(&ino).map(PathBuf::as_path)
    }

    /// Rewrites every path under `from` to be under `to`, preserving inodes.
    fn rename_subtree(&mut self, from: &Path, to: &Path) {
        let moved: Vec<(PathBuf, u64)> = self
            .by_path
            .iter()
            .filter_map(|(path, ino)| {
                path.strip_prefix(from)
                    .ok()
                    .map(|rest| (to.join(rest), *ino))
            })
            .collect();
        for (new_path, ino) in moved {
            let old_path = self.by_ino.insert(ino, new_path.clone());
            if let Some(old_path) = old_path {
                self.by_path.remove(&old_path);
            }
            self.by_path.insert(new_path, ino);
        }
    }
}

/// Configuration for the mounted tree's presentation.
#[derive(Debug, Clone)]
pub struct UserFsOptions {
    /// uid reported for every entry.  `0` makes the tree look root-owned,
    /// which is what a root solution should present.
    pub uid: u32,
    /// gid reported for every entry.
    pub gid: u32,
    /// Attribute cache lifetime.
    pub ttl: Duration,
    /// Whether to pass `allow_other`, letting other apps see the mount.
    pub allow_other: bool,
}

impl Default for UserFsOptions {
    fn default() -> Self {
        Self {
            uid: 0,
            gid: 0,
            ttl: Duration::from_secs(1),
            allow_other: false,
        }
    }
}

/// The UserFS filesystem as seen by the kernel.
pub struct UserFs {
    layers: Layers,
    inodes: InodeTable,
    options: UserFsOptions,
}

impl UserFs {
    /// Creates a filesystem over `layers`.
    pub fn new(layers: Layers, options: UserFsOptions) -> Self {
        Self {
            layers,
            inodes: InodeTable::new(),
            options,
        }
    }

    /// Creates a filesystem over `layers` with default presentation options.
    ///
    /// Used by the tests; the daemon builds options explicitly so it can pass
    /// the same values to the mount call.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_defaults(layers: Layers) -> Self {
        Self::new(layers, UserFsOptions::default())
    }

    /// Resolves an inode number to a path, or `ENOENT`.
    fn path(&self, ino: u64) -> std::result::Result<PathBuf, i32> {
        self.inodes
            .path_for(ino)
            .map(Path::to_path_buf)
            .ok_or(libc::ENOENT)
    }

    fn attr_of(&self, rel: &Path, ino: u64) -> Result<FileAttr> {
        let host = match self.layers.resolve(rel)? {
            Resolved::Upper(p) | Resolved::Lower(p) => p,
            Resolved::Missing => return Err(Error::PathNotFound(rel.to_path_buf())),
        };
        let meta = std::fs::symlink_metadata(&host)?;
        Ok(self.attr_from_metadata(&meta, ino))
    }

    fn attr_from_metadata(&self, meta: &std::fs::Metadata, ino: u64) -> FileAttr {
        use std::os::unix::fs::MetadataExt;
        FileAttr {
            ino,
            size: meta.size(),
            blocks: meta.blocks(),
            atime: meta.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
            mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(meta.ctime().max(0) as u64),
            crtime: SystemTime::UNIX_EPOCH,
            kind: file_type_of(meta),
            perm: (meta.mode() & 0o7777) as u16,
            nlink: meta.nlink() as u32,
            uid: self.options.uid,
            gid: self.options.gid,
            rdev: meta.rdev() as u32,
            blksize: meta.blksize() as u32,
            flags: 0,
        }
    }

    /// Ensures `rel` lives in the upper layer before a mutation, creating the
    /// parent directories as needed.
    fn ensure_upper(&self, rel: &Path) -> Result<PathBuf> {
        match self.layers.resolve(rel)? {
            Resolved::Upper(p) => Ok(p),
            Resolved::Lower(_) => self.layers.copy_up(rel),
            Resolved::Missing => {
                let upper = self.layers.upper().join(rel);
                if let Some(parent) = upper.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Ok(upper)
            }
        }
    }
}

fn file_type_of(meta: &std::fs::Metadata) -> FileType {
    use std::os::unix::fs::FileTypeExt;
    let ft = meta.file_type();
    if ft.is_dir() {
        FileType::Directory
    } else if ft.is_symlink() {
        FileType::Symlink
    } else if ft.is_char_device() {
        FileType::CharDevice
    } else if ft.is_block_device() {
        FileType::BlockDevice
    } else if ft.is_fifo() {
        FileType::NamedPipe
    } else if ft.is_socket() {
        FileType::Socket
    } else {
        FileType::RegularFile
    }
}

/// Converts a core error into a negative errno.
fn errno(error: &Error) -> i32 {
    match error {
        Error::PathNotFound(_) => libc::ENOENT,
        Error::PathEscape(_) => libc::EPERM,
        Error::NotRoot(_) => libc::EPERM,
        Error::Unsupported(_) => libc::ENOSYS,
        Error::Io(io) => match io.raw_os_error() {
            Some(code) => code,
            None => match io.kind() {
                std::io::ErrorKind::NotFound => libc::ENOENT,
                std::io::ErrorKind::PermissionDenied => libc::EACCES,
                std::io::ErrorKind::AlreadyExists => libc::EEXIST,
                std::io::ErrorKind::InvalidInput => libc::EINVAL,
                std::io::ErrorKind::DirectoryNotEmpty => libc::ENOTEMPTY,
                _ => libc::EIO,
            },
        },
        _ => libc::EIO,
    }
}

fn time_or_now(value: TimeOrNow) -> SystemTime {
    match value {
        TimeOrNow::SpecificTime(t) => t,
        TimeOrNow::Now => SystemTime::now(),
    }
}

impl Filesystem for UserFs {
    fn init(
        &mut self,
        _req: &Request<'_>,
        config: &mut KernelConfig,
    ) -> std::result::Result<(), libc::c_int> {
        // Ask for a generous read buffer; ignore a kernel that refuses.
        let _ = config.set_max_write(1024 * 1024);
        let _ = self.layers.prepare();
        Ok(())
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Ok(parent_path) = self.path(parent) else {
            reply.error(libc::ENOENT);
            return;
        };
        let rel = match Layers::normalize(parent_path.join(name)) {
            Ok(rel) => rel,
            Err(_) => {
                reply.error(libc::EPERM);
                return;
            }
        };
        let ino = self.inodes.ino_for(&rel);
        match self.attr_of(&rel, ino) {
            Ok(attr) => reply.entry(&self.options.ttl, &attr, 0),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let Ok(rel) = self.path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.attr_of(&rel, ino) {
            Ok(attr) => reply.attr(&self.options.ttl, &attr),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Ok(rel) = self.path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let result = (|| -> Result<()> {
            if mode.is_none() && uid.is_none() && gid.is_none() && size.is_none() {
                return Ok(());
            }
            let upper = self.ensure_upper(&rel)?;
            if let Some(mode) = mode {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(mode & 0o7777))?;
            }
            if let Some(size) = size {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&upper)?
                    .set_len(size)?;
            }
            if let Some(t) = atime {
                // Best effort: not every filesystem honours explicit times.
                let _ = filetime_set(&upper, Some(time_or_now(t)), None);
            }
            if let Some(t) = mtime {
                let _ = filetime_set(&upper, None, Some(time_or_now(t)));
            }
            if uid.is_some() || gid.is_some() {
                // Report EPERM honestly rather than faking a chown: an
                // unprivileged FUSE mount cannot change ownership.
                let current_uid = uid.unwrap_or(self.options.uid);
                let current_gid = gid.unwrap_or(self.options.gid);
                if current_uid != self.options.uid || current_gid != self.options.gid {
                    return Err(Error::NotRoot("chown on a FUSE mount requires root"));
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => match self.attr_of(&rel, ino) {
                Ok(attr) => reply.attr(&self.options.ttl, &attr),
                Err(e) => reply.error(errno(&e)),
            },
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let Ok(rel) = self.path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.layers.resolve(&rel) {
            Ok(Resolved::Upper(p)) | Ok(Resolved::Lower(p)) => match std::fs::read_link(p) {
                Ok(target) => reply.data(target.as_os_str().to_string_lossy().as_bytes()),
                Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
            },
            Ok(Resolved::Missing) => reply.error(libc::ENOENT),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn mknod(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        let Ok(parent_path) = self.path(parent) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Ok(rel) = Layers::normalize(parent_path.join(name)) else {
            reply.error(libc::EPERM);
            return;
        };
        let result = (|| -> Result<()> {
            let upper = self.layers.upper().join(&rel);
            if let Some(p) = upper.parent() {
                std::fs::create_dir_all(p)?;
            }
            // A 0:0 character device is a whiteout, not a file to create.
            let file_type = mode & libc::S_IFMT;
            if file_type == libc::S_IFCHR && _rdev == 0 {
                self.layers.whiteout(&rel)?;
                return Ok(());
            }
            if file_type == libc::S_IFREG || file_type == 0 {
                std::fs::File::create(&upper)?;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(mode & 0o7777))?;
                return Ok(());
            }
            Err(Error::Unsupported(
                "the FUSE backend cannot create device nodes, fifos or sockets".into(),
            ))
        })();
        match result {
            Ok(()) => {
                let ino = self.inodes.ino_for(&rel);
                match self.attr_of(&rel, ino) {
                    Ok(attr) => reply.entry(&self.options.ttl, &attr, 0),
                    Err(e) => reply.error(errno(&e)),
                }
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Ok(parent_path) = self.path(parent) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Ok(rel) = Layers::normalize(parent_path.join(name)) else {
            reply.error(libc::EPERM);
            return;
        };
        let result = (|| -> Result<()> {
            let upper = self.layers.upper().join(&rel);
            if let Some(p) = upper.parent() {
                std::fs::create_dir_all(p)?;
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::create_dir_all(&upper)?;
            std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(mode & 0o7777))?;
            // Creating over a whiteout removes it.
            let marker = upper
                .parent()
                .unwrap_or(Path::new(""))
                .join(format!(".wh.{}", name.to_string_lossy()));
            let _ = std::fs::remove_file(marker);
            Ok(())
        })();
        match result {
            Ok(()) => {
                let ino = self.inodes.ino_for(&rel);
                match self.attr_of(&rel, ino) {
                    Ok(attr) => reply.entry(&self.options.ttl, &attr, 0),
                    Err(e) => reply.error(errno(&e)),
                }
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.remove_entry(parent, name, false, reply);
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.remove_entry(parent, name, true, reply);
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let Ok(parent_path) = self.path(parent) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Ok(rel) = Layers::normalize(parent_path.join(link_name)) else {
            reply.error(libc::EPERM);
            return;
        };
        let result = (|| -> Result<()> {
            let upper = self.layers.upper().join(&rel);
            if let Some(p) = upper.parent() {
                std::fs::create_dir_all(p)?;
            }
            let _ = std::fs::remove_file(&upper);
            std::os::unix::fs::symlink(target, &upper)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                let ino = self.inodes.ino_for(&rel);
                match self.attr_of(&rel, ino) {
                    Ok(attr) => reply.entry(&self.options.ttl, &attr, 0),
                    Err(e) => reply.error(errno(&e)),
                }
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Ok(parent_path), Ok(newparent_path)) = (self.path(parent), self.path(newparent))
        else {
            reply.error(libc::ENOENT);
            return;
        };
        let (Ok(from), Ok(to)) = (
            Layers::normalize(parent_path.join(name)),
            Layers::normalize(newparent_path.join(newname)),
        ) else {
            reply.error(libc::EPERM);
            return;
        };

        // RENAME_NOREPLACE and RENAME_EXCHANGE.
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;
        if flags & RENAME_EXCHANGE != 0 {
            reply.error(libc::ENOSYS);
            return;
        }

        let result = (|| -> Result<()> {
            if flags & RENAME_NOREPLACE != 0
                && !matches!(self.layers.resolve(&to)?, Resolved::Missing)
            {
                return Err(Error::Io(std::io::Error::from(
                    std::io::ErrorKind::AlreadyExists,
                )));
            }
            // Bring the source into the upper layer first: a lower-only entry
            // cannot be moved without copying it up.
            let source_upper = self.ensure_upper(&from)?;
            let dest_upper = self.layers.upper().join(&to);
            if let Some(p) = dest_upper.parent() {
                std::fs::create_dir_all(p)?;
            }
            // An existing lower-only destination must be whited out.
            if matches!(self.layers.resolve(&to)?, Resolved::Lower(_)) {
                self.layers.whiteout(&to)?;
            } else if dest_upper.exists() {
                let meta = std::fs::symlink_metadata(&dest_upper)?;
                if meta.is_dir() {
                    std::fs::remove_dir_all(&dest_upper)?;
                } else {
                    std::fs::remove_file(&dest_upper)?;
                }
            }
            std::fs::rename(&source_upper, &dest_upper)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.inodes.rename_subtree(&from, &to);
                reply.ok();
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn link(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let (Ok(source), Ok(newparent_path)) = (self.path(ino), self.path(newparent)) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Ok(dest) = Layers::normalize(newparent_path.join(newname)) else {
            reply.error(libc::EPERM);
            return;
        };
        let result = (|| -> Result<()> {
            // Hard links cannot span layers, so both ends must be in upper.
            let source_upper = self.ensure_upper(&source)?;
            let dest_upper = self.layers.upper().join(&dest);
            if let Some(p) = dest_upper.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::hard_link(&source_upper, &dest_upper)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                let dest_ino = self.inodes.ino_for(&dest);
                match self.attr_of(&dest, dest_ino) {
                    Ok(attr) => reply.entry(&self.options.ttl, &attr, 0),
                    Err(e) => reply.error(errno(&e)),
                }
            }
            // EXDEV is the honest answer when the source is in a lower layer.
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Ok(rel) = self.path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let host = match self.layers.resolve(&rel) {
            Ok(Resolved::Upper(p)) | Ok(Resolved::Lower(p)) => p,
            Ok(Resolved::Missing) => {
                reply.error(libc::ENOENT);
                return;
            }
            Err(e) => {
                reply.error(errno(&e));
                return;
            }
        };
        use std::io::{Read, Seek, SeekFrom};
        match std::fs::File::open(&host).and_then(|mut f| {
            f.seek(SeekFrom::Start(offset.max(0) as u64))?;
            let mut buf = vec![0u8; size as usize];
            let n = f.read(&mut buf)?;
            buf.truncate(n);
            Ok(buf)
        }) {
            Ok(buf) => reply.data(&buf),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let Ok(rel) = self.path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let result = (|| -> Result<usize> {
            // Copy up before writing so a lower-layer file is never modified.
            let upper = self.ensure_upper(&rel)?;
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new().write(true).open(&upper)?;
            file.seek(SeekFrom::Start(offset.max(0) as u64))?;
            file.write_all(data)?;
            Ok(data.len())
        })();
        match result {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Ok(parent_path) = self.path(parent) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Ok(rel) = Layers::normalize(parent_path.join(name)) else {
            reply.error(libc::EPERM);
            return;
        };
        let result = (|| -> Result<()> {
            let upper = self.layers.upper().join(&rel);
            if let Some(p) = upper.parent() {
                std::fs::create_dir_all(p)?;
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::File::create(&upper)?;
            std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(mode & 0o7777))?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                let ino = self.inodes.ino_for(&rel);
                match self.attr_of(&rel, ino) {
                    Ok(attr) => reply.created(&self.options.ttl, &attr, 0, 0, 0),
                    Err(e) => reply.error(errno(&e)),
                }
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Ok(rel) = self.path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let entries = match self.layers.list(&rel) {
            Ok(entries) => entries,
            Err(e) => {
                reply.error(errno(&e));
                return;
            }
        };

        // Entries are indexed from 1 so that offset 0 can carry "." and "..".
        let mut all: Vec<(String, FileType)> = vec![
            (".".to_string(), FileType::Directory),
            ("..".to_string(), FileType::Directory),
        ];
        for name in entries {
            let child = rel.join(&name);
            let kind = match self.layers.resolve(&child) {
                Ok(Resolved::Upper(p)) | Ok(Resolved::Lower(p)) => std::fs::symlink_metadata(p)
                    .map(|m| file_type_of(&m))
                    .unwrap_or(FileType::RegularFile),
                _ => FileType::RegularFile,
            };
            all.push((name, kind));
        }

        for (index, (name, kind)) in all.iter().enumerate().skip(offset.max(0) as usize) {
            let child_ino = if name == "." {
                ino
            } else if name == ".." {
                let parent = rel.parent().map(Path::to_path_buf).unwrap_or_default();
                self.inodes.ino_for(&parent)
            } else {
                self.inodes.ino_for(&rel.join(name))
            };
            // `add` returns true when the buffer is full and the entry was
            // dropped, which is the signal to stop.
            if reply.add(child_ino, (index + 1) as i64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        // Report the upper layer's statistics: that is the only layer whose
        // free space the caller can consume.
        match statvfs(self.layers.upper()) {
            Ok(s) => reply.statfs(
                s.blocks,
                s.bfree,
                s.bavail,
                s.files,
                s.ffree,
                s.bsize as u32,
                s.namemax as u32,
                s.bsize as u32,
            ),
            Err(_) => reply.statfs(0, 0, 0, 0, 0, 4096, 255, 4096),
        }
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, _mask: i32, reply: ReplyEmpty) {
        let Ok(rel) = self.path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        // Existence is all that is checked here; the kernel enforces the mode
        // bits because the mount uses `default_permissions`.
        match self.layers.resolve(&rel) {
            Ok(Resolved::Missing) => reply.error(libc::ENOENT),
            Ok(_) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }
}

impl UserFs {
    fn remove_entry(&mut self, parent: u64, name: &OsStr, directory: bool, reply: ReplyEmpty) {
        let Ok(parent_path) = self.path(parent) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Ok(rel) = Layers::normalize(parent_path.join(name)) else {
            reply.error(libc::EPERM);
            return;
        };
        let result = (|| -> Result<()> {
            match self.layers.resolve(&rel)? {
                Resolved::Missing => Err(Error::PathNotFound(rel.clone())),
                Resolved::Upper(p) => {
                    let meta = std::fs::symlink_metadata(&p)?;
                    if directory && !meta.is_dir() {
                        return Err(Error::Io(std::io::Error::from_raw_os_error(libc::ENOTDIR)));
                    }
                    if !directory && meta.is_dir() {
                        return Err(Error::Io(std::io::Error::from_raw_os_error(libc::EISDIR)));
                    }
                    if meta.is_dir() {
                        std::fs::remove_dir(&p)?;
                    } else {
                        std::fs::remove_file(&p)?;
                    }
                    Ok(())
                }
                Resolved::Lower(_) => {
                    if directory {
                        return Err(Error::Io(std::io::Error::from_raw_os_error(
                            libc::ENOTEMPTY,
                        )));
                    }
                    // Whiteout so the lower entry disappears from the view.
                    self.layers.whiteout(&rel)
                }
            }
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }
}

struct StatVfs {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u64,
    namemax: u64,
}

fn statvfs(path: &Path) -> Result<StatVfs> {
    let c_path = std::ffi::CString::new(path.as_os_str().to_string_lossy().as_bytes())
        .map_err(|_| Error::Config("path contains a NUL".into()))?;
    // SAFETY: `buf` is a correctly sized, zeroed struct and `c_path` is a
    // valid NUL-terminated string.
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut buf) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(StatVfs {
        blocks: buf.f_blocks,
        bfree: buf.f_bfree,
        bavail: buf.f_bavail,
        files: buf.f_files,
        ffree: buf.f_ffree,
        bsize: buf.f_bsize,
        namemax: buf.f_namemax,
    })
}

fn filetime_set(path: &Path, atime: Option<SystemTime>, mtime: Option<SystemTime>) -> Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().to_string_lossy().as_bytes())
        .map_err(|_| Error::Config("path contains a NUL".into()))?;
    let to_timespec = |t: Option<SystemTime>| -> libc::timespec {
        match t.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()) {
            Some(d) => libc::timespec {
                tv_sec: d.as_secs() as libc::time_t,
                tv_nsec: d.subsec_nanos() as libc::c_long,
            },
            None => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
        }
    };
    let times = [to_timespec(atime), to_timespec(mtime)];
    // SAFETY: `times` has the two elements utimensat expects.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// True when this device can mount FUSE at all.
pub fn fuse_available() -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata("/dev/fuse")
        .map(|m| m.file_type().is_char_device())
        .unwrap_or(false)
}

/// Mounts `fs` at `mountpoint` on a background thread.
///
/// The returned session must be kept alive; dropping it unmounts the
/// filesystem.  Fails with the underlying error when `/dev/fuse` is missing or
/// the mount point cannot be created.
pub fn mount(fs: UserFs, mountpoint: &Path, options: &UserFsOptions) -> Result<BackgroundSession> {
    if !fuse_available() {
        return Err(Error::Unsupported(
            "/dev/fuse is not available on this device".into(),
        ));
    }
    std::fs::create_dir_all(mountpoint)?;
    let mut mount_options = vec![
        MountOption::FSName("usersu".to_string()),
        MountOption::Subtype("userfs".to_string()),
        MountOption::DefaultPermissions,
        MountOption::NoSuid,
        MountOption::NoDev,
    ];
    if options.allow_other {
        mount_options.push(MountOption::AllowOther);
    }
    fuser::spawn_mount2(fs, mountpoint, &mount_options).map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use usersu_core::overlay::WhiteoutStyle;

    fn fixture() -> (TempDir, UserFs, PathBuf) {
        let root = TempDir::new().unwrap();
        let lower = root.path().join("lower");
        fs::create_dir_all(&lower).unwrap();
        let layers = Layers::new(
            root.path().join("upper"),
            root.path().join("work"),
            vec![lower.clone()],
            WhiteoutStyle::Marker,
        );
        layers.prepare().unwrap();
        (root, UserFs::with_defaults(layers), lower)
    }

    #[test]
    fn inode_table_keeps_paths_stable() {
        let mut table = InodeTable::new();
        let a = table.ino_for(Path::new("a"));
        assert_eq!(a, table.ino_for(Path::new("a")));
        assert_eq!(table.path_for(a), Some(Path::new("a")));
        assert_eq!(table.ino_for(Path::new("")), InodeTable::ROOT);
    }

    #[test]
    fn inode_table_rewrites_renamed_subtrees() {
        let mut table = InodeTable::new();
        let dir = table.ino_for(Path::new("old"));
        let child = table.ino_for(Path::new("old/child"));
        table.rename_subtree(Path::new("old"), Path::new("new"));
        assert_eq!(table.path_for(dir), Some(Path::new("new")));
        assert_eq!(table.path_for(child), Some(Path::new("new/child")));
        // The old path is gone, so a fresh inode is allocated if it reappears.
        assert_ne!(table.ino_for(Path::new("old")), dir);
    }

    #[test]
    fn attr_uses_configured_owner() {
        let (_root, fs, lower) = fixture();
        fs::write(lower.join("file"), b"data").unwrap();
        let options = UserFsOptions {
            uid: 0,
            gid: 0,
            ..Default::default()
        };
        let fs = UserFs::new(
            Layers::new(
                fs.layers.upper(),
                fs.layers.work(),
                vec![lower],
                WhiteoutStyle::Marker,
            ),
            options,
        );
        let attr = fs.attr_of(Path::new("file"), 42).unwrap();
        assert_eq!(attr.uid, 0);
        assert_eq!(attr.gid, 0);
        assert_eq!(attr.size, 4);
        assert!(matches!(attr.kind, FileType::RegularFile));
    }

    #[test]
    fn ensure_upper_copies_up_lower_files() {
        let (_root, fs, lower) = fixture();
        fs::write(lower.join("file"), b"lower").unwrap();
        let upper = fs.ensure_upper(Path::new("file")).unwrap();
        assert_eq!(fs::read(&upper).unwrap(), b"lower");
        assert_eq!(fs::read(lower.join("file")).unwrap(), b"lower");
    }

    #[test]
    fn errno_mapping_is_specific() {
        assert_eq!(
            errno(&Error::PathNotFound(PathBuf::from("/x"))),
            libc::ENOENT
        );
        assert_eq!(errno(&Error::PathEscape(PathBuf::from("/x"))), libc::EPERM);
        assert_eq!(
            errno(&Error::Io(std::io::Error::from(
                std::io::ErrorKind::AlreadyExists
            ))),
            libc::EEXIST
        );
        assert_eq!(
            errno(&Error::Io(std::io::Error::from(
                std::io::ErrorKind::DirectoryNotEmpty
            ))),
            libc::ENOTEMPTY
        );
    }

    #[test]
    fn fuse_availability_is_reported_not_assumed() {
        // On a machine without /dev/fuse this must be false, and mounting must
        // fail with a clear error rather than panicking.
        let available = fuse_available();
        let (_root, fs, _lower) = fixture();
        let result = mount(
            fs,
            Path::new("/tmp/usersu-test-mount"),
            &UserFsOptions::default(),
        );
        if available {
            // If a device node exists the mount may still be denied; either way
            // it must not panic.
            let _ = result;
        } else {
            assert!(matches!(result, Err(Error::Unsupported(_))));
        }
    }
}
