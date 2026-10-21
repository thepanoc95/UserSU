//! UserSU configuration, persisted as `usersu.toml` inside the data directory.

use crate::error::{Error, Result};
use crate::paths;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Which privilege-acquisition strategy usud should try first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PrivilegeMode {
    /// Probe each provider in configured order, first success wins.
    #[default]
    Auto,
    /// Only use kernel exploits.
    KernelExploit,
    /// Only delegate to another root solution (Magisk, KernelSU, APatch, ...).
    RootSolution,
    /// Never elevate; run everything unprivileged in the FUSE sandbox.
    None,
}

/// Sandbox backend used to run an init system or a command tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxBackend {
    /// Pick the strongest backend the device supports.
    #[default]
    Auto,
    /// Boot a user-mode Linux kernel (linux-um-aarch64 on arm64, UML on amd64).
    Um,
    /// `chroot(2)` into UserFS.
    Chroot,
    /// `pivot_root(2)` into UserFS, falling back to `chroot`.
    PivotRoot,
    /// proot-style ptrace path rewriting; requires no privileges at all.
    Proot,
}

/// How the UserFS tree is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UserfsBackend {
    /// Overlayfs mount at `/userfs` plus `/data/me.usersu` and `/user_system`.
    #[default]
    Auto,
    /// Real mount points only.
    Overlayfs,
    /// FUSE only, mounted at `.../files/mnt/userfs`.
    Fuse,
}

/// A named UserFS profile.  Profiles let one device carry several isolated
/// root filesystems that the manager app can switch between.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Profile name; `default` is created on first run.
    pub name: String,
    /// Overlayfs upper directory, relative to the data directory.
    #[serde(default = "default_upper")]
    pub upper: String,
    /// Overlayfs work directory, relative to the data directory.
    #[serde(default = "default_work")]
    pub work: String,
    /// Read-only lower layers, absolute on-device paths.
    #[serde(default)]
    pub lower: Vec<PathBuf>,
    /// Whether this profile exposes the optional read-write `/user_system`.
    #[serde(default)]
    pub rw_user_system: bool,
    /// Whether this profile is the one usud activates at startup.
    #[serde(default)]
    pub active: bool,
}

fn default_upper() -> String {
    "upper".to_string()
}

fn default_work() -> String {
    "work".to_string()
}

impl Profile {
    /// Creates the default profile with `name` and no lower layers.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            upper: default_upper(),
            work: default_work(),
            lower: Vec::new(),
            rw_user_system: false,
            active: false,
        }
    }

    /// Resolves the upper directory against `data_dir`.
    pub fn upper_dir(&self, data_dir: &Path) -> PathBuf {
        data_dir.join(&self.upper)
    }

    /// Resolves the work directory against `data_dir`.
    pub fn work_dir(&self, data_dir: &Path) -> PathBuf {
        data_dir.join(&self.work)
    }
}

/// Top level configuration document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Schema version, bumped when the layout changes incompatibly.
    pub version: u32,
    /// Filesystem backend preference.
    pub userfs_backend: UserfsBackend,
    /// Privilege acquisition preference.
    pub privilege_mode: PrivilegeMode,
    /// Provider names to try, in order, for [`PrivilegeMode::Auto`].
    pub privilege_order: Vec<String>,
    /// Sandbox backend preference.
    pub sandbox_backend: SandboxBackend,
    /// Command used as PID 1 when booting a sandboxed init system.
    pub init_command: String,
    /// Extra arguments passed to the init command.
    pub init_args: Vec<String>,
    /// Mount options forwarded to the overlayfs metamodule.
    pub overlay_options: String,
    /// Profiles known to this device.
    pub profiles: Vec<Profile>,
    /// UIDs allowed to talk to usud over IPC without a prompt.
    pub allowed_uids: Vec<u32>,
    /// UIDs that should always be denied.
    pub denied_uids: Vec<u32>,
    /// Whether usud should log at debug level.
    pub debug: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            userfs_backend: UserfsBackend::Auto,
            privilege_mode: PrivilegeMode::Auto,
            privilege_order: vec![
                "existing-root".to_string(),
                "magisk".to_string(),
                "kernelsu".to_string(),
                "apatch".to_string(),
                "kernel-exploit".to_string(),
            ],
            sandbox_backend: SandboxBackend::Auto,
            init_command: "/userfs/system/bin/usud-init".to_string(),
            init_args: Vec::new(),
            overlay_options: "index=off,metacopy=off,redirect_dir=off".to_string(),
            profiles: vec![{
                let mut p = Profile::new("default");
                p.active = true;
                p
            }],
            allowed_uids: Vec::new(),
            denied_uids: Vec::new(),
            debug: false,
        }
    }
}

impl Config {
    /// Loads configuration from `path`, returning defaults when it is absent.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Parses configuration from a TOML string.
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Serializes configuration back to TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))
    }

    /// Writes configuration to `path`, creating parent directories.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_toml()?)?;
        Ok(())
    }

    /// Rejects configurations that cannot be honoured.
    pub fn validate(&self) -> Result<()> {
        if self.profiles.is_empty() {
            return Err(Error::Config("at least one profile is required".into()));
        }
        let active = self.profiles.iter().filter(|p| p.active).count();
        if active > 1 {
            return Err(Error::Config(
                "at most one profile may be marked active".into(),
            ));
        }
        for p in &self.profiles {
            if p.name.is_empty() {
                return Err(Error::Config("profile name must not be empty".into()));
            }
            if p.upper.starts_with('/') || p.work.starts_with('/') {
                return Err(Error::Config(format!(
                    "profile '{}' must use data-directory relative upper/work paths",
                    p.name
                )));
            }
        }
        for uid in &self.allowed_uids {
            if self.denied_uids.contains(uid) {
                return Err(Error::Config(format!(
                    "uid {uid} is both allowed and denied"
                )));
            }
        }
        Ok(())
    }

    /// Returns the active profile, falling back to the first one.
    pub fn active_profile(&self) -> &Profile {
        self.profiles
            .iter()
            .find(|p| p.active)
            .unwrap_or(&self.profiles[0])
    }

    /// Convenience: absolute path of the config file for the active layout.
    ///
    /// Honours [`paths::DATA_DIR_ENV`] so tests and unusual installs can move
    /// the data directory.
    pub fn default_path() -> PathBuf {
        let layout = crate::paths::detect_layout(crate::privilege::has_root());
        crate::paths::data_dir(layout).join(paths::CONFIG_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrips_through_toml() {
        let cfg = Config::default();
        let text = cfg.to_toml().unwrap();
        let parsed = Config::parse(&text).unwrap();
        assert_eq!(parsed.version, cfg.version);
        assert_eq!(parsed.profiles.len(), 1);
        assert!(parsed.active_profile().active);
        assert_eq!(parsed.privilege_mode, PrivilegeMode::Auto);
    }

    #[test]
    fn missing_file_yields_defaults() {
        let cfg = Config::load(Path::new("/nonexistent/usersu.toml")).unwrap();
        assert_eq!(cfg.version, 1);
    }

    #[test]
    fn rejects_absolute_profile_dirs() {
        let mut cfg = Config::default();
        cfg.profiles[0].upper = "/upper".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_conflicting_uid_rules() {
        let cfg = Config {
            allowed_uids: vec![1000],
            denied_uids: vec![1000],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_two_active_profiles() {
        let mut cfg = Config::default();
        let mut second = Profile::new("second");
        second.active = true;
        cfg.profiles.push(second);
        assert!(cfg.validate().is_err());
    }
}
