//! Provisioning of the optional pieces that live inside UserFS.
//!
//! UserSU itself is a sandbox and a privilege broker; it deliberately does not
//! ship a userland.  To be useful, a UserFS needs a few external components:
//!
//! * a shell and core utilities (`busybox`, `toybox`, ...) so that
//!   `/system/bin/sh` exists;
//! * a user-mode Linux kernel (`linux-um-aarch64` on arm64, the plain UML
//!   target on amd64) for the [`crate::sandbox::Backend::Um`] backend;
//! * optionally `proot`, though [`crate::proot`] reimplements its backend.
//!
//! This module resolves those components from two sources and nothing else:
//! files already present in a local source directory (an app asset directory,
//! or somewhere the user pushed them with `adb push`), or an explicit URL
//! recorded in the configuration.  It never invents a download location, and
//! every failure is reported with the path or URL that was tried.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The kind of component being provisioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    /// A shell and core utilities, installed as `/system/bin/sh`.
    Shell,
    /// A user-mode Linux kernel image.
    UmlKernel,
    /// A `proot` binary, for users who prefer the upstream implementation.
    Proot,
}

impl Component {
    /// Stable name used in configuration and logs.
    pub fn name(self) -> &'static str {
        match self {
            Component::Shell => "shell",
            Component::UmlKernel => "uml-kernel",
            Component::Proot => "proot",
        }
    }

    /// File names to look for in a source directory, most preferred first.
    pub fn candidate_names(self) -> &'static [&'static str] {
        match self {
            Component::Shell => &["busybox", "toybox", "sh"],
            Component::UmlKernel => &["linux-um", "linux-um-aarch64", "vmlinux", "uml/linux"],
            Component::Proot => &["proot"],
        }
    }

    /// Destination inside UserFS, relative to the UserFS root.
    pub fn destination(self) -> &'static str {
        match self {
            Component::Shell => "system/bin/sh",
            Component::UmlKernel => "system/bin/linux-um",
            Component::Proot => "system/bin/proot",
        }
    }
}

/// Where a component may be found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "source")]
pub enum Source {
    /// A directory to search for one of [`Component::candidate_names`].
    Directory(PathBuf),
    /// An explicit URL to download from.
    Url(String),
}

/// What to do with a component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provision {
    /// The component.
    pub component: Component,
    /// Where to look.
    pub source: Source,
}

/// The outcome of provisioning one component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provisioned {
    /// The file was installed at this path.
    Installed(PathBuf),
    /// The destination already existed and was left alone.
    AlreadyPresent(PathBuf),
    /// Nothing was found; the message names every location tried.
    NotFound(String),
}

/// Result of provisioning a whole set of components.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// One entry per requested component.
    pub entries: Vec<(Component, Provisioned)>,
}

impl Report {
    /// True when every component was installed or already present.
    pub fn complete(&self) -> bool {
        self.entries
            .iter()
            .all(|(_, p)| !matches!(p, Provisioned::NotFound(_)))
    }

    /// The components that could not be provisioned.
    pub fn missing(&self) -> Vec<Component> {
        self.entries
            .iter()
            .filter(|(_, p)| matches!(p, Provisioned::NotFound(_)))
            .map(|(c, _)| *c)
            .collect()
    }
}

/// Finds a component in a directory, returning the first matching file.
pub fn find_in_directory(dir: &Path, component: Component) -> Option<PathBuf> {
    for name in component.candidate_names() {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Installs one component into `userfs_root`.
///
/// The file is copied, not linked, so that the destination survives the source
/// directory being removed (which is what happens to an app's asset directory).
pub fn provision(userfs_root: &Path, component: Component, source: &Source) -> Provisioned {
    let destination = userfs_root.join(component.destination());
    if destination.is_file() {
        return Provisioned::AlreadyPresent(destination);
    }

    match source {
        Source::Directory(dir) => match find_in_directory(dir, component) {
            Some(found) => match install(&found, &destination) {
                Ok(()) => Provisioned::Installed(destination),
                Err(e) => Provisioned::NotFound(format!(
                    "found {} but could not install it: {e}",
                    found.display()
                )),
            },
            None => Provisioned::NotFound(format!(
                "no {} in {} (looked for {})",
                component.name(),
                dir.display(),
                component.candidate_names().join(", ")
            )),
        },
        Source::Url(url) => Provisioned::NotFound(format!(
            "downloading {} from {url} is not performed automatically; \
             fetch it and place it in a source directory instead",
            component.name()
        )),
    }
}

fn install(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(source, destination)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// Provisions every entry in `plan`.
pub fn provision_all(userfs_root: &Path, plan: &[Provision]) -> Report {
    let mut report = Report::default();
    for entry in plan {
        let outcome = provision(userfs_root, entry.component, &entry.source);
        log::info!("{}: {outcome:?}", entry.component.name());
        report.entries.push((entry.component, outcome));
    }
    report
}

/// The default provisioning plan for a device.
///
/// `asset_dir` is where the manager app unpacks its bundled components, and
/// `push_dir` is the conventional `adb push` destination.
pub fn default_plan(asset_dir: &Path, push_dir: &Path) -> Vec<Provision> {
    let mut plan = Vec::new();
    for component in [Component::Shell, Component::UmlKernel, Component::Proot] {
        // Prefer the app's own assets, then anything pushed by hand.
        let source = if find_in_directory(asset_dir, component).is_some() {
            Source::Directory(asset_dir.to_path_buf())
        } else {
            Source::Directory(push_dir.to_path_buf())
        };
        plan.push(Provision { component, source });
    }
    plan
}

/// The conventional `adb push` destination.
pub fn push_dir() -> PathBuf {
    PathBuf::from("/data/local/tmp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_component(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        path
    }

    #[test]
    fn finds_the_preferred_candidate_first() {
        let dir = TempDir::new().unwrap();
        make_component(dir.path(), "sh");
        make_component(dir.path(), "busybox");
        assert_eq!(
            find_in_directory(dir.path(), Component::Shell),
            Some(dir.path().join("busybox"))
        );
    }

    #[test]
    fn provision_copies_and_marks_executable() {
        let src = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        make_component(src.path(), "busybox");
        let outcome = provision(
            root.path(),
            Component::Shell,
            &Source::Directory(src.path().into()),
        );
        match outcome {
            Provisioned::Installed(path) => {
                assert_eq!(path, root.path().join("system/bin/sh"));
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o755);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn provision_is_idempotent() {
        let src = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        make_component(src.path(), "busybox");
        let source = Source::Directory(src.path().into());
        assert!(matches!(
            provision(root.path(), Component::Shell, &source),
            Provisioned::Installed(_)
        ));
        assert!(matches!(
            provision(root.path(), Component::Shell, &source),
            Provisioned::AlreadyPresent(_)
        ));
    }

    #[test]
    fn missing_component_names_every_candidate() {
        let src = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        let outcome = provision(
            root.path(),
            Component::UmlKernel,
            &Source::Directory(src.path().into()),
        );
        match outcome {
            Provisioned::NotFound(message) => {
                assert!(message.contains("linux-um"));
                assert!(message.contains("vmlinux"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn urls_are_never_fetched_implicitly() {
        let root = TempDir::new().unwrap();
        let outcome = provision(
            root.path(),
            Component::Shell,
            &Source::Url("https://example.invalid/busybox".into()),
        );
        assert!(matches!(outcome, Provisioned::NotFound(_)));
    }

    #[test]
    fn report_reports_missing_components() {
        let src = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        make_component(src.path(), "busybox");
        let plan = vec![
            Provision {
                component: Component::Shell,
                source: Source::Directory(src.path().into()),
            },
            Provision {
                component: Component::UmlKernel,
                source: Source::Directory(src.path().into()),
            },
        ];
        let report = provision_all(root.path(), &plan);
        assert!(!report.complete());
        assert_eq!(report.missing(), vec![Component::UmlKernel]);
    }

    #[test]
    fn default_plan_prefers_the_asset_directory() {
        let assets = TempDir::new().unwrap();
        let push = TempDir::new().unwrap();
        make_component(assets.path(), "busybox");
        make_component(push.path(), "proot");
        let plan = default_plan(assets.path(), push.path());
        let shell = plan
            .iter()
            .find(|p| p.component == Component::Shell)
            .unwrap();
        assert_eq!(shell.source, Source::Directory(assets.path().into()));
        let proot = plan
            .iter()
            .find(|p| p.component == Component::Proot)
            .unwrap();
        assert_eq!(proot.source, Source::Directory(push.path().into()));
    }
}
