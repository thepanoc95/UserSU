# UserSU

<img width="100" height="100" alt="UserSU Logo" src="./usersu_logo.png" />

A userspace root environment for Android, written in Rust.

[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-blue.svg)](http://unlicense.org/)
[![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-orange.svg)](https://www.rust-lang.org/)

## What this is

UserSU gives an Android device a root-like environment without unlocking the
bootloader or flashing a boot image. It combines three things:

1. **A privilege broker.** A backend daemon, `usud`, decides which apps may run
   commands as root, and by what means. It can delegate to a real root solution
   that is already installed, attempt a kernel exploit, or fall back to running
   everything unprivileged in a sandbox.
2. **Layered root filesystems.** UserFS is an overlay: a writable upper layer
   over one or more read-only lower layers, with whiteouts and copy-up. A
   profile is one such stack, so a device can carry several isolated roots.
3. **Sandboxes.** A command or an init system runs inside a user-mode Linux
   kernel, a `pivot_root(2)`/`chroot(2)` jail, or a ptrace-based proot that
   needs no privileges at all.

It is honest about what it can do. Every privileged operation probes for the
capability it needs and reports why it failed. It never fabricates a successful
escalation.

## Layout

| Path | Purpose | Needs root |
| --- | --- | --- |
| `/userfs` | UserFS root, a real mount point | yes |
| `/data/me.usersu` | Upper and work directories; the daemon socket | yes |
| `/user_system` | Optional read-write system layer | yes |
| `/data/data/me.usersu/files/mnt/userfs` | FUSE fallback mount for UserFS | no |

When the device cannot create and mount `/userfs`, `usud` serves the exact same
tree through FUSE under the app's files directory. The `su` entry point exists in
both trees:

```
/userfs/system/bin/su
/data/data/me.usersu/files/mnt/userfs/system/bin/su
```

Both are symlinks to `usud`, which selects `su` mode either from that symlink
name or from the `-root.me` argument.

## The components

| Crate / module | Role |
| --- | --- |
| `usersu-core` | Paths, configuration, the layer stack, privilege providers, sandbox selection, proot, `su` policy, and the wire protocol |
| `usud` | The backend daemon: `su`, the FUSE UserFS, the IPC server, and the sandbox executors |
| `usud-init` | A minimal PID 1 for a sandboxed init system |
| `manager/` | The Android manager app, Jetpack Compose |

## How usud is invoked

```
usud <subcommand>      # CLI: daemon, status, providers, shell, exec, install, ...
usud -root.me [args]   # su
usud su [args]         # the same thing, spelled explicitly
su -> usud             # a symlink; usud detects its argv[0]
```

Common commands:

```sh
usud daemon            # run the backend in the foreground
usud status            # daemon and device status
usud providers         # which privilege providers are usable, and why
usud install           # write usud and the su entry point into UserFS
usud shell             # a root shell inside UserFS
usud exec -- id         # run one command
usud boot              # start the sandboxed init system
usud profile list      # list profiles
usud stop              # stop the daemon
```

## Building

The backend builds for the host, which is what the tests use:

```sh
cargo build --workspace
cargo test --workspace
```

For Android, use the NDK, for example:

```sh
cargo ndk -t arm64-v8a build --release --bin usud --bin usud-init
```

The manager app needs the Android SDK and Gradle:

```sh
cd manager && gradle :app:assembleDebug
```

The workspace also uses a `justfile`: `just test`, `just check`, `just android`,
`just manager`.

## Filesystem backends

`userfs_backend` selects how UserFS is served:

* `auto` picks overlayfs when root is available and FUSE otherwise;
* `overlayfs` mounts `/userfs`, `/data/me.usersu` and `/user_system` via the
  overlayfs metamodule, and refuses to pretend when it cannot;
* `fuse` always serves the tree through FUSE.

## Sandbox backends

`sandbox_backend` selects how a command or init system runs:

* `um` boots a user-mode Linux kernel (`linux-um-aarch64` on arm64, UML on
  amd64) with UserFS as its root via hostfs;
* `pivot_root` bind-mounts UserFS and pivots into it;
* `chroot` chroots into UserFS with the pseudo-filesystems mounted;
* `proot` rewrites paths with `ptrace` and needs no privileges;
* `auto` chooses the strongest backend the device supports.

## Privilege providers

`privilege_mode` and `privilege_order` control acquisition. Providers are probed
in order:

* `existing-root` uses the daemon's own root if it has it;
* `magisk`, `kernelsu`, `apatch` delegate to a root solution already installed;
* `kernel-exploit` attempts a kernel exploit.

`privilege_mode = "none"` disables all of it and runs everything in the FUSE
sandbox.

## Configuration

`usud` reads `usersu.toml` from the data directory. It carries the backend
choices, the sandbox and init commands, the profile list, and the `allowed_uids`
and `denied_uids` access lists. `usud status` and the manager app's Settings tab
show the running values.

The manager app speaks the same framed protocol as the CLI, in JSON rather than
bincode, over the daemon socket.

## The protocol

Every message is a 4-byte little-endian length followed by a payload. `usud`
accepts bincode (the CLI and `su`) and JSON (the manager app) and pins the
encoding of a connection at the handshake. Responses are tagged JSON documents,
so a client can parse them without a bincode implementation.

## Status

This is a from-scratch rewrite and is under active development. The core, the
daemon, the FUSE backend, proot, and the init system are implemented and tested
on the host; the manager app is written to spec but has not been built here,
because the Android SDK is not available in this environment.

## License

Unlicense - public domain. Do whatever you want with it, no attribution needed
(but appreciated).

---

**Heads up:** This is for educational and development purposes. Don't use it to
bypass security on apps where you shouldn't have root access. Be responsible.
