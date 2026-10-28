# AGENTS.md

Repository-specific notes for working on UserSU.

## What this is

UserSU ("SpoofySu") is a userspace root environment for Android, written in
Rust. The workspace has three crates plus an Android app:

* `usersu-core` — no daemon and no root required; all filesystem, policy,
  protocol and sandbox-selection logic lives here so it can be unit tested on a
  developer machine. Privileged entry points live in `modules` and the root-only
  branches of `sandbox`, and report `Error::NotRoot` rather than pretending.
* `usud` — the backend binary. `main.rs` dispatches the CLI, `su` mode and the
  daemon; `ipc.rs` is the framed protocol server; `runner.rs` selects and spawns
  sandboxes; `fuse_fs.rs` serves the UserFS fallback; `userfs.rs` builds the
  layer stacks.
* `usud-init` — a minimal PID 1 for a sandboxed init system.
* `manager/` — the Android manager app (Kotlin, Jetpack Compose).

## Build and test

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --workspace
env -u USERSU_DATA_DIR -u USERSU_SOCKET cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

CI (`.github/workflows/test.yml`) runs exactly those four steps, so keep the tree
formatted and clippy-clean. The `justfile` wraps the same commands.

Tests must not depend on the developer's environment: several test failures in
the past came from a shell exporting `USERSU_DATA_DIR`, which is why the test
commands clear it. Always run the suite with `env -u USERSU_DATA_DIR -u
USERSU_SOCKET`.

## Environment constraints

* `/dev/fuse` cannot be created in the sandbox used for development (no
  `CAP_MKNOD`). FUSE code compiles and is linked, but mounting is not possible;
  the **directory-backed fallback** is what the tests exercise. Do not write a
  test that requires a real mount.
* There is no Android SDK, JDK or Gradle here, so `manager/` cannot be built.
  It is written to spec; validate changes by review, not by compiling. The
  Gradle wrapper JAR is a binary and is not committed, so the manager is built
  with a system `gradle`, not `./gradlew`, unless the wrapper is generated.
* The backend almost never has real root here, so the active backend is Proot
  and the active layout is Fuse. Magisk, KernelSU, APatch and kernel exploits
  are all correctly reported unavailable.

## Protocol

`usersu-core/src/protocol.rs` defines framing and message types. Framing is a
4-byte little-endian length followed by the payload. `usud` accepts two payload
encodings and pins one per connection at the handshake:

* **bincode** for the `usud` CLI and the `su` path;
* **JSON** for the manager app, which has no bincode implementation.

Requests are serde-tagged documents (unit variants are bare strings, struct
variants are `{"tag":{...}}`) and field names stay `snake_case`. Responses are
the tagged documents from `Response::to_json`. A Rust `Vec<u8>` is a JSON array
of numbers. When the protocol changes, refit the Kotlin mirror in
`manager/app/src/main/java/me/usersu/manager/data/Protocol.kt`.

`handle_connection` sniffs the handshake by trying bincode first, then JSON.
Keep that property when adding message types.

## Hard-won details

* **SCM_RIGHTS fd passing.** `send_fds` sends one ordinary byte alongside the
  descriptors. A zero-length `sendmsg` on a stream socket does not reliably
  deliver ancillary data. The receiver consumes that byte; it is not part of the
  framed protocol.
* **proot path translation.** `proot.rs` intercepts path syscalls at ptrace
  stops and rewrites the arguments. `PathSyscall` carries a `dirfd_arg`, so
  `openat`-family calls resolve relative names against the descriptor's
  directory rather than always the working directory. `statx` (and the stat
  family) is intercepted so `ls` works. The x86_64 and aarch64 syscall tables
  were written by hand with verified numbers and dirfd indices; check both when
  adding a syscall.
* **su policy.** Access is decided by the kernel-reported peer uid, never by
  anything the client sent. `allowed_uids`/`denied_uids` are validated to be
  disjoint. When a uid is not allowed the daemon says so explicitly; tests must
  set `allowed_uids` to the running uid to exercise the allowed path.

## Conventions

* Keep comments for non-obvious invariants, workarounds and deliberate
  trade-offs. Do not narrate the code or the change history.
* Prefer minimal, focused changes and real code paths in tests over mocks.
* The layout constants and the `Layout` enum live in `usersu-core/src/paths.rs`;
  use them rather than new path string literals.
