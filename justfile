# Build the release backend (usud) and its PID1 companion.
default:
    cargo build --release --bin usud --bin usud-init

# Build every crate for the host.
host:
    cargo build --workspace

# Run the whole workspace test suite in a clean environment.
test:
    env -u USERSU_DATA_DIR -u USERSU_SOCKET cargo test --workspace

# Lint and format check.
check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

# Build usud for an Android target; pass the triple, e.g. `just android aarch64-linux-android`.
android target='aarch64-linux-android':
    cargo ndk -t {{target}} build --release --bin usud --bin usud-init

# Build the manager app (needs the Android SDK and Gradle on PATH).
manager:
    cd manager && gradle :app:assembleDebug

# Generate the Gradle wrapper (needs Gradle on PATH). The wrapper JAR is a
# binary and is not committed, so this is a one-off step per checkout.
wrapper:
    cd manager && gradle wrapper

# Clean build artefacts.
clean:
    cargo clean
