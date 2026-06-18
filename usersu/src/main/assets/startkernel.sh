#!/system/bin/sh
# UserSU Usermode Kernel Entry Point
# Usage: startkernel.sh [kernel options] [init=program]
#
# Accepts standard Linux kernel command-line arguments:
#   init=/path/to/init    - Path to init process (default: /system/bin/sh)
#   root=/dev/block/...   - Root filesystem device
#   ro                    - Mount root read-only
#   rw                    - Mount root read-write
#   console=tty...        - Console device
#   -s, S, single         - Single user mode
#   quiet                 - Reduce kernel output
#   androidboot.*         - Android boot properties
#   boot_device=...       - Boot device

APP_DIR="/data/data/dev.github.thepanoc95.usersu/files"
BIN_DIR="$APP_DIR/bin"
LOCAL_DIR="/data/local/tmp/usersu"
KERNEL_CMDLINE=""

echo "[UserSU] Usermode Kernel v2.0 starting..."
echo "[UserSU] Kernel command line: $*"

# Parse kernel arguments into cmdline format
KERNEL_CMDLINE="$*"

# 1. Initialize kernel environment
mkdir -p "$LOCAL_DIR/bin" "$LOCAL_DIR/lib" "$LOCAL_DIR/branches" "$LOCAL_DIR/active"

# 2. Sync binaries
for f in proot psu psudo su start.sh startkernel.sh; do
    if [ -f "$BIN_DIR/$f" ]; then
        cp "$BIN_DIR/$f" "$LOCAL_DIR/bin/$f"
        chmod 755 "$LOCAL_DIR/bin/$f"
    fi
done

if [ -f "$APP_DIR/lib/libusersuhook.so" ]; then
    cp "$APP_DIR/lib/libusersuhook.so" "$LOCAL_DIR/lib/libusersuhook.so"
    chmod 644 "$LOCAL_DIR/lib/libusersuhook.so"
fi

# 3. Load the usermode kernel native library
export CLASSPATH="/data/data/dev.github.thepanoc95.usersu/files/bin/usersu-server.dex"

# 4. Bootstrap the kernel via app_process
# The kernel initialization happens via the JNI bridge in the server
exec /system/bin/app_process \
    -Djava.class.path="$CLASSPATH" \
    /system/bin \
    dev.github.thepanoc95.usersu.server.UserSUServer \
    --kernel "$KERNEL_CMDLINE" \
    2>&1
