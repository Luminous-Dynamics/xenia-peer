#!/usr/bin/env bash
# Build the JNI C glue layer (xenia_jni.c) into libxenia_jni.so, plus
# the Rust cdylib (libxenia_mobile_ffi.so) it links against.
#
# Prerequisites: ANDROID_NDK_HOME set (nix develop --impure provides
# this, see flake.nix).
#
# Output: src/main/jniLibs/arm64-v8a/libxenia_jni.so
#         src/main/jniLibs/arm64-v8a/libxenia_mobile_ffi.so

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
JNILIBS="$SCRIPT_DIR/src/main/jniLibs/arm64-v8a"
TARGET="aarch64-linux-android"
API="${ANDROID_API_LEVEL:-24}"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ERROR: ANDROID_NDK_HOME not set. Run: nix develop --impure"
    exit 1
fi

NDK_TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
CC="$NDK_TOOLCHAIN/bin/aarch64-linux-android${API}-clang"

mkdir -p "$JNILIBS"

# Step 1: Build the Rust cdylib.
echo "=== Building Rust libxenia_mobile_ffi.so ==="
cd "$WORKSPACE/.."
export CC_aarch64_linux_android="$CC"
export AR_aarch64_linux_android="$NDK_TOOLCHAIN/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC"
# 16KB page alignment: recent Android (15+) devices can run with a
# 16KB kernel page size, which requires every loaded .so's ELF LOAD
# segments to be aligned to 16KB, not the traditional 4KB. Without
# this, `adb install` on such a device (or the Play Console's own
# check) flags the library and can refuse to run it. Matches the same
# fix already applied to the JNI C shim below.
export RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"
cargo build --target "$TARGET" --release -p xenia-mobile-ffi

# Ask cargo where it actually put the output rather than assuming
# ./target -- this project's session tooling redirects
# CARGO_TARGET_DIR to a per-session cache dir (see root CLAUDE.md
# Rule 5), so a hardcoded relative path silently finds nothing there.
CARGO_TARGET_ROOT="$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')"
RUST_SO="$CARGO_TARGET_ROOT/$TARGET/release/libxenia_mobile_ffi.so"

cp "$RUST_SO" "$JNILIBS/libxenia_mobile_ffi.so"
echo "  Copied: libxenia_mobile_ffi.so ($(du -h "$JNILIBS/libxenia_mobile_ffi.so" | cut -f1))"

# Step 2: Compile the JNI C glue, linked against the Rust .so above.
echo "=== Building JNI glue (xenia_jni.c) ==="
"$CC" -shared -o "$JNILIBS/libxenia_jni.so" \
    -I"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include" \
    "$SCRIPT_DIR/src/main/cpp/xenia_jni.c" \
    -L"$JNILIBS" -lxenia_mobile_ffi \
    -llog \
    -fPIC -O2 -Wall -Werror \
    -Wl,-z,max-page-size=16384

echo "  Built:  libxenia_jni.so ($(du -h "$JNILIBS/libxenia_jni.so" | cut -f1))"

echo ""
echo "=== JNI build complete ==="
ls -lh "$JNILIBS/"
