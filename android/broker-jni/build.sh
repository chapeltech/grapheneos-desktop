#!/usr/bin/env bash
# Build the private Rust bridge; this does not install privileged OS code.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
case "${1:-host}" in
    host)
        export CARGO_TARGET_DIR="$root/android/out/broker-jni"
        cargo test --locked --manifest-path "$root/android/broker-rust/Cargo.toml"
        cargo clippy --locked --manifest-path "$root/android/broker-rust/Cargo.toml" --all-targets -- -D warnings
        cargo test --locked --manifest-path "$root/android/broker-jni/Cargo.toml"
        cargo clippy --locked --manifest-path "$root/android/broker-jni/Cargo.toml" --all-targets -- -D warnings
        cargo build --locked --release --manifest-path "$root/android/broker-jni/Cargo.toml"
        echo "Host JNI library: $CARGO_TARGET_DIR/release/libwonad_broker_jni.so"
        ;;
    android)
        : "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to the pinned Android NDK r30}"
        abi=${WONAD_ANDROID_ABI:-x86_64}
        case "$abi" in
            x86_64) rust_target=x86_64-linux-android; env_target=X86_64_LINUX_ANDROID;;
            arm64-v8a) rust_target=aarch64-linux-android; env_target=AARCH64_LINUX_ANDROID;;
            *) echo 'Unsupported Android ABI' >&2; exit 2;;
        esac
        ndk_tools="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
        test -x "$ndk_tools/${rust_target}35-clang"
        export CARGO_TARGET_DIR="$root/android/out/broker-jni-android"
        export "CARGO_TARGET_${env_target}_LINKER=$ndk_tools/${rust_target}35-clang"
        export "CARGO_TARGET_${env_target}_RUSTFLAGS=-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,defs"
        cargo build --locked --release --target "$rust_target" \
            --manifest-path "$root/android/broker-jni/Cargo.toml"
        python3 "$root/android/tools/check_native.py" --abi "$abi" --profile broker \
            --readelf "$ndk_tools/llvm-readelf" \
            "$CARGO_TARGET_DIR/$rust_target/release/libwonad_broker_jni.so"
        install -D -m 0644 "$CARGO_TARGET_DIR/$rust_target/release/libwonad_broker_jni.so" \
            "$root/android/out/broker-native/$abi/libwonad_broker_jni.so"
        ;;
    *) echo 'Usage: build.sh host|android' >&2; exit 2 ;;
esac
