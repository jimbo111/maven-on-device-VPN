#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_ROOT/rust/packet_engine"
FRAMEWORKS_DIR="$PROJECT_ROOT/maven/Frameworks"
BRIDGE_DIR="$PROJECT_ROOT/maven/PacketTunnelExtension/Bridge"

TARGET="${1:-aarch64-apple-ios}"

# The Xcode "Select Rust Library" phase reads per-platform subdirectories,
# so place the artifact where the build system actually looks.
case "$TARGET" in
    aarch64-apple-ios)     PLATFORM_DIR="ios-arm64" ;;
    aarch64-apple-ios-sim) PLATFORM_DIR="ios-arm64-simulator" ;;
    *)
        echo "Unsupported target: $TARGET (expected aarch64-apple-ios or aarch64-apple-ios-sim)" >&2
        exit 1
        ;;
esac

# Pin the target dir so a global CARGO_TARGET_DIR doesn't move the artifacts
# away from the paths we copy from (build.rs also writes the header there).
export CARGO_TARGET_DIR="$RUST_DIR/target"

echo "Building Rust packet_engine for target: $TARGET"
cd "$RUST_DIR"
cargo build --target "$TARGET" --release

echo "Copying artifacts..."
mkdir -p "$FRAMEWORKS_DIR/$PLATFORM_DIR" "$BRIDGE_DIR"
cp "$CARGO_TARGET_DIR/$TARGET/release/libpacket_engine.a" "$FRAMEWORKS_DIR/$PLATFORM_DIR/"

# Copy header if it exists
if [ -f "$CARGO_TARGET_DIR/packet_engine.h" ]; then
    cp "$CARGO_TARGET_DIR/packet_engine.h" "$BRIDGE_DIR/"
fi

echo "Done. Library: $FRAMEWORKS_DIR/$PLATFORM_DIR/libpacket_engine.a"
