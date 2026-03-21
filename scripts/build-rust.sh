#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_ROOT/rust/packet_engine"
FRAMEWORKS_DIR="$PROJECT_ROOT/maven/Frameworks"
BRIDGE_DIR="$PROJECT_ROOT/maven/PacketTunnelExtension/Bridge"

TARGET="${1:-aarch64-apple-ios}"

echo "Building Rust packet_engine for target: $TARGET"
cd "$RUST_DIR"
cargo build --target "$TARGET" --release

echo "Copying artifacts..."
mkdir -p "$FRAMEWORKS_DIR" "$BRIDGE_DIR"
cp "target/$TARGET/release/libpacket_engine.a" "$FRAMEWORKS_DIR/"

# Copy header if it exists
if [ -f "target/packet_engine.h" ]; then
    cp "target/packet_engine.h" "$BRIDGE_DIR/"
fi

echo "Done. Library: $FRAMEWORKS_DIR/libpacket_engine.a"
