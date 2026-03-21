#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_ROOT/rust/packet_engine"
FRAMEWORKS_DIR="$PROJECT_ROOT/maven/Frameworks"
BRIDGE_DIR="$PROJECT_ROOT/maven/PacketTunnelExtension/Bridge"

echo "Building Rust packet_engine for device and simulator..."

cd "$RUST_DIR"
cargo build --target aarch64-apple-ios --release
cargo build --target aarch64-apple-ios-sim --release

echo "Copying artifacts..."
mkdir -p "$FRAMEWORKS_DIR/ios-arm64" "$FRAMEWORKS_DIR/ios-arm64-simulator" "$BRIDGE_DIR"

cp "target/aarch64-apple-ios/release/libpacket_engine.a" \
   "$FRAMEWORKS_DIR/ios-arm64/"
cp "target/aarch64-apple-ios-sim/release/libpacket_engine.a" \
   "$FRAMEWORKS_DIR/ios-arm64-simulator/"

# Copy simulator lib as default for development
cp "target/aarch64-apple-ios-sim/release/libpacket_engine.a" \
   "$FRAMEWORKS_DIR/libpacket_engine.a"

# Copy generated header
cp "target/packet_engine.h" "$BRIDGE_DIR/"

echo "Done."
echo "  Device lib:    $FRAMEWORKS_DIR/ios-arm64/libpacket_engine.a"
echo "  Simulator lib: $FRAMEWORKS_DIR/ios-arm64-simulator/libpacket_engine.a"
echo "  Header:        $BRIDGE_DIR/packet_engine.h"
