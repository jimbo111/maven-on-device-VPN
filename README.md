# Maven

An iOS app that shows you every domain your device connects to. Everything runs on-device.

It sets up a local VPN tunnel, intercepts DNS queries, and stores the domain names in SQLite. Your internet works normally — Maven just watches.

## How it works

```
App traffic → Local VPN tunnel → Rust packet engine → SQLite
                                 (parses DNS)         (on-device)
```

1. **Rust packet engine** — extracts domains from DNS queries, groups CDN domains to parent sites, writes to SQLite
2. **Network Extension** — `NEPacketTunnelProvider` intercepts DNS and forwards to real DNS servers
3. **SwiftUI app** — reads the database, shows domains/stats/categories

## Use cases

- See what your phone is connecting to in real time
- Spot apps reaching out to unexpected trackers or analytics
- Learn how DNS works with live queries
- Understand your device's network behavior

## Getting started

```bash
# 1. Install Rust iOS targets
rustup target add aarch64-apple-ios aarch64-apple-ios-sim

# 2. Build the Rust library
./scripts/build-universal.sh

# 3. Open in Xcode
open maven/maven.xcodeproj
```

Set your dev team in Signing & Capabilities for both `maven` and `PacketTunnelExtension` targets, then run on a physical iPhone (tunnel doesn't work on Simulator).

## Testing

```bash
cd rust/packet_engine && cargo test
```

## Privacy

All packet analysis runs locally. Domain history stays on-device. No analytics, no tracking, no remote servers. DNS queries are forwarded to 8.8.8.8 for resolution.

## License

MIT
