# Maven

A local-only iOS app that shows you every domain your device connects to. All processing happens on-device — nothing leaves your phone.

Maven sets up a local VPN tunnel to intercept DNS queries, pulls out the domain names, and stores them in SQLite. You get full visibility into what your phone is talking to, without any data going to a remote server.

## How it works

```
App traffic  →  Local VPN tunnel  →  Rust packet engine  →  SQLite (on-device)
                                     (DNS parsing)

DNS queries are forwarded to a real DNS server (8.8.8.8).
Your internet works normally — Maven just observes.
```

Three layers:

1. **Rust packet engine** — parses raw IP packets, extracts domain names from DNS queries, maps them to parent sites, and writes to SQLite. Compiled as a C static library for iOS.
2. **Network Extension** — `NEPacketTunnelProvider` that intercepts DNS traffic, hands packets to the Rust engine, and forwards them for resolution.
3. **SwiftUI app** — reads the database and shows domains, categories, and stats.

## Use cases

- **See what your phone connects to** — find out which domains your apps are hitting in real time
- **Spot unexpected connections** — notice if an app is reaching out to trackers, analytics, or domains you didn't expect
- **Learn how DNS works** — watch actual DNS queries from your device as you browse
- **Privacy awareness** — understand your device's network behavior without installing shady monitoring tools
- **Educational tool** — if you're teaching or learning about networking, this is a live DNS lab on your phone

## Features

- Real-time DNS query interception and domain extraction
- Site grouping — CDN domains like `i.ytimg.com` are grouped under `youtube.com`
- Domain categorization — domains are tagged as Social Media, Entertainment, Shopping, etc.
- Local SQLite storage with visit history
- Search, sort, and filter domains
- Daily domain stats with charts
- Noise filtering for system/infrastructure domains
- Privacy-first: zero data leaves the device

## Project structure

```
maven/                          iOS app (Xcode project)
  maven/                        Main app target (SwiftUI)
    Views/                      Connection, Domains, Stats, Settings, Onboarding
    Services/                   VPNManager, DatabaseReader, CategoriesService
    Models/                     DomainRecord, UserSettings
  PacketTunnelExtension/        Network Extension target
    PacketTunnelProvider.swift   NEPacketTunnelProvider + DNS forwarder
    RustBridge.swift            Swift wrapper around C FFI
  Shared/                       Code shared between both targets
  Frameworks/                   Prebuilt Rust static libraries

rust/packet_engine/             Rust packet engine
  src/
    engine.rs                   Main orchestrator (batching, flush, stats)
    ip.rs                       IPv4/IPv6 header parser
    dns.rs                      DNS query parser
    site_mapper.rs              CDN → parent site mapping + eTLD+1
    storage.rs                  SQLite writer (rusqlite)
    domain.rs                   Domain normalization + noise filtering
    lib.rs                      C FFI entry points

scripts/
  build-rust.sh                 Build Rust for a specific iOS target
  build-universal.sh            Build for both device and simulator
```

## Requirements

- macOS 14+
- Xcode 15+
- Rust 1.75+ with iOS targets installed
- Apple Developer account (Network Extensions require a provisioning profile)
- Physical iPhone (the tunnel can't start on Simulator)

## Getting started

### 1. Install Rust iOS targets

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

### 2. Build the Rust library

```bash
./scripts/build-universal.sh
```

This compiles `libpacket_engine.a` for both device and simulator, and copies the generated C header to the Xcode project.

### 3. Open in Xcode

```bash
open maven/maven.xcodeproj
```

Set your development team in Signing & Capabilities for both targets (`maven` and `PacketTunnelExtension`). The entitlements for Network Extension and App Groups are already configured.

### 4. Run on device

Select your iPhone and hit Cmd+R. The app will ask for VPN permission (it's a local tunnel, not a remote proxy), then start capturing DNS queries when you browse.

## Testing

```bash
cd rust/packet_engine
cargo test
```

The iOS app needs a physical device to test the tunnel. It builds on Simulator but the Network Extension won't start.

## Architecture notes

**Why Rust?** The Network Extension has a 6 MB memory limit. Rust's ownership model keeps memory predictable and leak-free. The engine runs at ~3 MB.

**Why DNS-only?** Capturing all traffic would need a userspace TCP/IP stack. DNS-only keeps it simple and still catches the vast majority of domain connections.

**Why raw SQLite3 C API in Swift?** Avoids a third-party dependency. The read surface is small enough that a wrapper library isn't worth the complexity.

## Privacy

- All packet analysis runs locally in the Network Extension
- Domain history stays in a local SQLite database
- The VPN is local — traffic is observed and forwarded, not proxied
- DNS queries go to Google DNS (8.8.8.8) for resolution
- No analytics, no tracking, no remote servers

## License

MIT
