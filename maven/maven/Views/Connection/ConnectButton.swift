import SwiftUI
import NetworkExtension

struct ConnectButton: View {
    let status: NEVPNStatus
    let action: () -> Void

    private var isTransitioning: Bool {
        status == .connecting || status == .disconnecting || status == .reasserting
    }

    private var isConnected: Bool {
        status == .connected
    }

    private var ringColor: Color {
        if isConnected { return .green }
        if isTransitioning { return .orange }
        return .gray
    }

    private var fillColor: Color {
        if isConnected { return .green.opacity(0.15) }
        if isTransitioning { return .orange.opacity(0.10) }
        return Color(.secondarySystemBackground)
    }

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle()
                    .fill(fillColor)
                    .frame(width: 160, height: 160)

                Circle()
                    .stroke(ringColor, lineWidth: 4)
                    .frame(width: 160, height: 160)

                if isTransitioning {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .orange))
                        .scaleEffect(1.5)
                } else {
                    Image(systemName: isConnected ? "shield.checkered" : "shield.slash")
                        .font(.system(size: 48, weight: .medium))
                        .foregroundColor(isConnected ? .green : .gray)
                }
            }
        }
        .disabled(isTransitioning)
        .accessibilityLabel(
            isConnected ? "Disconnect VPN" :
            isTransitioning ? "VPN connection in progress" :
            "Connect VPN"
        )
        .animation(.easeInOut(duration: 0.3), value: status)
    }
}
