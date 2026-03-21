import SwiftUI
import NetworkExtension

struct ConnectionView: View {
    @EnvironmentObject var vpnManager: VPNManager
    @StateObject private var viewModel = ConnectionViewModel()

    var body: some View {
        NavigationStack {
            VStack(spacing: 32) {
                Spacer()

                statusView

                ConnectButton(status: viewModel.status) {
                    viewModel.toggleConnection()
                }

                if viewModel.status == .connected {
                    Text(viewModel.formattedDuration)
                        .font(.system(.title2, design: .monospaced))
                        .foregroundColor(.secondary)
                        .transition(.opacity)
                }

                Spacer()

                if viewModel.status == .connected {
                    quickStatsSection
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }

                #if DEBUG
                // Debug: show tunnel status breadcrumbs
                if viewModel.status == .connected {
                    Text(viewModel.tunnelDebugStatus)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal)
                }
                #endif
            }
            .padding()
            .animation(.easeInOut(duration: 0.4), value: viewModel.status)
            .navigationTitle("Maven")
            .alert("Connection Error", isPresented: Binding(
                get: { viewModel.connectionError != nil },
                set: { if !$0 { viewModel.connectionError = nil } }
            )) {
                Button("OK", role: .cancel) { viewModel.connectionError = nil }
            } message: {
                Text(viewModel.connectionError ?? "")
            }
        }
    }

    private var statusView: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(statusDotColor)
                .frame(width: 10, height: 10)
            Text(statusText)
                .font(.headline)
                .foregroundColor(.secondary)
        }
    }

    private var quickStatsSection: some View {
        HStack(spacing: 16) {
            StatCard(title: "Domains", value: viewModel.formattedDomainsToday, icon: "globe")
            StatCard(title: "Packets", value: viewModel.formattedPacketsScanned, icon: "arrow.left.arrow.right")
            StatCard(title: "DNS", value: viewModel.formattedDNSQueries, icon: "magnifyingglass")
        }
        .padding(.horizontal)
        .padding(.bottom, 8)
    }

    private var statusText: String {
        switch viewModel.status {
        case .connected: return "Protected"
        case .connecting: return "Connecting..."
        case .disconnecting: return "Disconnecting..."
        case .reasserting: return "Reconnecting..."
        case .disconnected: return "Not Connected"
        case .invalid: return "Not Configured"
        @unknown default: return "Unknown"
        }
    }

    private var statusDotColor: Color {
        switch viewModel.status {
        case .connected: return .green
        case .connecting, .disconnecting, .reasserting: return .orange
        case .disconnected, .invalid: return .gray
        @unknown default: return .gray
        }
    }
}

struct StatCard: View {
    let title: String
    let value: String
    let icon: String

    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundColor(.accentColor)
            Text(value)
                .font(.system(.title3, design: .rounded).bold())
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }
}
