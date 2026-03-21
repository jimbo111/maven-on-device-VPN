import SwiftUI
import NetworkExtension

struct MainTabView: View {
    @EnvironmentObject var vpnManager: VPNManager

    var body: some View {
        TabView {
            ConnectionView()
                .tabItem {
                    Label("Home", systemImage: "shield.checkered")
                }

            DomainListView()
                .tabItem {
                    Label("Domains", systemImage: "list.bullet")
                }

            StatsView()
                .tabItem {
                    Label("Stats", systemImage: "chart.bar")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gearshape")
                }
        }
    }
}

#Preview {
    MainTabView()
        .environmentObject(VPNManager.shared)
}
