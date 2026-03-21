import SwiftUI

struct SettingsView: View {
    @StateObject private var viewModel = SettingsViewModel()

    private let retentionOptions = [7, 14, 30, 60, 90]

    var body: some View {
        NavigationStack {
            Form {
                // General
                Section("General") {
                    Toggle("Auto-Connect on Launch", isOn: $viewModel.settings.autoConnect)
                }

                // Filtering
                Section {
                    Toggle("Filter Noise Domains", isOn: $viewModel.settings.filterNoise)
                        .onChange(of: viewModel.settings.filterNoise) { _, newValue in
                            viewModel.syncNoiseFilter(enabled: newValue)
                        }
                } header: {
                    Text("Filtering")
                } footer: {
                    Text("Hides common infrastructure domains like CDNs and analytics trackers.")
                }

                // Data
                Section("Data") {
                    Picker("Retention Period", selection: $viewModel.settings.retentionDays) {
                        ForEach(retentionOptions, id: \.self) { days in
                            Text("\(days) days").tag(days)
                        }
                    }

                    Button {
                        viewModel.exportCSV()
                    } label: {
                        if viewModel.isExporting {
                            ProgressView()
                        } else {
                            Label("Export as CSV", systemImage: "square.and.arrow.up")
                        }
                    }
                    .disabled(viewModel.isExporting)

                    Button(role: .destructive) {
                        viewModel.showClearConfirmation = true
                    } label: {
                        Label("Clear All Data", systemImage: "trash")
                    }
                }

                // About
                Section("About") {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text(viewModel.appVersion)
                            .foregroundColor(.secondary)
                    }

                    Link(destination: URL(string: "https://maven.jimmykim.com/privacy")!) {
                        HStack {
                            Text("Privacy Policy")
                            Spacer()
                            Image(systemName: "arrow.up.right.square")
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("Settings")
            .confirmationDialog(
                "Clear All Data",
                isPresented: $viewModel.showClearConfirmation,
                titleVisibility: .visible
            ) {
                Button("Clear All Data", role: .destructive) {
                    viewModel.clearAllData()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This will permanently delete all recorded domains and visit history. This action cannot be undone.")
            }
            .sheet(isPresented: $viewModel.showExportSheet, onDismiss: {
                viewModel.cleanupExportFile()
            }) {
                if let url = viewModel.csvFileURL {
                    ShareSheet(items: [url])
                }
            }
            .alert("Export Failed", isPresented: Binding(
                get: { viewModel.exportError != nil },
                set: { if !$0 { viewModel.exportError = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(viewModel.exportError ?? "")
            }
        }
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

#Preview {
    SettingsView()
}
