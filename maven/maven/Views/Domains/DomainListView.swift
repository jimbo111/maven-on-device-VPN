import SwiftUI

struct DomainListView: View {
    @StateObject private var viewModel = DomainListViewModel()

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.groupedDomains.isEmpty {
                    ContentUnavailableView(
                        "No Domains Found",
                        systemImage: "globe",
                        description: Text(viewModel.searchText.isEmpty
                            ? "Connect the VPN to start seeing domains."
                            : "No domains match your search.")
                    )
                } else {
                    List {
                        ForEach(viewModel.groupedDomains) { group in
                            Section(group.key) {
                                ForEach(group.domains) { domain in
                                    NavigationLink(value: domain) {
                                        DomainRowView(domain: domain)
                                    }
                                }
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                }
            }
            .navigationTitle("Domains")
            .searchable(text: $viewModel.searchText, prompt: "Search domains")
            .navigationDestination(for: DomainRecord.self) { domain in
                DomainDetailView(domain: domain)
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        ForEach(DomainListViewModel.SortOption.allCases) { option in
                            Button {
                                viewModel.sortBy(option)
                            } label: {
                                HStack {
                                    Text(option.rawValue)
                                    if viewModel.sortOption == option {
                                        Image(systemName: "checkmark")
                                    }
                                }
                            }
                        }
                    } label: {
                        Image(systemName: "arrow.up.arrow.down")
                    }
                }
            }
            .refreshable {
                viewModel.refresh()
            }
        }
    }
}

#Preview {
    DomainListView()
}
