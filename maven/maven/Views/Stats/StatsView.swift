import SwiftUI
import Charts

struct StatsView: View {
    @StateObject private var viewModel = StatsViewModel()

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.totalDomains == 0 && viewModel.totalVisits == 0 {
                    ContentUnavailableView(
                        "No Stats Yet",
                        systemImage: "chart.bar",
                        description: Text("Connect the VPN and browse to start seeing statistics.")
                    )
                } else {
                    ScrollView {
                        VStack(spacing: 20) {
                            summaryCards
                            chartSection
                            topDomainsSection
                        }
                        .padding()
                    }
                }
            }
            .navigationTitle("Stats")
            .refreshable {
                viewModel.refresh()
            }
        }
    }

    // MARK: - Summary Cards

    private var summaryCards: some View {
        HStack(spacing: 12) {
            SummaryCard(title: "Domains", value: "\(viewModel.totalDomains)", icon: "globe", color: .blue)
            SummaryCard(title: "Visits", value: viewModel.formattedVisits, icon: "arrow.triangle.swap", color: .purple)
            SummaryCard(title: "Today", value: "\(viewModel.domainsToday)", icon: "calendar", color: .green)
        }
    }

    // MARK: - Chart

    private var chartSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Domains Per Day")
                .font(.headline)

            Chart(viewModel.dailyDomainCounts) { item in
                BarMark(
                    x: .value("Day", item.dayLabel),
                    y: .value("Count", item.count)
                )
                .foregroundStyle(.blue.gradient)
                .cornerRadius(4)
            }
            .frame(height: 200)
            .chartYAxis {
                AxisMarks(position: .leading)
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(16)
    }

    // MARK: - Top Domains

    private var topDomainsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Top Domains")
                .font(.headline)

            ForEach(Array(viewModel.topDomains.enumerated()), id: \.element.id) { index, domain in
                HStack {
                    Text("\(index + 1)")
                        .font(.caption.bold())
                        .foregroundColor(.secondary)
                        .frame(width: 24)

                    Text(domain.domain)
                        .font(.subheadline)

                    Spacer()

                    Text("\(domain.visitCount)")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.secondary)
                }
                .padding(.vertical, 4)

                if index < viewModel.topDomains.count - 1 {
                    Divider()
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(16)
    }
}

// MARK: - Summary Card

struct SummaryCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(color)

            Text(value)
                .font(.title2.bold())

            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 16)
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

#Preview {
    StatsView()
}
