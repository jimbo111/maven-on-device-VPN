import SwiftUI

struct DomainRowView: View {
    let domain: DomainRecord

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "globe")
                .font(.title3)
                .foregroundColor(.accentColor)
                .frame(width: 32)

            VStack(alignment: .leading, spacing: 4) {
                Text(domain.domain)
                    .font(.body)
                    .lineLimit(1)

                HStack(spacing: 8) {
                    Text(domain.relativeTimeString)
                        .font(.caption)
                        .foregroundColor(.secondary)

                    sourceBadge
                }
            }

            Spacer()

            Text("\(domain.visitCount)")
                .font(.subheadline.monospacedDigit())
                .foregroundColor(.secondary)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color(.systemGray5))
                .cornerRadius(8)
        }
        .padding(.vertical, 4)
    }

    private var sourceBadge: some View {
        Text(domain.source)
            .font(.caption2.bold())
            .foregroundColor(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(domain.source == "DNS" ? Color.green : Color.blue)
            .cornerRadius(4)
    }
}

#Preview {
    let now = Date()
    let sample = DomainRecord(
        id: 1,
        domain: "apple.com",
        firstSeenMs: Int64((now.timeIntervalSince1970 - 86400) * 1000),
        lastSeenMs: Int64((now.timeIntervalSince1970 - 3600) * 1000),
        visitCount: 42,
        source: "dns",
        siteDomain: "apple.com"
    )
    return List {
        DomainRowView(domain: sample)
    }
}
