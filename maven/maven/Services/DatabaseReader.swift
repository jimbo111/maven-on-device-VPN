import Foundation
import SQLite3
import os.log

// MARK: - Supporting Types

struct DatabaseStats: Sendable {
    let totalDomains: Int
    let totalVisits: Int
    let domainsToday: Int
}

struct VisitRecord: Identifiable, Sendable {
    let id: Int64
    let domainId: Int64
    let timestampMs: Int64
    let source: String

    var date: Date {
        Date(timeIntervalSince1970: TimeInterval(timestampMs) / 1000)
    }
}

// MARK: - DatabaseReader

/// Manages the shared SQLite database written by the Rust packet engine.
///
/// Uses the C SQLite3 API directly (no third-party dependencies). Primarily
/// read-only, but includes admin write operations (truncateAllData,
/// cleanupOldVisits). Opened with READWRITE for WAL compatibility.
/// Returns empty results gracefully when the database file does not yet exist.
final class DatabaseReader {

    static let shared = DatabaseReader()

    // MARK: - Private State

    private var db: OpaquePointer?
    private var schemaValid = false
    private let queue = DispatchQueue(label: "com.jimmykim.maven.dbreader", qos: .userInitiated)
    private let log = OSLog(subsystem: "com.jimmykim.maven", category: "DatabaseReader")

    // MARK: - Init / Deinit

    private init() {
        // Open database inside the serial queue — openDatabase() uses
        // SQLITE_OPEN_NOMUTEX so all access must be serialized. (audit fix)
        queue.sync { openDatabase() }
    }

    deinit {
        closeDatabase()
    }

    // MARK: - Connection Management

    private var loggedNotFound = false

    private func openDatabase() {
        let path = AppGroupConfig.databasePath

        guard FileManager.default.fileExists(atPath: path) else {
            if !loggedNotFound {
                print("[Maven DB] Not found at \(path), waiting for tunnel to create it")
                loggedNotFound = true
            }
            db = nil
            return
        }
        loggedNotFound = false

        var handle: OpaquePointer?
        // Use READWRITE so we can read WAL databases properly.
        // The Rust engine is the only writer; we only read.
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX
        let rc = sqlite3_open_v2(path, &handle, flags, nil)

        if rc == SQLITE_OK {
            db = handle
            sqlite3_busy_timeout(db, 500)
            print("[Maven DB] Opened successfully at \(path)")
        } else {
            let errMsg = String(cString: sqlite3_errmsg(handle))
            print("[Maven DB] Open FAILED: rc=\(rc) err=\(errMsg)")
            sqlite3_close(handle)
            db = nil
        }
    }

    private func closeDatabase() {
        if let db = db {
            sqlite3_close(db)
            self.db = nil
            self.schemaValid = false
        }
    }

    /// Truncate all domain and visit data without deleting the database file.
    /// Safe to call while the Network Extension has the DB open — SQLite
    /// handles concurrent access via WAL. The extension's next write will
    /// simply create new rows.
    func truncateAllData() {
        queue.sync {
            ensureOpen()
            guard let db = db else { return }
            sqlite3_exec(db, "DELETE FROM visits", nil, nil, nil)
            sqlite3_exec(db, "DELETE FROM domains", nil, nil, nil)
            print("[Maven DB] All data truncated")
        }
    }

    private var schemaRetryCount = 0

    /// Re-open the database if it was nil at launch (file didn't exist yet).
    private func ensureOpen() {
        if db == nil {
            openDatabase()
        }
        // Validate schema — the extension may still be creating tables,
        // so just close and retry on the next call. NEVER delete the file
        // because the extension may have it open.
        if let db = db, !schemaValid {
            if validateSchema(db) {
                schemaValid = true
                schemaRetryCount = 0
                print("[Maven DB] Schema validated OK")
            } else {
                schemaRetryCount += 1
                if schemaRetryCount <= 3 {
                    print("[Maven DB] Schema not ready yet (attempt \(schemaRetryCount)), will retry")
                }
                closeDatabase()
                // Do NOT delete — the extension may still be creating tables
            }
        }
    }

    /// Check that the domains table has the columns we expect.
    private func validateSchema(_ db: OpaquePointer) -> Bool {
        var stmt: OpaquePointer?
        // PRAGMA table_info returns one row per column
        guard sqlite3_prepare_v2(db, "PRAGMA table_info(domains)", -1, &stmt, nil) == SQLITE_OK else {
            return false
        }
        defer { sqlite3_finalize(stmt) }

        var columns: Set<String> = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let name = sqlite3_column_text(stmt, 1) {
                columns.insert(String(cString: name))
            }
        }

        // These are the columns the Rust engine creates
        let required: Set<String> = ["id", "domain", "first_seen", "last_seen", "visit_count", "source", "site_domain"]
        return required.isSubset(of: columns)
    }

    // MARK: - Public API

    /// Most recent domains, ordered by `last_seen DESC`.
    func recentDomains(limit: Int = 100) -> [DomainRecord] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain, first_seen, last_seen, visit_count, source, site_domain
                FROM domains
                ORDER BY last_seen DESC
                LIMIT ?
                """
            return queryDomains(db: db, sql: sql, bind: { stmt in
                sqlite3_bind_int(stmt, 1, Int32(limit))
            })
        }
    }

    /// Domains whose name contains `query` (case-insensitive).
    func searchDomains(query: String) -> [DomainRecord] {
        let pattern = "%\(query)%"
        return queue.sync { () -> [DomainRecord] in
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain, first_seen, last_seen, visit_count, source, site_domain
                FROM domains
                WHERE domain LIKE ?
                ORDER BY last_seen DESC
                LIMIT 200
                """
            let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
            return queryDomains(db: db, sql: sql, bind: { stmt in
                _ = pattern.withCString { cStr in
                    sqlite3_bind_text(stmt, 1, cStr, -1, transient)
                }
            })
        }
    }

    /// Top domains by visit count.
    func topDomains(limit: Int = 20) -> [DomainRecord] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain, first_seen, last_seen, visit_count, source, site_domain
                FROM domains
                ORDER BY visit_count DESC
                LIMIT ?
                """
            return queryDomains(db: db, sql: sql, bind: { stmt in
                sqlite3_bind_int(stmt, 1, Int32(limit))
            })
        }
    }

    /// Aggregate statistics.
    func stats() -> DatabaseStats {
        queue.sync {
            ensureOpen()
            guard let db = db else {
                return DatabaseStats(totalDomains: 0, totalVisits: 0, domainsToday: 0)
            }

            let totalDomains = scalarInt(db: db, sql: "SELECT COUNT(*) FROM domains")
            let totalVisits = scalarInt(db: db, sql: "SELECT COUNT(*) FROM visits")

            let startOfTodayMs = Self.startOfTodayMs()
            let domainsToday = scalarInt(
                db: db,
                sql: "SELECT COUNT(DISTINCT domain_id) FROM visits WHERE timestamp >= ?",
                bind: { stmt in sqlite3_bind_int64(stmt, 1, startOfTodayMs) }
            )

            return DatabaseStats(
                totalDomains: totalDomains,
                totalVisits: totalVisits,
                domainsToday: domainsToday
            )
        }
    }

    /// Unique domain counts grouped by calendar day for the last `days` days.
    func dailyDomainCounts(days: Int = 7) -> [(date: Date, count: Int)] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            // Build the lower bound timestamp.
            let calendar = Calendar.current
            guard let startDate = calendar.date(byAdding: .day, value: -(days - 1), to: calendar.startOfDay(for: Date())) else {
                return []
            }
            let startMs = Int64(startDate.timeIntervalSince1970 * 1000)

            // Group visit timestamps into calendar days by dividing ms by ms-per-day.
            let sql = """
                SELECT (timestamp / 86400000) AS day_bucket,
                       COUNT(DISTINCT domain_id) AS cnt
                FROM visits
                WHERE timestamp >= ?
                GROUP BY day_bucket
                ORDER BY day_bucket ASC
                """

            var results: [Int64: Int] = [:]
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_int64(stmt, 1, startMs)

            while sqlite3_step(stmt) == SQLITE_ROW {
                let bucket = sqlite3_column_int64(stmt, 0)
                let count = Int(sqlite3_column_int(stmt, 1))
                results[bucket] = count
            }

            // Fill in zero-count days so the chart always has `days` entries.
            var output: [(date: Date, count: Int)] = []
            for offset in 0..<days {
                guard let dayDate = calendar.date(byAdding: .day, value: offset, to: startDate) else { continue }
                let bucket = Int64(dayDate.timeIntervalSince1970 * 1000) / 86400000
                let count = results[bucket] ?? 0
                output.append((date: dayDate, count: count))
            }

            return output
        }
    }

    /// Visit history for a specific domain.
    func visits(forDomainId domainId: Int64, limit: Int = 50) -> [VisitRecord] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain_id, timestamp, source
                FROM visits
                WHERE domain_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """

            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_int64(stmt, 1, domainId)
            sqlite3_bind_int(stmt, 2, Int32(limit))

            var records: [VisitRecord] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                let record = VisitRecord(
                    id: sqlite3_column_int64(stmt, 0),
                    domainId: sqlite3_column_int64(stmt, 1),
                    timestampMs: sqlite3_column_int64(stmt, 2),
                    source: columnText(stmt, index: 3)
                )
                records.append(record)
            }
            return records
        }
    }

    // MARK: - Helpers

    /// Runs a query that returns `DomainRecord` rows.
    private func queryDomains(
        db: OpaquePointer,
        sql: String,
        bind: ((OpaquePointer) -> Void)? = nil
    ) -> [DomainRecord] {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }

        bind?(stmt!)

        var records: [DomainRecord] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            // Column layout: id=0, domain=1, first_seen=2, last_seen=3,
            //                visit_count=4, source=5, site_domain=6
            let record = DomainRecord(
                id: sqlite3_column_int64(stmt, 0),
                domain: columnText(stmt, index: 1),
                firstSeenMs: sqlite3_column_int64(stmt, 2),
                lastSeenMs: sqlite3_column_int64(stmt, 3),
                visitCount: Int(sqlite3_column_int(stmt, 4)),
                source: columnText(stmt, index: 5),
                siteDomain: columnText(stmt, index: 6)
            )
            records.append(record)
        }
        return records
    }

    /// Read a non-null TEXT column as a Swift String (empty string fallback).
    private func columnText(_ stmt: OpaquePointer?, index: Int32) -> String {
        guard let cStr = sqlite3_column_text(stmt, index) else { return "" }
        return String(cString: cStr)
    }

    /// Read a nullable TEXT column.
    private func columnOptionalText(_ stmt: OpaquePointer?, index: Int32) -> String? {
        guard sqlite3_column_type(stmt, index) != SQLITE_NULL,
              let cStr = sqlite3_column_text(stmt, index) else { return nil }
        return String(cString: cStr)
    }

    /// Execute a scalar `SELECT COUNT(*)` style query, returning an Int.
    private func scalarInt(
        db: OpaquePointer,
        sql: String,
        bind: ((OpaquePointer) -> Void)? = nil
    ) -> Int {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return 0 }
        defer { sqlite3_finalize(stmt) }
        if let bind = bind { bind(stmt!) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Delete visit rows older than `days` days. Called on app launch to
    /// enforce the user's retention setting.
    func cleanupOldVisits(olderThanDays days: Int) {
        queue.sync {
            ensureOpen()
            guard let db = db else { return }
            let cutoffMs = Int64(Date().timeIntervalSince1970 * 1000) - Int64(days) * 86_400_000
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, "DELETE FROM visits WHERE timestamp < ?", -1, &stmt, nil) == SQLITE_OK else { return }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_int64(stmt, 1, cutoffMs)
            sqlite3_step(stmt)
        }
    }

    /// Millisecond timestamp at the start of today (midnight, local time zone).
    private static func startOfTodayMs() -> Int64 {
        let startOfDay = Calendar.current.startOfDay(for: Date())
        return Int64(startOfDay.timeIntervalSince1970 * 1000)
    }
}
