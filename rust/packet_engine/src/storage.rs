use rusqlite::{params, Connection};

use crate::domain::DomainRecord;
use crate::errors::EngineError;
use crate::site_mapper;

/// SQLite-backed persistent store for observed domain records and visit history.
pub struct DomainStorage {
    conn: Connection,
}

impl DomainStorage {
    /// Opens (or creates) the SQLite database at `db_path` and applies the
    /// required schema and PRAGMA configuration.
    ///
    /// Pass `":memory:"` for an in-process ephemeral database (useful in
    /// tests).
    ///
    /// PRAGMAs applied:
    /// - `journal_mode = WAL` — concurrent readers do not block the writer.
    /// - `synchronous = NORMAL` — durable enough for non-critical data.
    /// - `cache_size = -2000` — approximately 2 MB page cache.
    /// - `auto_vacuum = INCREMENTAL` — reclaim free pages incrementally.
    /// - `busy_timeout = 5000` — wait up to 5 s before returning SQLITE_BUSY.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseOpen`] if the database cannot be opened
    /// or if schema creation fails.
    pub fn new(db_path: &str) -> Result<Self, EngineError> {
        let conn = Connection::open(db_path)?;

        // Apply recommended PRAGMA settings before creating the schema.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -2000;
             PRAGMA auto_vacuum = INCREMENTAL;
             PRAGMA busy_timeout = 5000;",
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS domains (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                domain       TEXT    NOT NULL,
                first_seen   INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                source       TEXT    NOT NULL,
                visit_count  INTEGER NOT NULL DEFAULT 1,
                site_domain  TEXT    NOT NULL DEFAULT ''
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_domain
                ON domains(domain);

            CREATE TABLE IF NOT EXISTS visits (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id  INTEGER NOT NULL REFERENCES domains(id),
                timestamp  INTEGER NOT NULL,
                source     TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_visits_timestamp
                ON visits(timestamp);
            CREATE INDEX IF NOT EXISTS idx_visits_domain_id
                ON visits(domain_id);

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );",
        )?;

        // Migration: add site_domain column to existing databases.
        let _ = conn.execute(
            "ALTER TABLE domains ADD COLUMN site_domain TEXT NOT NULL DEFAULT ''",
            [],
        );

        Ok(Self { conn })
    }

    /// Inserts or updates a batch of [`DomainRecord`]s inside a single
    /// transaction.
    ///
    /// For each record:
    /// - The `domains` row is upserted: on a domain conflict the `last_seen`
    ///   timestamp, `source`, and `visit_count` are updated.
    /// - A new row is always appended to the `visits` table.
    ///
    /// The entire batch is committed atomically; if any step fails the
    /// transaction is rolled back.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseWrite`] if any SQL operation fails.
    pub fn batch_insert(&mut self, records: &[DomainRecord]) -> Result<(), EngineError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        for record in records {
            let site = site_mapper::map_to_site(&record.domain);
            tx.execute(
                "INSERT INTO domains (domain, first_seen, last_seen, source, visit_count, site_domain)
                 VALUES (?1, ?2, ?2, ?3, 1, ?4)
                 ON CONFLICT(domain) DO UPDATE SET
                     last_seen   = excluded.last_seen,
                     visit_count = visit_count + 1,
                     source      = CASE
                         WHEN excluded.source = 'sni' THEN 'sni'
                         WHEN excluded.source = 'dns_correlation' THEN
                             CASE WHEN domains.source = 'sni' THEN 'sni'
                                  ELSE excluded.source
                             END
                         ELSE domains.source
                     END,
                     site_domain = CASE
                         WHEN domains.site_domain = '' THEN excluded.site_domain
                         ELSE domains.site_domain
                     END",
                params![record.domain, record.timestamp_ms, record.source.as_str(), site.as_ref()],
            )
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

            // Fetch the domain's row id for the visit foreign key.
            let domain_id: i64 = tx
                .query_row(
                    "SELECT id FROM domains WHERE domain = ?1",
                    params![record.domain],
                    |row| row.get(0),
                )
                .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

            tx.execute(
                "INSERT INTO visits (domain_id, timestamp, source)
                 VALUES (?1, ?2, ?3)",
                params![domain_id, record.timestamp_ms, record.source.as_str()],
            )
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        Ok(())
    }

    /// Returns the number of distinct domains stored in the database.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseWrite`] if the query fails.
    pub fn domain_count(&self) -> Result<i64, EngineError> {
        self.conn
            .query_row("SELECT COUNT(*) FROM domains", [], |row| row.get(0))
            .map_err(|e| EngineError::DatabaseWrite(format!("Failed to read from database: {e}")))
    }

    /// Deletes all visit rows with a timestamp strictly older than
    /// `older_than_ms` (Unix milliseconds).
    ///
    /// Returns the number of rows removed.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseWrite`] if the DELETE fails.
    pub fn cleanup_old_visits(&self, older_than_ms: i64) -> Result<usize, EngineError> {
        let rows_deleted = self
            .conn
            .execute(
                "DELETE FROM visits WHERE timestamp < ?1",
                params![older_than_ms],
            )
            .map_err(|e| EngineError::DatabaseWrite(format!("Failed to read from database: {e}")))?;

        Ok(rows_deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DetectionSource, DomainRecord};

    /// Creates an in-memory [`DomainStorage`] and panics on failure.
    fn in_memory_storage() -> DomainStorage {
        DomainStorage::new(":memory:").expect("in-memory DB should open")
    }

    /// Builds a [`DomainRecord`] with a specific timestamp, bypassing the
    /// noise and validation filters used in `from_raw_name`.
    fn make_record(domain: &str, timestamp_ms: i64, source: DetectionSource) -> DomainRecord {
        DomainRecord {
            domain: domain.to_owned(),
            timestamp_ms,
            source,
        }
    }

    #[test]
    fn in_memory_db_tables_exist() {
        let storage = in_memory_storage();

        // Query sqlite_master to verify the expected tables were created.
        let count: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table'
                   AND name IN ('domains', 'visits', 'settings')",
                [],
                |row| row.get(0),
            )
            .expect("sqlite_master query should succeed");

        assert_eq!(count, 3, "domains, visits, and settings tables must exist");
    }

    #[test]
    fn insert_three_records_domain_count_is_three() {
        let mut storage = in_memory_storage();

        let records = vec![
            make_record("example.com", 1_000, DetectionSource::Dns),
            make_record("github.com", 2_000, DetectionSource::Sni),
            make_record("rust-lang.org", 3_000, DetectionSource::DnsCorrelation),
        ];

        storage.batch_insert(&records).expect("batch_insert should succeed");

        assert_eq!(
            storage.domain_count().expect("domain_count should succeed"),
            3
        );
    }

    #[test]
    fn insert_same_domain_twice_count_stays_one_visit_increments() {
        let mut storage = in_memory_storage();

        let first = make_record("example.com", 1_000, DetectionSource::Dns);
        storage
            .batch_insert(&[first])
            .expect("first insert should succeed");

        let second = make_record("example.com", 2_000, DetectionSource::Sni);
        storage
            .batch_insert(&[second])
            .expect("second insert should succeed");

        // Domain count must still be 1.
        assert_eq!(
            storage.domain_count().expect("domain_count should succeed"),
            1,
            "duplicate domain must not create a second domains row"
        );

        // visit_count on the domains row must be 2.
        let visit_count: i64 = storage
            .conn
            .query_row(
                "SELECT visit_count FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("visit_count query should succeed");

        assert_eq!(visit_count, 2, "visit_count must be incremented on upsert");

        // The visits table must have 2 rows.
        let visits_rows: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(*) FROM visits",
                [],
                |row| row.get(0),
            )
            .expect("visits count query should succeed");

        assert_eq!(visits_rows, 2, "each visit must produce a visits row");
    }

    #[test]
    fn cleanup_old_visits_removes_old_entries() {
        let mut storage = in_memory_storage();

        let records = vec![
            make_record("old.example.com", 500, DetectionSource::Dns),
            make_record("also-old.example.com", 900, DetectionSource::Dns),
            make_record("new.example.com", 2_000, DetectionSource::Dns),
        ];
        storage.batch_insert(&records).expect("batch_insert should succeed");

        // Verify that 3 visit rows exist before cleanup.
        let before: i64 = storage
            .conn
            .query_row("SELECT COUNT(*) FROM visits", [], |row| row.get(0))
            .expect("count query should succeed");
        assert_eq!(before, 3);

        // Remove visits older than timestamp 1_000.
        let removed = storage
            .cleanup_old_visits(1_000)
            .expect("cleanup should succeed");

        assert_eq!(removed, 2, "two old visit rows should have been removed");

        let after: i64 = storage
            .conn
            .query_row("SELECT COUNT(*) FROM visits", [], |row| row.get(0))
            .expect("count query should succeed");
        assert_eq!(after, 1, "one recent visit row should remain");
    }

    #[test]
    fn upsert_preserves_sni_source_over_dns() {
        let mut storage = in_memory_storage();

        // First visit via SNI
        let sni_record = make_record("example.com", 1_000, DetectionSource::Sni);
        storage.batch_insert(&[sni_record]).expect("insert should succeed");

        let source: String = storage
            .conn
            .query_row(
                "SELECT source FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("query should succeed");
        assert_eq!(source, "sni", "initial source must be sni");

        // Second visit via DNS — must NOT overwrite sni
        let dns_record = make_record("example.com", 2_000, DetectionSource::Dns);
        storage.batch_insert(&[dns_record]).expect("insert should succeed");

        let source_after: String = storage
            .conn
            .query_row(
                "SELECT source FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("query should succeed");
        assert_eq!(
            source_after, "sni",
            "source must remain 'sni' after a dns upsert — sni is higher fidelity"
        );
    }

    #[test]
    fn upsert_upgrades_dns_to_sni() {
        let mut storage = in_memory_storage();

        // First visit via DNS
        let dns_record = make_record("example.com", 1_000, DetectionSource::Dns);
        storage.batch_insert(&[dns_record]).expect("insert should succeed");

        // Second visit via SNI — must upgrade
        let sni_record = make_record("example.com", 2_000, DetectionSource::Sni);
        storage.batch_insert(&[sni_record]).expect("insert should succeed");

        let source: String = storage
            .conn
            .query_row(
                "SELECT source FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("query should succeed");
        assert_eq!(
            source, "sni",
            "source must be upgraded to 'sni' when sni is observed"
        );
    }

    #[test]
    fn upsert_preserves_sni_over_dns_correlation() {
        let mut storage = in_memory_storage();
        storage.batch_insert(&[make_record("example.com", 1_000, DetectionSource::Sni)]).unwrap();
        storage.batch_insert(&[make_record("example.com", 2_000, DetectionSource::DnsCorrelation)]).unwrap();

        let source: String = storage.conn
            .query_row("SELECT source FROM domains WHERE domain = 'example.com'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "sni", "sni must not be overwritten by dns_correlation");
    }

    #[test]
    fn upsert_upgrades_dns_to_dns_correlation() {
        let mut storage = in_memory_storage();
        storage.batch_insert(&[make_record("example.com", 1_000, DetectionSource::Dns)]).unwrap();
        storage.batch_insert(&[make_record("example.com", 2_000, DetectionSource::DnsCorrelation)]).unwrap();

        let source: String = storage.conn
            .query_row("SELECT source FROM domains WHERE domain = 'example.com'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "dns_correlation", "dns should be upgraded to dns_correlation");
    }

    #[test]
    fn upsert_preserves_dns_correlation_over_dns() {
        let mut storage = in_memory_storage();
        storage.batch_insert(&[make_record("example.com", 1_000, DetectionSource::DnsCorrelation)]).unwrap();
        storage.batch_insert(&[make_record("example.com", 2_000, DetectionSource::Dns)]).unwrap();

        let source: String = storage.conn
            .query_row("SELECT source FROM domains WHERE domain = 'example.com'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "dns_correlation", "dns_correlation must not be overwritten by dns");
    }

    #[test]
    fn upsert_upgrades_dns_correlation_to_sni() {
        let mut storage = in_memory_storage();
        storage.batch_insert(&[make_record("example.com", 1_000, DetectionSource::DnsCorrelation)]).unwrap();
        storage.batch_insert(&[make_record("example.com", 2_000, DetectionSource::Sni)]).unwrap();

        let source: String = storage.conn
            .query_row("SELECT source FROM domains WHERE domain = 'example.com'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "sni", "dns_correlation should be upgraded to sni");
    }

    #[test]
    fn cleanup_old_visits_with_no_old_entries_returns_zero() {
        let mut storage = in_memory_storage();

        let records = vec![make_record("example.com", 5_000, DetectionSource::Dns)];
        storage.batch_insert(&records).expect("batch_insert should succeed");

        let removed = storage
            .cleanup_old_visits(1_000)
            .expect("cleanup should succeed");

        assert_eq!(removed, 0, "no rows should be removed when all are newer");
    }
}
