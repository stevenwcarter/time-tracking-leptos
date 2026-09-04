//! Diesel r2d2 pool, connection PRAGMAs, and embedded migrations.
//!
//! Migrations are compiled in via `diesel_migrations` and run on every
//! startup. They are idempotent, so there is no separate migrate step and
//! the image ships no `migrations/` directory.

use std::env;
use std::fs;
use std::path::Path;

use diesel::connection::SimpleConnection;
use diesel::r2d2::{
    ConnectionManager, CustomizeConnection, Error as R2d2Error, Pool, PooledConnection,
};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;
pub type DbConn = PooledConnection<ConnectionManager<SqliteConnection>>;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

/// Applies SQLite PRAGMAs to every pooled connection.
///
/// `busy_timeout` MUST come first: `journal_mode = WAL` takes an exclusive
/// lock on the DB header, and r2d2 opens its initial connections in parallel.
/// Without a busy timeout already in effect the racing connections see
/// SQLITE_BUSY immediately and pool construction fails.
///
/// `foreign_keys` is per-connection, not per-database — set here or the
/// schema's ON DELETE CASCADE clauses silently do nothing.
#[derive(Debug)]
struct ConnectionInit;

impl CustomizeConnection<SqliteConnection, R2d2Error> for ConnectionInit {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), R2d2Error> {
        conn.batch_execute(
            "PRAGMA busy_timeout = 5000; \
             PRAGMA journal_mode = WAL; \
             PRAGMA foreign_keys = ON;",
        )
        .map_err(R2d2Error::QueryError)
    }
}

/// Builds a pool from `DATABASE_URL` (default `./data/time-tracking.db`),
/// creating the parent directory if needed.
///
/// `:memory:` is capped at one connection on purpose. A bare `:memory:` URL
/// gives each connection its *own* empty database, so a multi-connection pool
/// would hand some callers an unmigrated schema.
pub fn build_pool() -> anyhow::Result<DbPool> {
    let url = env::var("DATABASE_URL").unwrap_or_else(|_| "./data/time-tracking.db".to_string());

    let max_size = if url == ":memory:" {
        1
    } else {
        if let Some(parent) = Path::new(&url).parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        8
    };

    let manager = ConnectionManager::<SqliteConnection>::new(&url);
    Ok(Pool::builder()
        .max_size(max_size)
        .connection_customizer(Box::new(ConnectionInit))
        .build(manager)?)
}

/// Runs all pending migrations. Idempotent; call once at startup.
pub fn run_migrations(pool: &DbPool) -> anyhow::Result<()> {
    let mut conn = pool.get()?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("migrations failed: {e}"))?;
    Ok(())
}

/// A migrated, single-connection in-memory pool for tests.
///
/// Not `#[cfg(test)]`: integration tests and other modules' test suites use
/// it too, and `#[cfg(test)]` items are invisible across crate-internal test
/// binaries. Gated on `ssr` so it never reaches the wasm bundle.
#[cfg(feature = "ssr")]
pub fn test_pool() -> DbPool {
    let manager = ConnectionManager::<SqliteConnection>::new(":memory:");
    let pool = Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(ConnectionInit))
        .build(manager)
        .expect("in-memory pool");
    run_migrations(&pool).expect("migrations apply");
    pool
}

#[cfg(test)]
mod tests {
    // `SqlQuery::get_result` below is a `RunQueryDsl` method; `super::*`
    // doesn't carry it in because the pool/migration code never calls it.
    use diesel::RunQueryDsl;

    use super::*;

    /// An in-memory pool must apply migrations and be usable afterwards.
    #[test]
    fn memory_pool_applies_migrations() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let n: i64 = diesel::sql_query("SELECT COUNT(*) AS c FROM user")
            .get_result::<Count>(&mut conn)
            .expect("user table exists")
            .c;
        assert_eq!(n, 0);
    }

    /// `foreign_keys` is per-connection and MUST be set by the customizer;
    /// without it the ON DELETE CASCADE in the schema silently does nothing.
    #[test]
    fn foreign_keys_pragma_is_on() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        // `PRAGMA foreign_keys` alone returns a column named `foreign_keys`,
        // not `c`; go through the pragma table-valued function so the
        // shared `Count` helper (which expects column `c`) still applies.
        let on: i64 = diesel::sql_query("SELECT foreign_keys AS c FROM pragma_foreign_keys()")
            .get_result::<Count>(&mut conn)
            .expect("pragma readable")
            .c;
        assert_eq!(on, 1, "foreign_keys must be ON for cascade deletes to work");
    }

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        c: i64,
    }
}
