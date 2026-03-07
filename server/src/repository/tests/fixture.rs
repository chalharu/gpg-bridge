use async_trait::async_trait;

use crate::repository::sqlite::SqliteRepository;
use crate::repository::sqlite::tests::build_sqlite_test_pool;
use crate::repository::{MIGRATOR, SignatureRepository};

#[async_trait]
pub(crate) trait TestFixture: Send + Sync {
    fn repo(&self) -> &dyn SignatureRepository;
    fn backend_name(&self) -> &'static str;
    fn foreign_key_error_fragment(&self) -> &'static str;

    /// Count rows in the given table.  Useful for verifying side-effects
    /// that are not exposed through the repository trait (e.g. audit_log
    /// counts).
    async fn count_table_rows(&self, table: &str) -> i64;

    async fn close_pool(&self);
    async fn execute_sql(&self, sql: &str) -> anyhow::Result<()>;
}

fn allowed_table_name(table: &str) -> &'static str {
    match table {
        "audit_log" => "audit_log",
        "client_pairings" => "client_pairings",
        "clients" => "clients",
        "jtis" => "jtis",
        "pairings" => "pairings",
        "requests" => "requests",
        "signing_keys" => "signing_keys",
        other => panic!(
            "unexpected table name in test fixture: {other}; allowed: audit_log, client_pairings, clients, jtis, pairings, requests, signing_keys"
        ),
    }
}

// ---------------------------------------------------------------------------
// SQLite
// ---------------------------------------------------------------------------

pub(crate) struct SqliteTestFixture {
    pub repo: SqliteRepository,
    pub pool: sqlx::SqlitePool,
}

impl SqliteTestFixture {
    pub async fn setup() -> Self {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };
        Self { repo, pool }
    }
}

#[async_trait]
impl TestFixture for SqliteTestFixture {
    fn repo(&self) -> &dyn SignatureRepository {
        &self.repo
    }

    fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    fn foreign_key_error_fragment(&self) -> &'static str {
        "FOREIGN KEY constraint failed"
    }

    async fn count_table_rows(&self, table: &str) -> i64 {
        let query = format!("SELECT COUNT(*) FROM [{}]", allowed_table_name(table));
        let count: i32 = sqlx::query_scalar(&query)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        i64::from(count)
    }

    async fn close_pool(&self) {
        self.pool.close().await;
    }

    async fn execute_sql(&self, sql: &str) -> anyhow::Result<()> {
        sqlx::query(sql).execute(&self.pool).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL (shared embedded instance)
// ---------------------------------------------------------------------------

use crate::repository::postgres::PostgresRepository;
use postgresql_embedded::{PostgreSQL, SettingsBuilder, VersionReq};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time::sleep;

const EMBEDDED_POSTGRES_VERSION: &str = "=18.2.0";
const EMBEDDED_POSTGRES_RETRY_COUNT: usize = 3;

struct SharedPostgres {
    _postgresql: postgresql_embedded::PostgreSQL,
    connect_options: PgConnectOptions,
}

// SAFETY: PostgreSQL from postgresql_embedded is Send+Sync in practice;
// the struct holds a child-process handle and connection metadata.
unsafe impl Send for SharedPostgres {}
unsafe impl Sync for SharedPostgres {}

static SHARED_PG: OnceCell<SharedPostgres> = OnceCell::const_new();

fn build_embedded_postgres() -> PostgreSQL {
    let version = std::env::var("GPG_BRIDGE_TEST_POSTGRES_VERSION")
        .unwrap_or_else(|_| EMBEDDED_POSTGRES_VERSION.to_string());
    let installation_dir = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".theseus")
        .join("postgresql");
    let settings = SettingsBuilder::new()
        .version(VersionReq::parse(&version).expect("invalid postgres version"))
        .installation_dir(installation_dir)
        .build();
    PostgreSQL::new(settings)
}

async fn start_shared_postgres_with_retry() -> SharedPostgres {
    for attempt in 1..=EMBEDDED_POSTGRES_RETRY_COUNT {
        let mut pg = build_embedded_postgres();
        let start_result = match pg.setup().await {
            Ok(()) => pg.start().await,
            Err(error) => Err(error),
        };

        if let Err(error) = start_result {
            if attempt == EMBEDDED_POSTGRES_RETRY_COUNT {
                panic!("PostgreSQL startup failed after {attempt} attempts: {error}");
            }
            drop(pg);
            sleep(Duration::from_secs(attempt as u64)).await;
            continue;
        }

        let settings = pg.settings();
        let connect_options = PgConnectOptions::new()
            .host(&settings.host)
            .port(settings.port)
            .username(&settings.username)
            .password(&settings.password);

        return SharedPostgres {
            _postgresql: pg,
            connect_options,
        };
    }

    unreachable!("retry loop should return or panic")
}

async fn get_shared_postgres() -> &'static SharedPostgres {
    SHARED_PG
        .get_or_init(|| async { start_shared_postgres_with_retry().await })
        .await
}

pub(crate) struct PostgresTestFixture {
    pub repo: PostgresRepository,
    pub pool: sqlx::PgPool,
}

impl PostgresTestFixture {
    pub async fn setup() -> Self {
        let shared = get_shared_postgres().await;
        let db_name = format!("test_{}", uuid::Uuid::new_v4().simple());

        // Connect to the default 'postgres' database to create our test DB.
        let admin_opts = shared.connect_options.clone().database("postgres");
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(admin_opts)
            .await
            .expect("failed to connect admin pool");

        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin_pool)
            .await
            .expect("failed to create test database");
        admin_pool.close().await;

        // Connect to the newly created test database.
        let test_opts = shared.connect_options.clone().database(&db_name);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(test_opts)
            .await
            .expect("failed to connect test pool");

        MIGRATOR.run(&pool).await.unwrap();

        let repo = PostgresRepository { pool: pool.clone() };
        Self { repo, pool }
    }
}

#[async_trait]
impl TestFixture for PostgresTestFixture {
    fn repo(&self) -> &dyn SignatureRepository {
        &self.repo
    }

    fn backend_name(&self) -> &'static str {
        "postgres"
    }

    fn foreign_key_error_fragment(&self) -> &'static str {
        "violates foreign key constraint"
    }

    async fn count_table_rows(&self, table: &str) -> i64 {
        let query = format!("SELECT COUNT(*) FROM \"{}\"", allowed_table_name(table));
        sqlx::query_scalar::<_, i64>(&query)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn close_pool(&self) {
        self.pool.close().await;
    }

    async fn execute_sql(&self, sql: &str) -> anyhow::Result<()> {
        sqlx::query(sql).execute(&self.pool).await?;
        Ok(())
    }
}
