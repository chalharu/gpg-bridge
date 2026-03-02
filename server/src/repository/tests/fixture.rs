use async_trait::async_trait;

use crate::repository::sqlite::SqliteRepository;
use crate::repository::sqlite::tests::build_sqlite_test_pool;
use crate::repository::{MIGRATOR, SignatureRepository};

#[async_trait]
pub(crate) trait TestFixture: Send + Sync {
    fn repo(&self) -> &dyn SignatureRepository;

    /// Count rows in the given table.  Useful for verifying side-effects
    /// that are not exposed through the repository trait (e.g. audit_log
    /// counts).
    async fn count_table_rows(&self, table: &str) -> i64;
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

    async fn count_table_rows(&self, table: &str) -> i64 {
        let query = format!("SELECT COUNT(*) FROM {table}");
        let count: i32 = sqlx::query_scalar(&query)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        i64::from(count)
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL (shared embedded instance)
// ---------------------------------------------------------------------------

use crate::repository::postgres::PostgresRepository;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::OnceCell;

struct SharedPostgres {
    _postgresql: postgresql_embedded::PostgreSQL,
    connect_options: PgConnectOptions,
}

// SAFETY: PostgreSQL from postgresql_embedded is Send+Sync in practice;
// the struct holds a child-process handle and connection metadata.
unsafe impl Send for SharedPostgres {}
unsafe impl Sync for SharedPostgres {}

static SHARED_PG: OnceCell<SharedPostgres> = OnceCell::const_new();

async fn get_shared_postgres() -> &'static SharedPostgres {
    SHARED_PG
        .get_or_init(|| async {
            let mut pg = postgresql_embedded::PostgreSQL::default();
            pg.setup().await.expect("PostgreSQL setup failed");
            pg.start().await.expect("PostgreSQL start failed");

            let settings = pg.settings();
            let connect_options = PgConnectOptions::new()
                .host(&settings.host)
                .port(settings.port)
                .username(&settings.username)
                .password(&settings.password);

            SharedPostgres {
                _postgresql: pg,
                connect_options,
            }
        })
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

    async fn count_table_rows(&self, table: &str) -> i64 {
        let query = format!("SELECT COUNT(*) FROM {table}");
        sqlx::query_scalar::<_, i64>(&query)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}
