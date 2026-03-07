mod audit_log_tests;
mod cleanup_tests;
mod client_pairing_tests;
mod client_tests;
mod fixture;
mod helpers;
mod infrastructure_tests;
mod jti_tests;
mod pairing_tests;
mod request_tests;
mod signing_key_tests;

/// Generate parameterized test wrappers for both SQLite and PostgreSQL.
macro_rules! repo_test {
    ($name:ident) => {
        mod $name {
            #[tokio::test]
            async fn sqlite() {
                let f = super::super::fixture::SqliteTestFixture::setup().await;
                super::$name(&f).await;
            }

            #[tokio::test]
            #[ignore = "requires embedded PostgreSQL"]
            async fn postgres() {
                let f = super::super::fixture::PostgresTestFixture::setup().await;
                super::$name(&f).await;
            }
        }
    };
}
// Make macro available to child modules.
pub(super) use repo_test;
