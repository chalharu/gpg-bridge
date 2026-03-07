use anyhow::Context;

use super::PostgresRepository;
use crate::repository::impl_signature_repository;

impl_signature_repository!(
    PostgresRepository,
    "postgres",
    "failed to run postgres migrations"
);
