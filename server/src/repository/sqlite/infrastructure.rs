use anyhow::Context;

use super::SqliteRepository;
use crate::repository::impl_signature_repository;

impl_signature_repository!(
    SqliteRepository,
    "sqlite",
    "failed to run sqlite migrations"
);
