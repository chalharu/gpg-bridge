use anyhow::Context;

use super::PostgresRepository;
use crate::repository::cleanup::impl_cleanup_repository;

impl_cleanup_repository!(PostgresRepository);
