use anyhow::Context;

use super::SqliteRepository;
use crate::repository::cleanup::impl_cleanup_repository;

impl_cleanup_repository!(SqliteRepository);
