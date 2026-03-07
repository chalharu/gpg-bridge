use anyhow::Context;

use super::SqliteRepository;
use crate::repository::jti::impl_jti_repository;

impl_jti_repository!(SqliteRepository);
