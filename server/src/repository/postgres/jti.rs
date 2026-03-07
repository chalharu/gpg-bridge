use anyhow::Context;

use super::PostgresRepository;
use crate::repository::jti::impl_jti_repository;

impl_jti_repository!(PostgresRepository);
