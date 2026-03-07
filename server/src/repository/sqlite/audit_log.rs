use anyhow::Context;

use super::SqliteRepository;
use crate::repository::audit_log::impl_audit_log_repository;

impl_audit_log_repository!(SqliteRepository);
