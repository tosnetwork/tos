/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! Error types for the TOS Sandbox.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Transaction execution failed: {0}")]
    ExecutionFailed(#[from] anyhow::Error),

    #[error("Get-method failed with exit code {exit_code}")]
    GetMethodFailed { exit_code: i32 },

    #[error("Message routing exceeded max depth {0}")]
    MaxDepthExceeded(usize),

    #[error("Contract has no code")]
    NoCode,

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Config error: {0}")]
    ConfigError(String),
}

pub type SandboxResult<T> = std::result::Result<T, SandboxError>;
