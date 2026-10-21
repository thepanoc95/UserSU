use std::path::PathBuf;

/// Errors produced by UserSU core logic.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse configuration: {0}")]
    Config(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("operation requires root: {0}")]
    NotRoot(&'static str),

    #[error("filesystem is not writable: {0}")]
    NotWritable(PathBuf),

    #[error("path escapes the UserFS root: {0}")]
    PathEscape(PathBuf),

    #[error("path not found: {0}")]
    PathNotFound(PathBuf),

    #[error("unsupported operation: {0}")]
    Unsupported(String),

    #[error("usud is not running")]
    DaemonNotRunning,

    #[error("usud protocol error: {0}")]
    Protocol(String),

    #[error("sandbox error: {0}")]
    Sandbox(String),
}

pub type Result<T> = std::result::Result<T, Error>;
