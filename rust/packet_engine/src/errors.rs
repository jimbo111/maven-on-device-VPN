use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("Failed to open database: {0}")]
    DatabaseOpen(#[from] rusqlite::Error),

    #[error("Failed to write to database: {0}")]
    DatabaseWrite(String),

    #[error("Invalid database path: {0}")]
    InvalidPath(String),

    #[error("Engine already initialized")]
    AlreadyInitialized,

    #[error("Engine not initialized")]
    NotInitialized,
}
