use thiserror::Error;
use tokio_postgres::error::Error as PgError;

#[derive(Error, Debug)]
pub enum RyhopeError {
    /// An error that occured while interacting with the DB.
    #[error("DB error while {msg}: {err}")]
    DbError { msg: String, err: PgError },

    /// An error that occured while interacting with the DB.
    #[error("DB error while {msg}: {err}")]
    DbPoolError {
        msg: String,
        err: bb8::RunError<PgError>,
    },

    /// The internal state is incoherent; this is a bug.
    #[error("internal Error: {0}")]
    Internal(String),

    /// Unable to extract data from the DB
    #[error("unable to deserialize data while {msg}: {err}")]
    InvalidFormat { msg: String, err: PgError },

    /// A non-recoverable error
    #[error("fatal error: {0}")]
    Fatal(String),
}
impl RyhopeError {
    pub fn from_db<S: AsRef<str>>(msg: S, err: PgError) -> Self {
        RyhopeError::DbError {
            msg: msg.as_ref().to_string(),
            err,
        }
    }

    pub fn from_bb8<S: AsRef<str>>(msg: S, err: bb8::RunError<PgError>) -> Self {
        RyhopeError::DbPoolError {
            msg: msg.as_ref().to_string(),
            err,
        }
    }

    pub fn invalid_format<S: AsRef<str>>(msg: S, err: PgError) -> Self {
        RyhopeError::InvalidFormat {
            msg: msg.as_ref().to_string(),
            err,
        }
    }

    pub fn internal<S: AsRef<str>>(msg: S) -> Self {
        RyhopeError::Internal(msg.as_ref().to_string())
    }

    pub fn fatal<S: AsRef<str>>(msg: S) -> Self {
        RyhopeError::Fatal(msg.as_ref().to_string())
    }
}

pub fn ensure<S: AsRef<str>>(cond: bool, msg: S) -> Result<(), RyhopeError> {
    if cond {
        Ok(())
    } else {
        Err(RyhopeError::fatal(msg.as_ref()))
    }
}
