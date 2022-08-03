use cosmwasm_std::{OverflowError, StdError};
use thiserror::Error;

pub type NeptuneAuthorizationResult<T> = core::result::Result<T, NeptuneAuthorizationError>;

const NEPT_AUTH_ERR: &str = "Neptune Authorization Error -";

#[derive(Error, Debug, PartialEq)]
pub enum NeptuneAuthorizationError {
    #[error("{0}")]
    Error(String),

    #[error("{} Generic: {0}", NEPT_AUTH_ERR)]
    Generic(String),

    #[error("{} StdError: {0}", NEPT_AUTH_ERR)]
    Std(#[from] StdError),

    #[error("{} OverflowError: {0}", NEPT_AUTH_ERR)]
    OverflowError(#[from] OverflowError),

    #[error("{} Unauthorized: {0}", NEPT_AUTH_ERR)]
    Unauthorized(String),

    #[error("{} Invalid permission group: {0}", NEPT_AUTH_ERR)]
    InvalidPermissionGroup(String),
}
