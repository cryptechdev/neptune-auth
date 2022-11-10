use cosmwasm_std::{OverflowError, StdError};
use thiserror::Error;

pub type NeptuneAuthorizationResult<T> = core::result::Result<T, NeptAuthError>;

const AUTH_ERR: &str = "Neptune Authorization Error -";

#[derive(Error, Debug, PartialEq)]
pub enum NeptAuthError {
    #[error("{0}")]
    Error(String),

    #[error("{} Generic: {0}", AUTH_ERR)]
    Generic(String),

    #[error("{} StdError: {0}", AUTH_ERR)]
    Std(#[from] StdError),

    #[error("{} OverflowError: {0}", AUTH_ERR)]
    OverflowError(#[from] OverflowError),

    #[error("{} Unauthorized: {0}", AUTH_ERR)]
    Unauthorized(String),

    #[error("{} Invalid permission group: {0}", AUTH_ERR)]
    InvalidPermissionGroup(String),
}
