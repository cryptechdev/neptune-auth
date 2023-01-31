use cosmwasm_std::{Addr, StdError};
use thiserror::Error;

pub type NeptAuthResult<T> = core::result::Result<T, NeptAuthError>;

const AUTH_ERR: &str = "Neptune Auth Error -";

#[derive(Error, Debug, PartialEq)]
pub enum NeptAuthError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{} Unauthorized: {sender} is not {permission_group}", AUTH_ERR)]
    Unauthorized { sender: Addr, permission_group: String },

    #[error("{} Public must be only entry in permission group list", AUTH_ERR)]
    InvalidPublic,

    #[error("{} Empty permission group list", AUTH_ERR)]
    EmptyPermissionGroupList,
}
