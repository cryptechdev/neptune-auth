use cosmwasm_std::Addr;
use thiserror::Error;

pub type NeptuneAuthorizationResult<T> = core::result::Result<T, NeptAuthError>;

const AUTH_ERR: &str = "Neptune Auth Error -";

#[derive(Error, Debug, PartialEq)]
pub enum NeptAuthError {
    #[error("{} Unauthorized: {sender} is not {permission_group}", AUTH_ERR)]
    Unauthorized { sender: Addr, permission_group: String },
    #[error("{} Invalid permission group: {0}", AUTH_ERR)]
    InvalidPermissionGroup(String),
}
