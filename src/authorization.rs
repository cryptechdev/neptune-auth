use std::fmt::Debug;

use cosmwasm_std::{Addr, Deps, Env};

use crate::error::{NeptAuthError, NeptuneAuthorizationResult};

#[derive(Clone, Debug)]
pub enum PermissionGroup {
    Public,
    Restricted(Vec<Addr>),
}

impl From<Vec<Addr>> for PermissionGroup {
    fn from(vec: Vec<Addr>) -> Self { Self::Restricted(vec) }
}

pub trait NeptuneAuth<M> {
    fn permissions(msg: &M) -> Result<PermissionGroupList, NeptAuthError>;
}

pub trait GetPermissionGroup: Debug {
    fn get_permission_group(&self, deps: Deps, env: &Env) -> Result<PermissionGroup, NeptAuthError>;
}

pub type PermissionGroupList<'a> = Vec<&'a dyn GetPermissionGroup>;

#[derive(Clone, Debug)]
pub enum BasePermissionGroups {
    Internal,
    Public,
}

impl GetPermissionGroup for BasePermissionGroups {
    fn get_permission_group(&self, _deps: Deps, env: &Env) -> Result<PermissionGroup, NeptAuthError> {
        Ok(match self {
            Self::Internal => PermissionGroup::Restricted(vec![env.contract.address.clone()]),
            Self::Public => PermissionGroup::Public,
        })
    }
}

/// This function is placed inside the contracts' execute function.
pub fn neptune_execute_authorize<M, A: NeptuneAuth<M>>(
    deps: Deps, env: &Env, address: &Addr, message: &M,
) -> Result<(), NeptAuthError> {
    let permissions = A::permissions(message)?;
    authorize_permissions(deps, env, address, &permissions)
}

/// Verifies that the given address is contained within the given permission group list.
pub fn authorize_permissions(
    deps: Deps, env: &Env, addr: &Addr, permissions: &PermissionGroupList,
) -> Result<(), NeptAuthError> {
    let collected_permissions: Result<Vec<PermissionGroup>, NeptAuthError> =
        permissions.iter().map(|x| x.get_permission_group(deps, env)).collect();

    let flattened = flatten_permissions(collected_permissions?)?;

    match flattened {
        PermissionGroup::Public => Ok(()),
        PermissionGroup::Restricted(vec) => {
            if vec.iter().any(|i| *i == *addr) {
                Ok(())
            } else {
                Err(NeptAuthError::Unauthorized {
                    sender:           addr.clone(),
                    permission_group: format!("{permissions:?}"),
                })
            }
        }
    }
}

/// Flattens a permission group list into a single permission group.
fn flatten_permissions(permission_group_vec: Vec<PermissionGroup>) -> NeptuneAuthorizationResult<PermissionGroup> {
    if permission_group_vec.is_empty() {
        // Don't allow empty permission groups.
        Err(NeptAuthError::InvalidPermissionGroup("No permission groups supplied".to_string()))
    } else if permission_group_vec.len() == 1 {
        // We only allow the public permission group if it alone.
        Ok(permission_group_vec[0].clone())
    } else {
        // General case, flatten all the permission groups into one.
        let mut result_vec: Vec<Addr> = vec![];
        for permission_group in permission_group_vec {
            match permission_group {
                PermissionGroup::Public => {
                    return Err(NeptAuthError::InvalidPermissionGroup(
                        "Public must be only entry in permission group list".to_string(),
                    ))
                }
                PermissionGroup::Restricted(vec) => result_vec = [result_vec, vec].concat(),
            }
        }
        return Ok(PermissionGroup::Restricted(result_vec));
    }
}
