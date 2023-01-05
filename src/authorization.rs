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

pub trait NeptuneContractAuthorization<M> {
    fn permissions(msg: &M) -> Result<PermissionGroupList, NeptAuthError>;
}

pub fn neptune_execute_authorize<M, A: NeptuneContractAuthorization<M>>(
    deps: Deps, env: &Env, address: &Addr, message: &M,
) -> Result<(), NeptAuthError> {
    let permissions = A::permissions(message)?;
    authorize_permissions(deps, env, address, &permissions)
}

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
                Err(NeptAuthError::Unauthorized(format!("Unauthorized execution: {} is not {:?}", *addr, permissions)))
            }
        }
    }
}

fn flatten_permissions(permission_group_vec: Vec<PermissionGroup>) -> NeptuneAuthorizationResult<PermissionGroup> {
    if permission_group_vec.is_empty() {
        Err(NeptAuthError::InvalidPermissionGroup("No permission groups supplied".to_string()))
    } else if permission_group_vec.len() == 1 {
        Ok(permission_group_vec[0].clone())
    } else {
        let mut result_vec: Vec<Addr> = vec![];
        for i in permission_group_vec {
            match i {
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
