use std::{fmt::Debug, error::Error};
use cosmwasm_std::{Deps, Addr, Env,};
use crate::{
    error::{NeptuneAuthorizationError, NeptuneAuthorizationResult},
};

#[derive(Clone, Debug)]
pub enum PermissionGroup {
    Public,
    Restricted(Vec<Addr>),
}

impl From<Vec<Addr>> for PermissionGroup {
    fn from(vec: Vec<Addr>) -> Self {
        Self::Restricted(vec)
    }
}

pub trait GetPermissionGroup: Debug {
    fn get_permission_group(&self, deps: Deps, env: &Env) -> Result<PermissionGroup, Box<dyn Error>>;
}

pub type PermissionGroupList<'a> = Vec<&'a dyn GetPermissionGroup>;

#[derive(Clone, Debug)]
pub enum BasePermissionGroups {
    Internal,
    Public,
}

impl GetPermissionGroup for BasePermissionGroups {
    fn get_permission_group(&self, _deps: Deps, env: &Env) -> Result<PermissionGroup, Box<dyn Error>> {

        Ok(match self {
            Self::Internal          => PermissionGroup::Restricted(vec![env.contract.address.clone()]),
            Self::Public            => PermissionGroup::Public,
        })
    }
}

pub trait NeptuneContractAuthorization<M> {
    fn permissions(msg: &M) -> Result<PermissionGroupList, Box<dyn Error>>;
}

/// Structure to pass the base authorization levels for a global permissions check on all executes
#[derive(Copy, Clone)]
pub struct BaseAuthorization {}

pub fn neptune_execute_authorize<M, A: NeptuneContractAuthorization<M>>(
    deps: Deps,
    env: &Env,
    address: &Addr,
    message: &M,
) -> Result<(), Box<dyn Error>> {
    let permission_result = A::permissions(message);

    match permission_result {
        Ok(p) => authorize_permissions(deps.clone(), env, address, &p),
        Err(e) => Err(e),
    }
}

pub fn authorize_permissions(
    deps: Deps,
    env: &Env,
    addr: &Addr,
    permissions: &PermissionGroupList,
) -> Result<(), Box<dyn Error>> {
    let collected_permissions: Result<Vec<PermissionGroup>, Box<dyn Error>> = permissions.iter()
    .map(|x| x.get_permission_group(deps, env))
    .collect();

    let flattened = flatten_permissions(collected_permissions?)?;

    match flattened {
        PermissionGroup::Public => return Ok(()),
        PermissionGroup::Restricted(vec) => {
            if vec.iter().any(|i| *i == *addr) { return Ok(())}
            else {
                return Err(NeptuneAuthorizationError::Unauthorized(format!("Unauthorized execution: {} is not {:?}", *addr, permissions)).into()) 
            }
        },
    }
}

fn flatten_permissions(permission_group_vec: Vec<PermissionGroup>) -> NeptuneAuthorizationResult<PermissionGroup> {
    if permission_group_vec.len() == 0 {
        return Err(NeptuneAuthorizationError::InvalidPermissionGroup("No permission groups supplied".to_string()));
    } else if permission_group_vec.len() == 1 {
        return Ok(permission_group_vec[0].clone())
    } else {
        let mut result_vec: Vec<Addr> = vec![];
        for i in permission_group_vec {
            match i {
                PermissionGroup::Public => return Err(NeptuneAuthorizationError::InvalidPermissionGroup("Public must be only entry in permission group list".to_string())),
                PermissionGroup::Restricted(vec) => result_vec = [result_vec, vec].concat()
            }
        }
        return Ok(PermissionGroup::Restricted(result_vec))
    }
}
