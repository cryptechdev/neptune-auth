use crate::error::{NeptAuthError, NeptAuthResult};
use cosmwasm_std::{Addr, CustomQuery, Deps, Empty, Env};
use std::fmt::Debug;

/// The basic type for a permission group.
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

pub type PermissionGroupList<'a, C> = Vec<&'a dyn GetPermissionGroup<C>>;

/// This trait should be derived for any type that requires authorization.
pub trait NeptuneAuth {
    fn permissions<C: CustomQuery>(&self) -> NeptAuthResult<PermissionGroupList<C>>;

    /// This function is placed inside the contracts' execute function.
    fn neptune_authorize(
        &self,
        deps: Deps<impl CustomQuery>,
        env: &Env,
        address: &Addr,
    ) -> NeptAuthResult<()> {
        let permissions = self.permissions()?;
        authorize_permissions(deps, env, address, &permissions)
    }
}

/// This trait determines how a permission group is retrieved.
/// It will usually be derived for your config type.
pub trait GetPermissionGroup<C = Empty>: Debug
where
    C: CustomQuery,
{
    fn get_permission_group(&self, deps: Deps<C>, env: &Env) -> NeptAuthResult<PermissionGroup>;
}

/// These base permission groups are starting points.
/// You should create other enums for custom permission groups.
#[derive(Clone, Debug)]
pub enum BasePermissionGroups {
    Internal,
    Public,
}

/// This is an example of how to implement the GetPermissionGroup trait.
impl<C> GetPermissionGroup<C> for BasePermissionGroups
where
    C: CustomQuery,
{
    fn get_permission_group(&self, _deps: Deps<C>, env: &Env) -> NeptAuthResult<PermissionGroup> {
        Ok(match self {
            Self::Internal => PermissionGroup::Restricted(vec![env.contract.address.clone()]),
            Self::Public => PermissionGroup::Public,
        })
    }
}

/// Verifies that the given address is contained within the given permission group list.
pub fn authorize_permissions<C: CustomQuery>(
    deps: Deps<C>,
    env: &Env,
    addr: &Addr,
    permissions: &PermissionGroupList<C>,
) -> NeptAuthResult<()> {
    let collected_permissions = permissions
        .iter()
        .map(|x| x.get_permission_group(deps, env))
        .collect::<Result<Vec<_>, _>>()?;

    let flattened = flatten_permissions(collected_permissions)?;

    match flattened {
        PermissionGroup::Public => Ok(()),
        PermissionGroup::Restricted(vec) => {
            if vec.contains(addr) {
                Ok(())
            } else {
                Err(NeptAuthError::Unauthorized {
                    sender: addr.clone(),
                    permission_group: format!("{permissions:?}"),
                })
            }
        }
    }
}

/// Flattens a permission group list into a single permission group.
fn flatten_permissions(
    permission_group_vec: Vec<PermissionGroup>,
) -> NeptAuthResult<PermissionGroup> {
    if permission_group_vec.is_empty() {
        // Don't allow empty permission groups.
        Err(NeptAuthError::EmptyPermissionGroupList)
    } else if permission_group_vec.len() == 1 {
        // We only allow the public permission group if it is alone.
        Ok(permission_group_vec[0].clone())
    } else {
        // General case, flatten all the permission groups into one.
        let mut result_vec: Vec<Addr> = vec![];
        for permission_group in permission_group_vec {
            match permission_group {
                PermissionGroup::Public => return Err(NeptAuthError::InvalidPublic),
                PermissionGroup::Restricted(vec) => result_vec = [result_vec, vec].concat(),
            }
        }
        return Ok(PermissionGroup::Restricted(result_vec));
    }
}
