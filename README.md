# neptune-auth
This package is used to manage the authentication of callers for any arbitrary message type.
This code is currently not audited and should be used with caution.
When auditing is complete (sometime in Q1 2023) this warning will be removed.

**Usage**

The first step is to create some sort of config type which has access to stored addresses.
```rust
#[derive(Copy, Display)]
#[cw_serde]
pub enum Config {
    Admin,
    Bot,
}
```

Then you should impl GetPermissionGroup for the Config.
```rust
impl GetPermissionGroup for Config {
    fn get_permission_group(&self, deps: Deps, _env: &Env) -> Result<PermissionGroup, NeptAuthError> {
        /// How your config accesses storage is up to you
        /// Here we use a map from cw_storage_plus
        Ok(vec![self.load(deps).unwrap()].into())
    }
}
```

Then you can can assign a permission group for each variant in a given message type.
Here I use ExecuteMsg as an example.
```rust
use crate::config::Config::*;

impl NeptuneAuth for ExecuteMsg {
    fn permissions(&self) -> Result<Vec<&dyn GetPermissionGroup>, NeptAuthError> {
        Ok(match self {
            ExecuteMsg::SetConfig { .. } => vec![&Admin],
            ExecuteMsg::AddAsset { .. } => vec![&Bot],
            ExecuteMsg::RemoveAsset { .. } => vec![&Bot],
            ExecuteMsg::UpdatePrices { .. } => vec![&Admin, &Bot],
        })
    }
}
```

And finally you place the authorization check inside the execute entry point.
```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, MyError> {
    // This is the line that checks the permissions
    // It will return an error if the caller does not have the required permissions
    msg.neptune_authorize(deps.as_ref(), &env, &info.sender)?;

    ...
}
```