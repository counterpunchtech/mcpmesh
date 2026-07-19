//! mcpmesh-trust: key generation/storage and trust gates (PairGate/RosterGate land in M2/M3).
pub mod binding;
pub mod keys;
pub mod roster;
pub use keys::{DeviceKey, KeyError, OrgRootKey, UserKey};
/// The §13 paths rule lives on `mcpmesh-local-api` (the featureless vocabulary crate —
/// plugins are barred from depending on trust, and the endpoint formula must have ONE
/// home); re-exported here so `mcpmesh_trust::paths::…` stays a valid spelling.
pub use mcpmesh_local_api::paths;
pub use roster::mutate::{empty_roster, remove_user, revoke_device, upsert_member};
pub use roster::validate::{ResolvedDevice, RosterState, RosterView};
pub use roster::{Roster, RosterDevice, RosterError, RosterUser};
