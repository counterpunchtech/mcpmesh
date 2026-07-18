//! mcpmesh-trust: key generation/storage and trust gates (PairGate/RosterGate land in M2/M3).
pub mod binding;
pub mod keys;
pub mod paths;
pub mod roster;
pub use keys::{DeviceKey, KeyError, OrgRootKey, UserKey};
pub use roster::mutate::{empty_roster, remove_user, revoke_device, upsert_member};
pub use roster::validate::{ResolvedDevice, RosterState, RosterView};
pub use roster::{Roster, RosterDevice, RosterError, RosterUser};
