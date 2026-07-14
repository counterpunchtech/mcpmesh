//! The family's one wire codec: compact JSON, UTF-8, one frame per `\n`, 16 MiB cap
//! (mcpmesh §7.3). Re-exported from `mcpmesh-codec` — ONE implementation, provably shared
//! with the daemon side (`mcpmesh_net::framing` re-exports the same crate), closing the
//! old [RECONCILE-CODEC] fresh-copy drift. `mcpmesh-codec` links no iroh, so this stays a
//! no-iroh client crate (host §7.1).
pub use mcpmesh_codec::{FrameReader, Inbound, MAX_FRAME_BYTES, Violation, write_frame};
