//! The `subscribe` live event stream (pairing liveness & health telemetry). One tagged envelope per
//! frame; `Event.record` is the existing [`AuditRecord`] verbatim, so the stream and the on-disk log
//! carry ONE schema. Producer-side only — the daemon serializes these frames; the consumer (Task 8's
//! `internal watch`) reads them as untyped JSON.
use mcpmesh_local_api::PeerReachability;

use crate::audit::AuditRecord;
use crate::audit::log::ActiveSession;

/// One frame of the `subscribe` stream. Tagged on `type` (snake_case), so a frame is
/// `{"type":"snapshot",...}` / `{"type":"event",...}` / `{"type":"lagged",...}`.
#[derive(serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamFrame {
    /// The FIRST frame: a point-in-time picture of the mesh (open sessions + paired-peer
    /// reachability) so a fresh subscriber renders immediately without replaying history.
    Snapshot {
        active_sessions: Vec<ActiveSession>,
        reachability: Vec<PeerReachability>,
    },
    /// A live audit event (session open/close, request, blob fetch, trust) — the tap on the hub.
    /// Boxed so this (much larger) variant does not bloat every frame; serde delegates through the
    /// `Box`, so the wire shape is the record's fields verbatim.
    Event { record: Box<AuditRecord> },
    /// The subscriber fell `dropped` records behind the broadcast ring; the stream continues (a
    /// fresh reconnect would re-`Snapshot`). Never drops the subscriber (spec: backpressure).
    Lagged { dropped: u64 },
}
