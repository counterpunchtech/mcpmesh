//! The gated per-scope app-blob provider. A SEPARATE transport from
//! the roster blob (`roster::transport::RosterBlobs`, MemStore, `iroh_blobs::ALPN`, ungated): an
//! `FsStore` at `<data_dir>/blobs/` advertised on `APP_BLOB_ALPN`, built with
//! `BlobsProtocol::new(&fsstore, Some(events))` so a request-time Intercept hook (`provider`) can
//! serve a hash ONLY to callers a scope grants (`scope`). Hashes are integrity proofs, never
//! capabilities: authorization is a separate scope-membership decision keyed on the AUTHENTICATED
//! endpoint id resolved via the daemon's trust gate.
pub mod provider;
pub mod scope;

/// The app-blob ALPN (the named `mcpmesh/blob/1` protocol), DISTINCT from `iroh_blobs::ALPN`
/// (which the untouched roster provider AND the iroh-blobs `Downloader` are pinned to). The daemon
/// accept loop dispatches this ALPN to the gated `AppBlobs` provider; the caller-side fetch opens a
/// connection on it and uses `store.remote().fetch` (the Downloader cannot — it hardcodes
/// `iroh_blobs::ALPN`).
pub const APP_BLOB_ALPN: &[u8] = b"mcpmesh/blob/1";
