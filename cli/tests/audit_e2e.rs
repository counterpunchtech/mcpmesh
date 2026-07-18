//! M4b E2E (spec §11.3): a REAL in-process mesh session lands audit records with the arguments
//! HASHED (the raw argument bytes never appear in the file) and the session + proxied-request event
//! classes present. The trust class is proven by `trust_mutations_emit_audit_events` and the
//! blob-fetch class by `served_get_records_blob_fetch_audit` (both Task 5).
//!
//! Harness: a direct `serve(...)` + `mcpmesh_net::connect(...)` mesh over two localhost endpoints (no
//! subprocess, no control socket). `connect` dials the FULL server address, so there is no id→addr
//! discovery step and no `MemoryLookup`. The audit sink writes to a hermetic temp dir.
use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::audit::{AuditLog, AuditSink};
use mcpmesh::config::Config;
use mcpmesh::daemon::build_services_audited;
use mcpmesh_net::{TrustGate, serve};
use serde_json::json;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

async fn local_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![mcpmesh_net::ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind localhost endpoint")
}

#[tokio::test]
async fn real_session_audits_with_hashed_args_and_all_event_classes() {
    timeout(Duration::from_secs(90), async {
        let secret = "TOP-SECRET-ARGUMENT-do-not-log-me";
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");

        // The serving "server machine" endpoint: an echo `run` service audited to `audit_dir`.
        // Capture the address BEFORE `server_ep` is moved into `serve` below.
        let server_ep = local_endpoint().await;
        let server_addr = server_ep.addr();

        // Trust the caller endpoint (the connecting side) as petname "bob". `PeerEntry` is a struct
        // literal (allowlist.rs) — fields are `endpoint_id` / `petname` / `services` / `paired_at`
        // (mirrors proxy_roundtrip.rs); there is no `PeerEntry::new`.
        let caller_ep = local_endpoint().await;
        let caller_id = *caller_ep.id().as_bytes();
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new({
            let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
            store
                .add(PeerEntry {
                    endpoint_id: caller_id,
                    petname: "bob".into(),
                    services: vec!["notes".into()],
                    paired_at: None,
                    user_id: None,
                })
                .unwrap();
            store
        }));

        // Serve an echo `run` service named "notes", threaded with a REAL audit sink.
        // TOML LITERAL string for the stub path (like every sibling suite): a windows
        // `D:\…\stub.exe` path in a basic "…" string is an invalid escape sequence.
        let cfg = Config::from_toml_str(&format!(
            "[services.notes]\nrun = ['{STUB}']\nallow = [\"bob\"]\n"
        ))
        .unwrap();
        let sink = AuditSink::new(AuditLog::spawn(audit_dir.clone()));
        let _serve = serve(
            server_ep,
            gate,
            build_services_audited(&cfg, &sink, &mcpmesh::limits::MeshLimiters::unlimited()),
        );

        // Drive one MCP session over the mesh from the caller endpoint: connect (dialing the FULL
        // server address — no id→addr discovery, no MemoryLookup), initialize, then a tools/call whose
        // arguments carry `secret`.
        let mut transport = mcpmesh_net::connect(&caller_ep, server_addr, "notes")
            .await
            .unwrap();
        // initialize
        transport
            .send_value(json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{"_meta":{"mcpmesh/service":"notes"},"capabilities":{}}
            }))
            .await
            .unwrap();
        let _init = transport.recv_value().await.unwrap().unwrap();
        // tools/call with the sensitive argument.
        transport
            .send_value(json!({
                "jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"read_file","arguments":{"text":secret}}
            }))
            .await
            .unwrap();
        let call = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(call["id"], 2);
        drop(transport); // EOF → session_close

        // Poll the audit file until the request record lands.
        let month = &mcpmesh::audit::now_ts()[..7];
        let file = audit_dir.join(format!("{month}.jsonl"));
        let mut body = String::new();
        for _ in 0..100 {
            if let Ok(b) = std::fs::read_to_string(&file)
                && b.contains("\"kind\":\"request\"")
                && b.contains("\"kind\":\"session_open\"")
                && b.contains("\"kind\":\"session_close\"")
            {
                body = b;
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }

        // PRIVACY (the headline): the raw argument NEVER appears anywhere in the audit file.
        assert!(
            !body.contains(secret),
            "raw argument leaked into the audit log:\n{body}"
        );
        // The request record carries the tool NAME + a blake3 args hash + a bytes_out count.
        assert!(body.contains("\"tool\":\"read_file\""));
        assert!(body.contains("\"method\":\"tools/call\""));
        assert!(body.contains("blake3:"));
        assert!(body.contains("\"bytes_out\":"));
        assert!(body.contains("\"peer\":\"bob\""));
        // Session lifecycle present.
        assert!(body.contains("\"kind\":\"session_open\""));
        assert!(body.contains("\"kind\":\"session_close\""));
    })
    .await
    .expect("audit E2E timed out");
}
