//! Every value the porcelain prints under `--json` — the machine face, as pure
//! unit-tested builders. [`crate::render`] owns the human strings; this module owns
//! the JSON mirror. Shapes serialize the mcpmesh-local/1 result types verbatim
//! wherever one exists (additive discipline: an absent field means empty/none, same
//! as the wire), plus small hand-built objects for verbs with no API result. One
//! JSON value per invocation on stdout; a failure is one
//! `{"error":{"code":…,"message":…}}` line on stderr.

use mcpmesh_local_api::{Hello, InviteResult, PairResult, StatusResult};

use crate::doctor::{Level, Verdict};
use crate::{client, render};

/// The `--json` error object: the SAME human message [`render::error_lines`]
/// produces (joined, without the leading "Error: "), plus the control-API JSON-RPC
/// `code` when the failure came from the daemon — the machine-branchable field the
/// human path deliberately hides.
pub fn error_json(err: &anyhow::Error) -> serde_json::Value {
    let code = err
        .chain()
        .find_map(|cause| match cause.downcast_ref::<client::ClientError>() {
            Some(client::ClientError::Api(v)) => v.get("code").and_then(|c| c.as_i64()),
            _ => None,
        });
    let joined = render::error_lines(err).join("\n");
    let message = joined.strip_prefix("Error: ").unwrap_or(&joined).to_string();
    serde_json::json!({"error": {"code": code, "message": message}})
}

/// `status --json`: the [`StatusResult`] verbatim, plus the [`Hello`] fields and the
/// device fingerprint the human header carries. Hello's api/stack fields win over
/// StatusResult's `stack_version` copy (they are the same value from a live daemon).
pub fn status_json(fingerprint: &str, hello: &Hello, status: &StatusResult) -> serde_json::Value {
    let mut v = serde_json::to_value(status).expect("StatusResult serializes");
    let o = v.as_object_mut().expect("StatusResult is an object");
    o.insert("api".into(), hello.api.clone().into());
    o.insert("api_version".into(), hello.api_version.clone().into());
    o.insert("api_minor".into(), hello.api_minor.into());
    o.insert("stack_version".into(), hello.stack_version.clone().into());
    o.insert("device_fingerprint".into(), fingerprint.into());
    v
}

/// `invite --json`: the [`InviteResult`] verbatim plus the requested services (what
/// the operator asked to grant — the same provenance as the human line).
pub fn invite_json(invite: &InviteResult, services: &[String]) -> serde_json::Value {
    let mut v = serde_json::to_value(invite).expect("InviteResult serializes");
    v.as_object_mut()
        .expect("InviteResult is an object")
        .insert("services".into(), serde_json::json!(services));
    v
}

/// `pair --json`: the [`PairResult`] verbatim plus the ready-to-use
/// `<peer>/<service>` mount targets (the machine mirror of "You can now use: …").
pub fn pair_json(result: &PairResult) -> serde_json::Value {
    let mounts: Vec<String> = result
        .services
        .iter()
        .map(|s| format!("{}/{s}", result.peer_nickname))
        .collect();
    let mut v = serde_json::to_value(result).expect("PairResult serializes");
    v.as_object_mut()
        .expect("PairResult is an object")
        .insert("mounts".into(), serde_json::json!(mounts));
    v
}

/// `pair --remove --json`.
pub fn unpair_json(nickname: &str) -> serde_json::Value {
    serde_json::json!({"removed": nickname})
}

/// `serve --json`.
pub fn serve_json(name: &str) -> serde_json::Value {
    serde_json::json!({"service": name, "serving": true})
}

/// `up --json`.
pub fn up_json(socket: &std::path::Path) -> serde_json::Value {
    serde_json::json!({"socket": socket.display().to_string()})
}

/// `use --json`: per service, the mount target, the exact Claude Code command, and
/// the generic MCP stdio server entry (name/command/args) any client can consume —
/// the machine mirror of [`crate::proxy::client_instruction_lines`].
pub fn use_json(peer: &str, services: &[String]) -> serde_json::Value {
    let mounts: Vec<serde_json::Value> = services
        .iter()
        .map(|s| {
            serde_json::json!({
                "target": format!("{peer}/{s}"),
                "claude_code_command":
                    format!("claude mcp add {peer}-{s} -- mcpmesh connect {peer}/{s}"),
                "mcp_server": {
                    "name": format!("{peer}-{s}"),
                    "command": "mcpmesh",
                    "args": ["connect", format!("{peer}/{s}")],
                },
            })
        })
        .collect();
    serde_json::json!({"peer": peer, "mounts": mounts})
}

/// `doctor --json`: every finding, plus the warn/error tallies the human summary
/// line carries and an overall `ok` (false iff any ERROR — mirrors the exit code).
pub fn doctor_json(findings: &[(&str, Verdict)]) -> serde_json::Value {
    let list: Vec<serde_json::Value> = findings
        .iter()
        .map(|(check, v)| {
            serde_json::json!({"check": check, "level": v.level.as_str(), "message": v.message})
        })
        .collect();
    let count = |l: Level| findings.iter().filter(|(_, v)| v.level == l).count();
    serde_json::json!({
        "findings": list,
        "warnings": count(Level::Warn),
        "errors": count(Level::Error),
        "ok": count(Level::Error) == 0,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn api_error(value: serde_json::Value) -> anyhow::Error {
        anyhow::Error::from(client::ClientError::Api(value))
    }

    #[test]
    fn error_json_carries_the_control_api_code_and_clean_message() {
        let err = api_error(json!({"code": -32055, "message": "invite failed: invite expired"}));
        let v = error_json(&err);
        assert_eq!(v["error"]["code"], json!(-32055));
        // The wire's "{method} failed: " framing is stripped, same as the human path.
        assert_eq!(v["error"]["message"], json!("invite expired"));
    }

    #[test]
    fn error_json_on_a_plain_error_has_null_code_and_the_chain() {
        let err =
            anyhow::Error::from(std::io::Error::other("disk full")).context("write roster");
        let v = error_json(&err);
        assert_eq!(v["error"]["code"], serde_json::Value::Null);
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(msg.contains("write roster") && msg.contains("disk full"), "{msg}");
    }

    #[test]
    fn status_json_merges_hello_and_fingerprint_over_the_status_result() {
        let hello = Hello {
            api: "mcpmesh-local/1".into(),
            api_version: "1.1".into(),
            api_minor: 1,
            stack_version: "0.6.1".into(),
        };
        let status = StatusResult {
            stack_version: "0.6.1".into(),
            services: vec![],
            peers: vec![],
            roster: None,
            presence: vec![],
            self_user_id: None,
            recent_pairings: vec![],
            reachability: vec![],
        };
        let v = status_json("fp-words", &hello, &status);
        assert_eq!(v["api"], "mcpmesh-local/1");
        assert_eq!(v["api_minor"], 1);
        assert_eq!(v["device_fingerprint"], "fp-words");
        // Empty vecs with skip_serializing_if stay ABSENT (additive discipline —
        // consumers read absent as empty, exactly like the wire).
        assert!(v.get("recent_pairings").is_none());
        assert!(v.get("roster").is_none());
    }

    #[test]
    fn invite_json_carries_the_line_expiry_and_requested_services() {
        let invite = InviteResult {
            invite_line: "mcpmesh-invite:MFRGGZDF".into(),
            expires_at_epoch: 1_086_400,
        };
        let v = invite_json(&invite, &["notes".to_string(), "kb".to_string()]);
        assert_eq!(v["invite_line"], "mcpmesh-invite:MFRGGZDF");
        assert_eq!(v["expires_at_epoch"], 1_086_400);
        assert_eq!(v["services"], json!(["notes", "kb"]));
    }

    #[test]
    fn pair_json_serializes_the_result_and_mount_targets() {
        let result = PairResult {
            peer_nickname: "alice".into(),
            sas_code: "tango-fig-42".into(),
            services: vec!["notes".into(), "kb".into()],
            app_label: None,
            peer_user_id: None,
        };
        let v = pair_json(&result);
        assert_eq!(v["peer_nickname"], "alice");
        assert_eq!(v["sas_code"], "tango-fig-42");
        assert_eq!(v["mounts"], json!(["alice/notes", "alice/kb"]));
    }

    #[test]
    fn use_json_emits_the_exact_client_commands() {
        let v = use_json("alice", &["notes".to_string()]);
        assert_eq!(v["peer"], "alice");
        let m = &v["mounts"][0];
        assert_eq!(m["target"], "alice/notes");
        assert_eq!(
            m["claude_code_command"],
            "claude mcp add alice-notes -- mcpmesh connect alice/notes"
        );
        assert_eq!(m["mcp_server"]["command"], "mcpmesh");
        assert_eq!(m["mcp_server"]["args"], json!(["connect", "alice/notes"]));
    }

    #[test]
    fn small_ack_objects_have_their_documented_shapes() {
        assert_eq!(unpair_json("bob"), json!({"removed": "bob"}));
        assert_eq!(serve_json("notes"), json!({"service": "notes", "serving": true}));
        assert_eq!(
            up_json(std::path::Path::new("/run/mcpmesh/mcpmesh.sock")),
            json!({"socket": "/run/mcpmesh/mcpmesh.sock"})
        );
    }

    #[test]
    fn doctor_json_tallies_and_flags_errors() {
        let findings = vec![
            ("config", Verdict::ok("config parses")),
            ("device.key", Verdict::error("group/world-writable (mode 0666)")),
            ("daemon", Verdict::warn("daemon not running")),
        ];
        let v = doctor_json(&findings);
        assert_eq!(v["findings"][1]["check"], "device.key");
        assert_eq!(v["findings"][1]["level"], "error");
        assert_eq!(v["warnings"], 1);
        assert_eq!(v["errors"], 1);
        assert_eq!(v["ok"], false);
        // A clean report is ok:true.
        let clean = doctor_json(&[("config", Verdict::ok("fine"))]);
        assert_eq!(clean["ok"], true);
        assert_eq!(clean["errors"], 0);
    }
}
