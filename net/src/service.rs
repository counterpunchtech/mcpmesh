//! Initialize-time service selection (spec §7.2 step 4) and the reserved-namespace
//! rule (spec §6.3): caller-supplied `mcpmesh/*` _meta keys are deleted before anything
//! acts on the frame; refusal wording never distinguishes unknown from unauthorized.
use serde_json::Value;

/// The authorization outcome. `#[must_use]`: dropping this value would leave the
/// frame cleaned but the caller unauthorized-yet-served — the compiler must object.
#[must_use]
#[derive(Debug, PartialEq)]
pub enum ServiceDecision {
    Selected(String),
    Refuse, // caller sends errors::synthesized(id, ERR_SERVICE, MSG_SERVICE)
}

pub fn select_service(init: &mut Value, caller_allowed: &[String]) -> ServiceDecision {
    // Read the request before stripping, distinguishing "key absent" (may default)
    // from "key present but not a string" (malformed → requested something
    // unresolvable → Refuse; it must never fall through to the default).
    let entry = init.pointer("/params/_meta/mcpmesh~1service");
    let malformed = entry.is_some_and(|v| !v.is_string());
    let requested: Option<String> = entry.and_then(Value::as_str).map(String::from);

    // Strip ALL reserved keys, always — before any decision is acted on (spec §6.3).
    // A non-object `_meta` (array/string) has no keys in the reserved namespace and
    // passes through untouched — deliberate asymmetry with the non-string-request
    // refusal above (D6: parse no further than the rule requires); the M2 peer
    // injector must therefore REPLACE a non-object `_meta`, never merge (seam note).
    if let Some(meta) = init
        .pointer_mut("/params/_meta")
        .and_then(Value::as_object_mut)
    {
        meta.retain(|k, _| !k.starts_with("mcpmesh/"));
    }

    if malformed {
        return ServiceDecision::Refuse;
    }
    match requested {
        Some(name) if caller_allowed.contains(&name) => ServiceDecision::Selected(name),
        Some(_) => ServiceDecision::Refuse,
        None if caller_allowed.len() == 1 => ServiceDecision::Selected(caller_allowed[0].clone()),
        None => ServiceDecision::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn init_with_meta(meta: serde_json::Value) -> serde_json::Value {
        json!({"jsonrpc":"2.0","id":1,"method":"initialize",
               "params":{"protocolVersion":"2025-06-18","_meta": meta,"capabilities":{}}})
    }

    #[test]
    fn named_and_allowed_service_is_selected_and_meta_stripped() {
        let mut init = init_with_meta(json!({"mcpmesh/service":"notes","other/key":"kept"}));
        let d = select_service(&mut init, &["notes".into()]);
        assert_eq!(d, ServiceDecision::Selected("notes".into()));
        let meta = &init["params"]["_meta"];
        assert!(
            meta.get("mcpmesh/service").is_none(),
            "reserved keys must be stripped"
        );
        assert_eq!(meta["other/key"], "kept");
    }

    #[test]
    fn caller_forged_peer_meta_never_survives() {
        let mut init =
            init_with_meta(json!({"mcpmesh/service":"notes","mcpmesh/peer":{"name":"forged"}}));
        // This test checks only the strip side effect; discarding the decision is
        // deliberate and must be explicit — which is the #[must_use] working.
        let _ = select_service(&mut init, &["notes".into()]);
        assert!(init["params"]["_meta"].get("mcpmesh/peer").is_none());
    }

    #[test]
    fn missing_meta_with_exactly_one_allowed_defaults() {
        let mut init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let d = select_service(&mut init, &["only".into()]);
        assert_eq!(d, ServiceDecision::Selected("only".into()));
    }

    #[test]
    fn missing_meta_with_two_allowed_refuses() {
        let mut init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let d = select_service(&mut init, &["a".into(), "b".into()]);
        assert!(matches!(d, ServiceDecision::Refuse));
    }

    #[test]
    fn unknown_and_unauthorized_are_indistinguishable() {
        let mut a = init_with_meta(json!({"mcpmesh/service":"nope"}));
        let mut b = init_with_meta(json!({"mcpmesh/service":"exists-but-not-yours"}));
        assert_eq!(
            select_service(&mut a, &["notes".into()]),
            select_service(&mut b, &["notes".into()])
        );
    }

    #[test]
    fn non_object_meta_passes_through_untouched_and_defaults() {
        // Binding seam contract (plan Task 9 notes): a non-object `_meta` names no
        // service and holds no reserved keys — it survives verbatim, and the
        // key-absent default rule applies. The M2 peer injector replaces, not merges.
        let mut init = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
               "params":{"_meta": ["not", "an", "object"]}});
        let d = select_service(&mut init, &["only".into()]);
        assert_eq!(d, ServiceDecision::Selected("only".into()));
        assert_eq!(init["params"]["_meta"], json!(["not", "an", "object"]));
    }

    #[test]
    fn non_string_service_request_refuses_never_defaults() {
        // A non-string `mcpmesh/service` is malformed caller input: it requested
        // something unresolvable, so it must Refuse — never fall through to the
        // single-allowed default as if nothing was requested.
        let mut init = init_with_meta(json!({"mcpmesh/service": 42}));
        let d = select_service(&mut init, &["only".into()]);
        assert!(matches!(d, ServiceDecision::Refuse));
        // Stripping is unconditional even on the refusal path.
        assert!(init["params"]["_meta"].get("mcpmesh/service").is_none());
    }
}
