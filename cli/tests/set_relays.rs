//! `set_relays` (#53) — the live custom-relay-set control verb, driven end-to-end over the
//! real control API against an in-process `mcpmesh-node`. Two postures, both hermetic (no
//! network): a `custom`-mode node exercises the LIVE insert/remove diff path (Minimal preset +
//! `RelayMode::custom`, so nothing dials n0), and a `disabled`-mode node exercises the
//! persist-but-restart-required path plus validation/idempotency.
//!
//! Well-formed dummy `https://…` relay URLs are enough: `insert_relay`/`remove_relay` only
//! MUTATE the running endpoint's relay map (no synchronous dial), so the node stays up across
//! every edit — which is the whole point of the verb.
use mcpmesh_node::{Config, NodeBuilder};

/// A custom-mode, network-free posture: `presets::Minimal` (custom discovery to a bogus local
/// URL keeps us off n0) + a custom relay map. The endpoint binds locally and never dials out.
fn custom_hermetic(relay_urls: &str) -> Config {
    Config::from_toml_str(&format!(
        "[network]\nrelay_mode = \"custom\"\nrelay_urls = [{relay_urls}]\n\
         discovery_mode = \"custom\"\ndiscovery_urls = [\"https://dns.example\"]\n"
    ))
    .expect("valid custom test config")
}

#[tokio::test(flavor = "multi_thread")]
async fn set_relays_applies_live_on_the_custom_path() {
    let root = tempfile::tempdir().unwrap();
    let node = NodeBuilder::new(root.path())
        .config(custom_hermetic("\"https://relay-a.example\""))
        .start()
        .await
        .expect("custom-mode node starts");
    let mut ctl = node.control().await.expect("control");

    // Add relay-b to the mix (custom → custom): applied LIVE, no restart.
    let r = ctl
        .set_relays(&[
            "https://relay-a.example".into(),
            "https://relay-b.example".into(),
        ])
        .await
        .expect("set_relays add");
    assert!(r.changed, "the set differed → changed");
    assert!(
        !r.restart_required,
        "custom→custom is applied live, no restart"
    );
    // The node is still alive across the live reconfigure (endpoint was not torn down).
    ctl.status().await.expect("status after a live relay add");

    // Idempotent: the SAME set again is a clean no-op (no writes, still live-consistent).
    let again = ctl
        .set_relays(&[
            "https://relay-a.example".into(),
            "https://relay-b.example".into(),
        ])
        .await
        .expect("set_relays idempotent");
    assert!(!again.changed, "same set → changed=false");
    assert!(!again.restart_required);

    // Remove relay-a (custom → custom): live again, node stays up.
    let removed = ctl
        .set_relays(&["https://relay-b.example".into()])
        .await
        .expect("set_relays remove");
    assert!(removed.changed);
    assert!(!removed.restart_required);
    ctl.status()
        .await
        .expect("status after a live relay remove");

    // The persisted config reflects exactly the last set, mode forced to custom.
    let cfg = Config::load(&root.path().join("config").join("config.toml")).expect("reload config");
    assert_eq!(cfg.network.relay_mode, "custom");
    assert_eq!(
        cfg.network.relay_urls,
        vec!["https://relay-b.example/".to_string()]
    );
}

/// Regression (#53 review): the diff is on iroh's NORMALIZED `RelayUrl`, not the raw string, so
/// re-spelling the SAME relay (a trailing slash, host case) is an idempotent no-op — it must NOT
/// remove-then-reinsert (which, ordered wrong, would drop the relay the caller meant to keep).
#[tokio::test(flavor = "multi_thread")]
async fn set_relays_treats_a_respelled_url_as_unchanged() {
    let root = tempfile::tempdir().unwrap();
    // Boot config spells the relay WITHOUT a trailing slash …
    let node = NodeBuilder::new(root.path())
        .config(custom_hermetic("\"https://relay-a.example\""))
        .start()
        .await
        .expect("custom-mode node starts");
    let mut ctl = node.control().await.expect("control");

    // … and the caller sends the SAME relay WITH a trailing slash (+ host case). Both normalize to
    // the same `RelayUrl`, so this is unchanged — no writes, no endpoint churn.
    let r = ctl
        .set_relays(&["https://Relay-A.example/".into()])
        .await
        .expect("set_relays respelled");
    assert!(
        !r.changed,
        "a re-spelling of the same relay must be unchanged, not a drop+reinsert"
    );
    assert!(!r.restart_required);
    ctl.status().await.expect("node still serving");
}

#[tokio::test(flavor = "multi_thread")]
async fn set_relays_persists_but_requires_restart_from_a_non_custom_mode() {
    let root = tempfile::tempdir().unwrap();
    let node = NodeBuilder::new(root.path())
        .config(Config::from_toml_str("[network]\nrelay_mode = \"disabled\"\n").unwrap())
        .start()
        .await
        .expect("hermetic node starts");
    let mut ctl = node.control().await.expect("control");

    // disabled → custom is a MODE transition iroh can't do live: persisted, restart_required.
    let r = ctl
        .set_relays(&["https://relay-a.example".into()])
        .await
        .expect("set_relays from disabled");
    assert!(r.changed);
    assert!(
        r.restart_required,
        "a non-custom current mode can't be live-transitioned"
    );
    // Config now names the custom set so a restart reproduces it.
    let cfg = Config::load(&root.path().join("config").join("config.toml")).expect("reload config");
    assert_eq!(cfg.network.relay_mode, "custom");
    assert_eq!(
        cfg.network.relay_urls,
        vec!["https://relay-a.example/".to_string()]
    );

    // Validation (atomic — nothing applied on error):
    // empty list is rejected …
    let empty = ctl.set_relays(&[]).await;
    assert!(empty.is_err(), "empty relay set is rejected");
    // … and a malformed URL is rejected, leaving the prior config intact.
    let bad = ctl.set_relays(&["not a url".into()]).await;
    assert!(bad.is_err(), "a malformed relay url is rejected");
    let cfg = Config::load(&root.path().join("config").join("config.toml")).expect("reload config");
    assert_eq!(
        cfg.network.relay_urls,
        vec!["https://relay-a.example/".to_string()],
        "a rejected edit does not touch the persisted set"
    );
}
