# Dev smoke: MCP echo across two real machines / NATs

> **Layer note:** this runbook drives `mcpmesh-net` directly (a `StaticGate`,
> hand-passed addresses, an echo backend) — it does not exercise pairing,
> `status`, or reachability. For the CLI porcelain across a real network, see
> [`e2e-real.md`](e2e-real.md).

Validates the one M1 acceptance clause CI cannot exercise —
**"two machines on different NATs complete an MCP session over `mcpmesh/mcp/1`"**
(spec §16 AC; §10.2/§10.3 relay+discovery). Run it whenever iroh is re-pinned,
before tagging a release, or when touching `mcpmesh-net`'s endpoint layer.

It drives the two `#[ignore]`d helpers in `net/tests/session.rs`:
`two_machine_serve` (machine A) and `two_machine_connect` (machine B). They are
`#[ignore]`d so CI never runs them (one hangs 10 min by design, both need two
machines). They reuse the same `EchoBackend` + `initialize`/`tools/call` echo path
as the in-process `known_peer_completes_initialize_and_echo` test — the only
differences are the network (`presets::N0`: n0 public relays + DNS/pkarr
discovery, vs the localhost `Minimal` + `RelayMode::Disabled`) and the identity
passing described below.

> **House rule:** one `cargo` invocation at a time *per machine* (one target dir).
> A and B are different machines, so they run concurrently — fine.

---

## Mechanism (iroh 1.0.1, reconciled)

- **Peer address passing.** `iroh::EndpointAddr` derives `serde` (it is
  `{ id, addrs: {relay|ip …} }`). `two_machine_serve` serializes its addr to JSON
  and prints **one** line: `MCPMESH_SMOKE_PEER=<json>`. `two_machine_connect`
  deserializes it from the `MCPMESH_SMOKE_PEER` env var. No node-ticket type is
  involved — JSON round-trips cleanly.
- **Gate pinning.** The server's `StaticGate` resolves the *connector's*
  EndpointId (default-deny, D5/D8). So the connector binds a **stable secret key**
  (a fixed dev seed baked into the test — *not secret*, override with
  `MCPMESH_SMOKE_SECRET=<64-hex>`), making its EndpointId constant and shareable in
  advance. `two_machine_serve` allows `MCPMESH_SMOKE_ALLOW=<EndpointId>` if set, else
  defaults to that built-in connector identity (and prints it).
  - **Simplest path:** set neither `MCPMESH_SMOKE_SECRET` nor `MCPMESH_SMOKE_ALLOW` on
    either machine — the built-in dev connector identity matches on both sides, so
    only `MCPMESH_SMOKE_PEER` (on B) is required.
  - **Pin a fresh identity:** set `MCPMESH_SMOKE_SECRET` on B, read the
    "this connector's EndpointId: …" line it prints, and pass that as
    `MCPMESH_SMOKE_ALLOW` on A.
- **Relay override.** Default relay is n0's (`presets::N0`). Set
  `MCPMESH_SMOKE_RELAY=https://relay.runbolo.com` on either/both machines to use
  Bolo's relay via `RelayMode::custom` instead.
- **Relay-forced variant.** `MCPMESH_SMOKE_FORCE_RELAY=1` on B strips direct (`Ip`)
  addrs from the peer addr so the session **establishes** over the relay path.
  iroh may still upgrade to a direct path via hole-punching afterward — the `PASS`
  line reports the path actually used (from `Endpoint::remote_info`).

| Env var | Side | Meaning |
|---|---|---|
| `MCPMESH_SMOKE_PEER` | B (required) | The serialized `EndpointAddr` line printed by A |
| `MCPMESH_SMOKE_ALLOW` | A (optional) | EndpointId to pin in the gate; default = built-in connector id |
| `MCPMESH_SMOKE_SECRET` | B (optional) | 64-hex secret key for a fresh connector identity |
| `MCPMESH_SMOKE_RELAY` | A and/or B (optional) | Custom relay URL (e.g. `https://relay.runbolo.com`) |
| `MCPMESH_SMOKE_FORCE_RELAY` | B (optional) | Strip direct addrs → force the relay path |

---

## Procedure

### 0. Both machines (different networks — home / office / phone-hotspot)

```bash
git pull
cargo build -p mcpmesh-net --tests     # one cargo at a time per machine
```

### 1. Machine A — serve (prints the peer line, then serves 10 min)

```bash
cargo test -p mcpmesh-net --test session -- --ignored two_machine_serve --nocapture
```

> The serve side waits up to **30 s** on `online()` (for a relay connection) *before*
> printing the `MCPMESH_SMOKE_PEER=` line — this is expected, not a hang.

Copy the single line it prints:

```
MCPMESH_SMOKE_PEER={"id":"…","addrs":[{"Relay":"https://…"},{"Ip":"…"}]}
```

(If you want to pin a non-default connector, first run step 2's reveal on B, then
re-run this with `MCPMESH_SMOKE_ALLOW=<that EndpointId>`.)

### 2. Machine B — connect (dials, runs initialize + byte-faithful echo)

```bash
export MCPMESH_SMOKE_PEER='{"id":"…","addrs":[…]}'   # the whole JSON from A (quote it)
cargo test -p mcpmesh-net --test session -- --ignored two_machine_connect --nocapture
```

**Expected:**

```
PASS — initialize + byte-faithful echo completed over mcpmesh/mcp/1. path=DIRECT (active addrs: ["ip:…"])
```

`path=DIRECT` means hole-punching succeeded; `path=RELAY` means the session ran
over the relay. Both are a PASS for the AC — record which one you got.

### 3. Relay-forced variant (exercise the relay fallback)

Re-run step 2 with the relay path forced (optionally against Bolo's relay):

```bash
export MCPMESH_SMOKE_PEER='…'                          # same line from A
export MCPMESH_SMOKE_FORCE_RELAY=1
export MCPMESH_SMOKE_RELAY=https://relay.runbolo.com   # optional; omit for n0's relay
cargo test -p mcpmesh-net --test session -- --ignored two_machine_connect --nocapture
```

Expect `PASS` again. The `path=` verdict shows whether iroh stayed on the relay or
upgraded to direct after establishing over it.

> **You MUST record at least one run whose `PASS` line reads `path=RELAY`** to
> actually validate the relay fallback (spec §10.3). `MCPMESH_SMOKE_FORCE_RELAY=1`
> alone does **not** guarantee it: the `presets::N0` endpoint keeps DNS/pkarr
> discovery on, which can re-supply direct addresses from the EndpointId — so a run
> can still come back `path=DIRECT` after the strip. To force a genuine relay path,
> combine `MCPMESH_SMOKE_FORCE_RELAY=1` with `MCPMESH_SMOKE_RELAY=https://relay.runbolo.com`
> and/or a hole-punch-hostile NAT combo (e.g. two symmetric NATs). A `path=DIRECT`
> result validates **direct traversal only** — not the relay.

---

## Record for each run (paste into the release/validation log)

- **Date:**
- **iroh pin:** `=1.0.1` (workspace `Cargo.toml`)
- **NAT combo:** e.g. `A: home NAT (CGNAT) · B: phone hotspot`
- **Relay:** n0 default / `relay.runbolo.com`
- **Path:** `DIRECT` or `RELAY` (from the `PASS` line's `path=`)
- **Result:** PASS / FAIL (+ notes)
- **[ ] at least one observed `path=RELAY` run** (relay fallback validated, §10.3)

> **Note on the built-in dev identity:** the default connector secret is a hardcoded
> seed baked into the test — it is effectively **public**. It is fine for a throwaway
> echo smoke, but any run that would carry real data must set a fresh
> `MCPMESH_SMOKE_SECRET` on the connect side and the matching `MCPMESH_SMOKE_ALLOW` on the
> serve side.

---

## Troubleshooting

- **B fails immediately with a closed connection / gate refusal.** A's gate did not
  resolve B's EndpointId. Either run both sides with defaults (no
  `MCPMESH_SMOKE_SECRET`/`MCPMESH_SMOKE_ALLOW`), or make sure the `MCPMESH_SMOKE_ALLOW`
  you set on A exactly equals the "this connector's EndpointId: …" line B prints.
- **`MCPMESH_SMOKE_PEER is not a serialized EndpointAddr`.** The env value must be the
  JSON object only; the test also tolerates the whole `MCPMESH_SMOKE_PEER=…` line.
  Keep the quotes so the shell does not split the JSON.
- **Connect times out (60 s).** No path could be established — check both machines
  actually reached the relay (A's serve waits up to 30 s for `online()`), and that
  a corporate firewall is not blocking the relay's HTTPS/QUIC.
