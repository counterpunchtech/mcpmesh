# mcpmesh operator runbook

The end-to-end procedures for standing up and running an mcpmesh **org** (roster mode) and for the
day-one **pairing** flow. Every command here is porcelain from spec §1.6 — no config file is
hand-edited, and no key ever moves between machines.

> **Acceptance (spec §16 M4 AC4 — out of CI):** this runbook must be **executable by a non-author** —
> someone who did not write mcpmesh follows it start to finish on a clean machine and reaches a working
> deployment. That execution is the human-verification acceptance step (like the two-machine NAT smoke
> test in `dev-two-machine-smoke.md`): it is not a CI gate; the runbook is the deliverable and a
> non-author run is its sign-off. If a non-author gets stuck, the fix is to clarify **this file**.

> **Trust model in one line:** the **org-root signature** is the trust boundary. Everything a joiner or
> a peer receives (the roster, the invite) is verified against the pinned org-root public key. The
> HTTPS host that serves `roster.json`, the chat channel that carries an invite, and the gossip network
> are all **untrusted transport** — tampering is caught by the signature, rollback by the
> strictly-increasing serial plus the freshness rule (§4.3).

---

## 0. Install

**crates.io (any platform with a Rust toolchain) — the simplest path:**

```
cargo install mcpmesh
```

**Homebrew (macOS/Linux):**

```
brew tap counterpunchtech/mcpmesh https://github.com/counterpunchtech/mcpmesh
brew install --HEAD counterpunchtech/mcpmesh/mcpmesh
```

**Debian/Ubuntu (.deb):**

```
cargo install cargo-deb          # one-time tooling
cargo deb -p mcpmesh               # builds target/debian/mcpmesh_<version>_<arch>.deb
sudo dpkg -i target/debian/mcpmesh_*.deb
```

**From source (any platform):**

```
cargo install --path cli   # installs the `mcpmesh` binary
```

Confirm the install and the local health of the machine:

```
mcpmesh --version
mcpmesh doctor
```

`mcpmesh doctor` is read-only and local-only: it lints the config, key-file permissions, roster
freshness, the relay/discovery self-hosting combination, and the runtime dir, and optionally pings the
daemon. On a fresh machine it reports "daemon not running" (a WARN, not an error) and otherwise passes.

---

## 1. Pairing mode (day one, no org)

Two people, four commands, no server infrastructure:

```
# Alice shares a notes server:
alice$ mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes
alice$ mcpmesh invite notes          # prints a one-time mcpmesh-invite:… line — send it to Bob out-of-band

# Bob redeems it and mounts it in his AI client:
bob$   mcpmesh pair mcpmesh-invite:…   # prints a short code (e.g. "tango-fig-cabbage"), the
                                       # mount target, and the exact AI-client steps
bob$   claude mcp add alice-notes -- mcpmesh connect alice/notes   # the command `pair` printed
```

`pair` prints the AI-client instructions inline (Claude Code's command, Claude Desktop's config
entry + path + restart, and the generic stdio command for anything else); `mcpmesh use
alice/notes` reprints them on demand. mcpmesh never writes a third-party client's config itself —
the operator pastes what they can later find and remove.

Confirm the SAS code on both sides before using the service — it authenticates the pairing (§4.2).
Bob's `pair` prints the code; Alice runs `mcpmesh status` and reads the SAME code under
**recent pairings**. Confirm it matches **verbally, out-of-band** (a call, in person — not the channel
that carried the invite). The recent-pairings list is a display-only ceremony aid held in memory by
Alice's daemon — a daemon restart clears it, so do the comparison right after pairing. To revoke
later: `mcpmesh pair --remove alice`.

---

## 2. Roster mode: org setup

Roster mode layers team management on the same machinery. Run these on the **operator machine** (the
one that will hold the org-root key).

### 2.1 Create the org

```
operator$ mcpmesh org create acme --roster-url https://intranet.acme.com/mcpmesh-roster.json
```

This mints the **org-root key** (one-time per node, stored 0600 at `~/.config/mcpmesh/org-root.key`),
signs an empty roster (serial 1), installs it, and prints:

- an **org invite code** (`mcpmesh-org:…`) — hand this to each joiner;
- the **org-root fingerprint** (short words) — you read this aloud during every approval (§4.4).

`--roster-url` both pins the URL in your config `[roster].url` **and** is carried in the invite so a
joiner bootstraps its first roster without gossip (D5). You do not need to have the HTTPS host serving
anything yet — you publish to it in step 2.3.

### 2.2 A joiner joins

On each teammate's machine:

```
alice$ mcpmesh join mcpmesh-org:… --name "Alice Nguyen" --label laptop
```

This mints Alice's **user key** (0600, local, never moves), pins the org root, and prints:

- a **join code** (`mcpmesh-join:…`) — Alice sends this to you (the operator) out-of-band;
- the **org-root fingerprint** — Alice confirms it matches what you read aloud (closes the phished-invite MITM, P4);
- a **join-code fingerprint** — Alice reads THIS back to you (closes the join-code-substitution MITM).

### 2.3 The dual fingerprint ceremony + approve

When Alice sends her join code, run:

```
operator$ mcpmesh org approve mcpmesh-join:… --groups team-eng
```

Before it installs, `approve` prints the **join-code fingerprint** it is about to approve. **Both legs
of the ceremony must match, out-of-band (a call, in person — not the same channel that carried the
code):**

1. **Org-root fingerprint** — you read yours aloud; Alice confirms it equals what her `join` printed.
   (Stops an attacker who phished Alice with a fake invite pinning the attacker's root.)
2. **Join-code fingerprint** — Alice reads hers back; you confirm it equals what `approve` printed.
   (Stops an attacker who substituted their own device's join code for Alice's.)

If either differs, do **not** approve — investigate. On a match, `approve` adds Alice's device to the
roster under `team-eng`, bumps the serial, re-signs, and installs. Service allowlists can now name the
group: `allow = ["team-eng"]`.

### 2.4 Publish the roster (the operator's standing responsibility)

Every serial bump (`org create`, `org approve`, `org revoke`) rewrites the signed roster at
`~/.config/mcpmesh/roster.json`. Nodes that are online converge via gossip within ~60 s automatically.
But the **pinned `[roster].url` is the joiner's first-roster bootstrap AND the currency beacon** — a
node with no fresh URL confirmation degrades to stale after `max_staleness` (default 24h). So after
**every** serial bump, publish the new `roster.json` to the HTTPS host:

```
# Whatever your host is — an intranet box, S3, the relay's static dir. Examples:
operator$ scp ~/.config/mcpmesh/roster.json web@intranet:/var/www/mcpmesh-roster.json
# or:
operator$ aws s3 cp ~/.config/mcpmesh/roster.json s3://acme-mcpmesh/mcpmesh-roster.json --content-type application/json
```

The host is **untrusted** — you are publishing a **signed** document. A tampered or rolled-back copy is
rejected by every node (bad signature, or serial ≤ installed). Serve it over **HTTPS** (the freshness
poll validates TLS; a plain-HTTP or self-signed host means nodes cannot confirm currency and will
degrade). Confirm currency on any node:

```
alice$ mcpmesh status      # shows: roster · serial N · approved   (and a hint if no [roster].url)
alice$ mcpmesh doctor      # full freshness/roster-url diagnostic
```

### 2.5 Add a second device to an existing person

Keys never move between machines. On the **new** machine, then on an **already-enrolled** machine:

```
newbox$    mcpmesh devices code --label desktop        # prints an mcpmesh-device:… code
laptop$    mcpmesh devices add mcpmesh-device:…          # signs it with the user key → prints a join code
operator$  mcpmesh org approve mcpmesh-join:… --groups team-eng   # same ceremony, APPENDS the device
```

Then publish the roster (2.4).

---

## 3. Revocation

```
operator$ mcpmesh org revoke alice/laptop     # one device (lost/stolen)
operator$ mcpmesh org revoke alice            # a person departing (all their devices)
operator$ mcpmesh org revoke --user-key alice # user-key rotation (§4.6, see §4 below)
```

Each bumps the serial, re-signs, installs, and **severs any live sessions** the revocation cuts (D8),
across all ALPNs. **Then publish the roster (2.4)** so offline/remote nodes converge — connected nodes
enforce within 60 s via gossip; under a network attacker withholding both gossip and the URL poll,
staleness is bounded by `max_staleness + grace` (~4 days by default), never by roster expiry alone.

---

## 4. Key management

### 4.1 The org-root key (P5 — the catastrophic anchor)

`~/.config/mcpmesh/org-root.key` signs every roster. Its compromise lets an attacker forge membership.

- Keep it **0600** and on the operator machine only. `mcpmesh doctor` flags loosened permissions.
- It is **offline-signed-in-porcelain**: only `org create/approve/revoke` ever load it, and it is never
  exposed as an online signing oracle. Run approvals on a well-secured, ideally dedicated, operator box.
- **Back it up to offline media** (an encrypted USB key kept physically secure). Losing it means you
  cannot bump the roster serial — you would have to re-establish the org and re-enroll everyone.
- Threshold/quorum org-root signing is the v2 hardening path (spec §18 Q4); a single offline key + this
  runbook is the accepted posture for ≤ 50 users.

### 4.2 User keys

`~/.config/mcpmesh/user.key` (0600, per person, per machine, never moves) binds a person's devices. A
compromised user key lets an attacker bind new devices as that person.

### 4.3 User-key rotation (compromise runbook, §4.6)

```
operator$ mcpmesh org revoke --user-key alice     # removes Alice, keeps her device endpoints un-revoked
alice$    mcpmesh join mcpmesh-org:… --name "Alice Nguyen"   # regenerates a fresh user key, re-enrolls
operator$ mcpmesh org approve mcpmesh-join:… --groups team-eng --user-id alice   # same user_id + groups
operator$ # …then publish the roster (2.4)
```

The `--user-key` revoke severs all of Alice's devices at once; she re-enrolls per §2.2–2.3 with a fresh
user key on the SAME machines; you re-approve with the SAME `user_id` so allowlists keep working.

---

## 5. Self-hosting relay & discovery (§10.3)

Defaults use n0's public relays + DNS/pkarr discovery. Traffic is always end-to-end encrypted; only
metadata (which endpoints exist, their addresses, the relayed connection graph) is visible to that
infrastructure. To self-host, set **both** in `~/.config/mcpmesh/config.toml`:

```toml
[network]
relay_mode     = "custom"
relay_urls     = ["https://relay.acme.com"]        # your iroh relay server(s)
discovery_mode = "custom"
discovery_urls = ["https://dns.acme.com/pkarr"]    # your pkarr relay(s) — an iroh-dns-server
                                                   # exposes one; used for BOTH publishing and
                                                   # resolving peer addresses (nothing goes to n0)
```

The modes are `relay_mode = "default" | "custom" | "disabled"` and
`discovery_mode = "default" | "custom"`. `relay_mode = "disabled"` is the **hermetic** mode — no
relay AND no discovery (localhost/testing; `discovery_mode` is ignored). A `"custom"` mode without
its URL list, or an unknown mode, is a **startup error** — the daemon refuses to run rather than
silently falling back to public infrastructure.

**Self-host both or neither.** Doing only one is an incomplete metadata mitigation — `mcpmesh doctor`
WARNs on that combination (and ERRs on a `[network]` the daemon would refuse). Bolo operates
`relay.runbolo.com` if you want a relay without running your own. Restart the daemon after editing
(`mcpmesh status` auto-starts it).

---

## 6. Health check reference

Run `mcpmesh doctor` after install, after any config change, and when a node behaves unexpectedly. It
reports, per check, one of `OK` / `WARN` / `ERR` and exits non-zero if any check is `ERR`:

| Check | What it means |
|---|---|
| `config` | `config.toml` parses; roster mode has `org_id`/`user_id`. |
| `daemon` | the local daemon is reachable (WARN if not running — start it with any verb). |
| `self-hosting` | the `[network]` posture: ERR if the config is one the daemon refuses (unknown mode, `custom` without URLs); WARN if exactly one of relay/discovery is self-hosted (§10.3) or if discovery knobs are set alongside the hermetic `relay_mode = "disabled"`; OK otherwise. |
| `roster-url` | WARN if roster mode has no `[roster].url` (degrades to stale). |
| `roster-freshness` | the roster's state (approved/degraded/stopped/pending) + last-confirmed age. |
| `device.key` / `user.key` / `org-root.key` | ERR if group/world-writable, WARN if readable (must be 0600). |
| `runtime-dir` | ERR if the control-socket dir is not 0700 and owned by you. |

`doctor` never changes anything — if it reports a key-permission problem, fix it yourself with
`chmod 600 <path>`.
