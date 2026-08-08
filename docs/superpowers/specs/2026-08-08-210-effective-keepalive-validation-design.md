# #210: validate the EFFECTIVE keepalive, not just a configured one — design

Date: 2026-08-08
Issue: #210
Release: 0.53.0 (**MINOR** — see Versioning)

## The bug

`build_transport_config` (`node/src/daemon/boot.rs`) runs its keepalive-vs-idle-timeout check
**inside `if let Some(k) = keep`**. The check therefore only ever sees a keepalive the operator
wrote down.

Omit `keep_alive_secs`, set only `idle_timeout_secs`, and no check runs:

```toml
[network]
idle_timeout_secs = 3   # boots fine
```

The endpoint gets `max_idle_timeout(3s)` beside **iroh's default 5s keepalive** on both the
connection and the path. The keepalive now fires *after* the idle timer — precisely the condition
the function's own error text describes, and it boots silently.

Verified against the source at 0.52.5: the block at `boot.rs:985-1031` is gated on `keep`, and
`boot.rs:1034-1049` applies `max_idle_timeout` unconditionally.

**The failing direction is the silent one.** A config that refuses at boot costs five minutes. One
that boots and then severs live sessions on a timer reads as a flaky network, and the config that
caused it looks accepted. Same shape as #128, where work nested inside a timeout budget made peers
that were answering get reported offline.

## Why the mirror case exists already

The code *does* already reason about effective values — in the other direction. Line 1016 computes
`let effective = idle.unwrap_or(IROH_DEFAULT_IDLE_SECS)` so a bare keepalive is checked against
iroh's default idle timeout, with a comment noting that branch is currently unreachable (the 5s
keepalive cap sits under the 30s default idle).

This change is that same idea applied to the other operand, and the operand where it **is**
reachable: cap 5s ≥ any `idle_timeout_secs <= 5`.

`MeshState::keep_alive_secs()` (`node/src/daemon.rs:1054`) already resolves the effective keepalive
as `configured.unwrap_or(IROH_MAX_PATH_KEEP_ALIVE_SECS)` for the per-session path, and
`per_session_transport_config` already validates against it. So the per-session path is correct
today and only **boot** is wrong — which is why the issue reproduces from config alone.

## The change

In `build_transport_config`, hoist the ordering check out of the `if let Some(k)` block:

```rust
let effective_keep = keep.unwrap_or(IROH_MAX_PATH_KEEP_ALIVE_SECS);
let effective_idle = idle.unwrap_or(IROH_DEFAULT_IDLE_SECS);
anyhow::ensure!(effective_idle == 0 || effective_keep < effective_idle, ...);
```

The two checks that are genuinely about a *configured* value stay inside `if let Some(k)`:

- `k > 0` — `0` is a zero-length timer, not "disable keepalives";
- `k <= IROH_MAX_PATH_KEEP_ALIVE_SECS` — above the cap the knob silently cannot work.

Neither applies to a default the operator did not write.

**`idle == 0` still passes**, unchanged: `0` is QUIC's "no idle timeout", so nothing can arrive
after it.

### The message must not blame a key the operator never set

The existing text names `keep_alive_secs` as the thing to fix. When the keepalive is iroh's default
that is misleading — it sends the reader to a key absent from their config. Two wordings:

- **keepalive configured** — today's message, unchanged.
- **keepalive defaulted** — name the default as the source, and give the fix that matches the
  operator's actual file: raise `idle_timeout_secs` above the default keepalive, or set
  `keep_alive_secs` below the idle timeout.

## Versioning: MINOR

`idle_timeout_secs = 3` with no `keep_alive_secs` **boots today and will refuse after this change**.
That is a behavior change for existing configs, so per `RELEASING.md`'s pre-1.0 rule it is **MINOR
(0.53.0)**, not PATCH — even though the change is small and the configs it starts refusing were
already broken at runtime.

Turning a silent runtime failure into a boot refusal is the point, not a side effect; the release
notes must say so plainly so an operator who hits it knows the refusal is the fix, not a regression.

No `API_MINOR` bump: no control-API surface changes.

## Testing

`build_transport_config` returns the config rather than mutating a builder specifically so tests can
assert what was set. Tests go alongside the existing `#[cfg(test)]` cases in `boot.rs`.

1. **The bug, as a refusal.** `idle_timeout_secs = 3`, no `keep_alive_secs` → `Err`, and the message
   names iroh's default rather than a key the operator did not set.
2. **The boundary.** `idle == 5` (equal to the default keepalive) → `Err`; `idle == 6` → `Ok`.
   Equal must fail: a keepalive arriving exactly at the idle deadline is the race.
3. **`idle_timeout_secs = 0` still boots** with no keepalive set — "no idle timeout" cannot be
   raced.
4. **No regression on configs that set both**, and the existing refusals (`k == 0`, `k > cap`) still
   fire with their own messages.
5. **Neither key set** still returns `Ok(None)` — iroh's own defaults, untouched.

**Mutations to verify the tests are not vacuous**, each must fail at least one test above:

- revert the hoist (put the check back inside `if let Some(k) = keep`) → test 1 must fail;
- change `<` to `<=` → the `idle == 5` case in test 2 must fail;
- drop the `effective_idle == 0` short-circuit → test 3 must fail.

The `<`/`<=` mutation matters most: with `effective_keep = 5` and `idle = 5` both operands are
equal, so a fixture that only tried `idle = 3` would pass under either operator and measure
nothing.
