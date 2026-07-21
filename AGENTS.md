# Driving mcpmesh from scripts and AI agents

This file is the automation contract for the `mcpmesh` CLI — written for AI coding
agents (Claude Code, Codex, …) and shell scripts alike. Everything here is stable,
tested behavior; the human-facing prose output is NOT part of the contract, the
`--json` output is.

## TL;DR recipe

```sh
# 1. Bring the daemon up and get the control-socket path (blocks until ready):
SOCK=$(mcpmesh up --timeout 15)

# 2. Every verb takes --json (global flag): one JSON value on stdout.
mcpmesh --json status
mcpmesh --json serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes
INVITE=$(mcpmesh --json invite notes | sed -n 's/.*"invite_line":"\([^"]*\)".*/\1/p')

# 3. On the other machine (or other --profile), redeem it:
mcpmesh --json pair "$INVITE"    # → {"peer_nickname":…,"sas_code":…,"mounts":["you/notes"],…}

# 4. Reach the service: `connect` IS the MCP stdio server — point your MCP client at it.
claude mcp add you-notes -- mcpmesh connect you/notes
```

Need a second identity for testing on one machine? `--profile <dir>` (or the
`MCPMESH_HOME` env var) sandboxes ALL state — keys, config, data, socket — under one
directory. Two profiles on one host pair exactly like two machines
(see [`docs/loopback.sh`](docs/loopback.sh) for the complete scripted flow).

## No prompts, ever

No command reads from a TTY. There are no confirmations, so there is no `--yes` flag
to remember. Destructive verbs (`pair --remove`, `org revoke`,
`internal roster install`) act immediately. The only "confirmation" in the system is
the out-of-band safety-code ceremony between humans — see below for asserting it in
automation.

## The `--json` contract

- `--json` is a **global flag**: `mcpmesh --json <verb> …` and `mcpmesh <verb> --json …`
  both work.
- Success: exactly **one JSON value on stdout** (streaming verbs emit JSONL — see below).
- Failure: exactly one line on **stderr**, shaped
  `{"error":{"code":<int|null>,"message":"…"}}`, and exit code 1. `code` is the
  control API's JSON-RPC error code when the daemon refused (see
  [`docs/local-protocol.md`](docs/local-protocol.md) for the code table); `null` when
  the failure was local (bad flags, unreadable file, …). **Branch on `error.code`,
  not on exit codes** — the process exit code stays 0/1.
- Shapes mirror the `mcpmesh-local/1` result types and evolve **additively only**.
  An **absent field means empty/none** (same discipline as the wire protocol): e.g.
  `status` omits `recent_pairings` when there are none. Write consumers accordingly.
- `connect` and `internal daemon` accept the flag but ignore it (`connect` is a raw
  MCP byte pipe — MCP itself is your structured interface there).

Per-verb output, abbreviated:

| Command | `--json` stdout |
|---|---|
| `status` | `StatusResult` + `api`, `api_version`, `api_minor`, `stack_version`, `device_fingerprint` |
| `up` | `{"socket": "<path>"}` |
| `serve <name> -- …` | `{"service": "<name>", "serving": true}` |
| `invite <svc…>` | `{"invite_line": "mcpmesh-invite:…", "expires_at_epoch": <u64>, "services": […]}` |
| `pair <invite>` | `PairResult` (`peer_nickname`, `sas_code`, `services`, …) + `"mounts": ["peer/svc", …]` |
| `pair --remove <nick>` | `{"removed": "<nick>"}` |
| `use <peer>/<svc>` | `{"peer": …, "mounts": [{"target", "claude_code_command", "mcp_server": {name, command, args}}]}` |
| `doctor` | `{"findings": [{"check","level","message"}], "warnings", "errors", "ok"}` (exit 1 iff any error) |
| `join` / `org create/approve/revoke` / `devices code/add` | the flow's artifacts (`join_code`, `org_invite`, fingerprints, serials, …) |
| `internal watch` | JSONL: one typed stream frame per line (snapshot / event / lagged) |
| `internal audit tail` | JSONL audit records (in both modes — already machine-readable) |

## Blocking commands

- `mcpmesh connect <peer>/<svc>` — blocks pumping MCP frames until stdin closes.
  It is the stdio MCP **server process for your MCP client's config** — don't run it
  bare in a script and wait for it to return.
- `mcpmesh internal daemon` — the daemon itself; you never need to run it (every verb
  auto-starts it; `mcpmesh up` does so explicitly and synchronously).
- `mcpmesh internal watch` — streams events until killed; with `--json` it's a clean
  JSONL event feed.

Readiness is `mcpmesh up`'s contract: it returns only once the daemon answers on the
control socket (or exits non-zero with the daemon's own startup error). Never poll
for the socket file; just run `up`.

## Pairing end-to-end, scripted — including the safety code

```sh
# Inviter side:
INVITE=$(mcpmesh --json invite notes | …extract invite_line…)   # or parse with jq

# Redeemer side:
PAIR=$(mcpmesh --json pair "$INVITE")
REDEEMER_SAS=$(printf '%s' "$PAIR" | sed -n 's/.*"sas_code":"\([^"]*\)".*/\1/p')

# Inviter side — the same code appears in status.recent_pairings (newest first):
INVITER_SAS=$(mcpmesh --json status | sed -n 's/.*"sas_code":"\([^"]*\)".*/\1/p' | head -n1)

[ -n "$REDEEMER_SAS" ] && [ "$REDEEMER_SAS" = "$INVITER_SAS" ] || exit 1
```

Humans compare the safety code aloud; automation compares the strings. A matching
SAS is a real man-in-the-middle assertion — **assert it in test harnesses rather than
skipping it**. (Pairing completes regardless; the check is advisory authenticity,
not a gate.) Invite-shaped artifacts are grep-stable by prefix: `mcpmesh-invite:`,
`mcpmesh-org:`, `mcpmesh-join:`, `mcpmesh-device:`.

## Prefer the local API for long-lived integrations

Shelling out per verb is fine for scripts and agents. If you are embedding mcpmesh in
an application, speak the `mcpmesh-local/1` control socket directly — typed requests,
typed results, a live event stream — via the
[`mcpmesh-local-api`](https://crates.io/crates/mcpmesh-local-api) crate.
`mcpmesh up` prints the socket path; the full protocol is documented in
[`docs/local-protocol.md`](docs/local-protocol.md).

## Shell completions & man pages

`mcpmesh completions <bash|zsh|fish|elvish|powershell>` prints a completion script;
`mcpmesh internal man <dir>` writes roff man pages for the whole command tree.
