# `blob_list` filters + paging (#84b)

**Status:** accepted · **Issue:** #84 item (b) · **Target:** 0.18.0 (surface change → MINOR)

## Problem

`blob_list` renders **every** scope with **every** hash, grant and (since 0.17.0) withdrawal, into a
single response. The control frame cap is 16 MiB and a violation closes the connection on the third
strike — so this does not degrade at scale, it **fails**, and it takes the caller's control
connection with it.

The owner has now confirmed (#84d) that the intended granularity is **one scope per file**
(`file:<hash>`). That makes scope count grow with every file ever shared, so the cliff is reached by
ordinary use rather than by abuse. 0.17.0's `withdrawn` set widened every row, bringing it closer.

## Approach

`BlobListParams`, all optional so today's `blob_list {}` keeps working:

| param | effect |
|---|---|
| `scope: Option<String>` | exact-match one scope |
| `hash: Option<String>` | only scopes containing this hash (normalized first) |
| `limit: Option<usize>` | at most N scopes |
| `offset: Option<usize>` | skip N scopes |
| `counts_only: Option<bool>` | omit the three vectors, return sizes |

Ordering is by scope name (the table is a `BTreeMap`, so it is already sorted and stable) — paging
without a stable order returns overlapping or missing rows, which is worse than no paging.

`BlobScopeList` gains `total: usize` (scopes matching the filter **before** limit/offset) and
`truncated: bool`. Without those a caller cannot tell a complete page from a clipped one, which is
the same class of silent-wrong-answer this repo has hit repeatedly.

### A default limit, and why it is a behaviour change worth making

An unbounded default keeps the failure reachable for every existing caller — they get a closed
connection rather than a truncated answer. Default `limit` = **256** scopes, with `truncated: true`
and `total` telling the caller what they did not see.

This IS a behaviour change: a daemon with >256 scopes previously answered with everything (or died).
It is the right one — a truncated answer a caller can detect and page through beats a connection
kill — but it must be documented as such, not slipped in.

### `counts_only`

Under one-scope-per-file the common question is "how many files, how many withdrawn", not "list
every hash". `counts_only` answers it in constant response size. `hashes`/`grants`/`withdrawn` are
omitted (already `skip_serializing_if` for `withdrawn`; the other two become `Option`-shaped via
empty vectors plus the counts).

## Surface + versioning

- `Request::BlobList` gains `BlobListParams` (all optional; `#[serde(default)]` so `{}` still
  parses — the existing verb takes NO params today, so this must not become a required object).
- `ScopeInfo` gains `hash_count`, `grant_count`, `withdrawn_count` (additive, always present).
- `BlobScopeList` gains `total`, `truncated`.
- `API_MINOR` 19 → 20, `API_VERSION` "1.19" → "1.20".
- Workspace → **0.18.0** (behaviour change from the default limit → MINOR).

## Explicitly NOT here

Item (c), O(N) persistence: a single JSON file rewritten per mutation cannot be made sub-linear, so
it wants per-scope files or a keyed store — its own design pass. Item (a), the byte budget, is
independent of granularity and unblocked either way.

## Testing (TDD, RED first)

1. **Unit — `blob_list {}` still works** and now reports `total` + `truncated: false` for a small
   table. The back-compat guarantee.
2. **Unit — the default limit truncates and says so.** 300 scopes → 256 returned, `total: 300`,
   `truncated: true`. Fails if the default is unbounded or if `truncated` is not set.
3. **Unit — `offset` + `limit` page without overlap or gaps.** Two pages of 10 over 25 scopes
   return disjoint sets whose union is the first 20 in name order. Fails on an unstable order.
4. **Unit — `scope` filter is exact**, not a prefix or substring match: `file:aa` must not match
   `file:aabb`.
5. **Unit — `hash` filter normalizes.** The base32 rendering of a hash matches a scope holding its
   canonical hex, matching #83's normalization rule. Fails if the filter compares raw strings.
6. **Unit — `counts_only` omits the vectors and keeps the counts**, and `total` still reflects the
   filter.
7. **Integration — a large table does not kill the connection.** Enough scopes to exceed the frame
   cap unpaged; assert the default-limited response arrives and the connection survives. This is
   the failure the issue reports and the only test that proves it is gone.
