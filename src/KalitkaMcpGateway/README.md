# Kalitka MCP Gateway (public / AGPL)

The guarded proxy in front of *another* MCP server: `Claude / ChatGPT / Copilot → kalitka →
existing MCP server → GitHub / SQL / cloud / ERP`. This is where kalitka stops being PAM for
SSH/RDP and becomes PAM for AI agents — a human approves the *specific call*, and the grant is
bound to that call so nothing can change between approval and execution.

This directory is the **security foundation** (first slice): the canonical **call fingerprint**.
The proxy, policy match, `pending` state machine and human-safe renderer are later slices; the
full design is in `docs/design/mcp.md`.

## Why the fingerprint is the boundary

`restart_vm` is not the risk — *which VM* is. A human approves `restart_vm(dev-01)`; nothing may
let `restart_vm(prod-web-01)` execute against that approval. So the grant is bound to a hash of
the **canonicalised call**, and only that exact call may run.

Fields are joined with **length-prefixed framing** (4-byte big-endian length ‖ bytes), so a value
containing a delimiter can never shift a boundary and collide two different calls.

```
call_fingerprint = SHA-256(
    "kalitka-mcp-call-v2" ‖ upstream_alias ‖ tool_name ‖ tool_contract_id
      ‖ subject_id ‖ (asserted|claimed) ‖ workload_id ‖ workload_assurance ‖ JCS(arguments) )

tool_contract_id = SHA-256( upstream_id ‖ tool_name ‖ inventory_epoch ‖ JCS(inputSchema) )
```

- **`tool_contract_id`** binds the contract the gateway *observed* (the real `inputSchema`, not
  the server's self-reported version), plus the **inventory epoch** (a digest of the whole
  snapshot — so any inventory change invalidates all in-flight grants, durably across restarts).
  `description`/`title`/`icons` are excluded (a typo fix must not invalidate live grants);
  `outputSchema` is out in v1 (the authority is over the input operation).
- **Typed identity in the binding** — `AuthenticatedCallContext`: the subject (id + whether it was
  *asserted* vs merely *claimed*) and the workload (id + *assurance*). One identity string cannot
  stand for two trust levels; an approval at one assurance is not reusable at another.
- **`upstream_alias`** (admin-assigned, stable) is in the fingerprint, so a caller cannot aim
  the same call at a softer policy space by renaming an upstream.
- **Call ID** — a short Crockford-base32 prefix (`7DM4-R9KT-2F81`) shown identically in the
  approval UI, the audit log and the gateway logs, so a human can confirm what they approved.

## Canonicalization (RFC 8785 / JCS) — the exact spec

`Jcs.Canonicalize` implements RFC 8785:

- Objects sorted by key over **UTF-16 code units**; no insignificant whitespace.
- Strings: minimal JSON escaping (`"`, `\`, C0 controls; short escapes where ES defines them,
  else `\u00xx` lowercase hex); everything else emitted literally as UTF-8.
- Numbers: the ECMAScript `Number::toString` production — **not** any platform `ToString`. The
  shortest round-tripping digits come from the runtime (identical to V8's), but the formatting
  is applied per the spec steps here, and pinned by **V8-derived boundary vectors**.

Two v1 rules from the design, both fail-safe:

- **No schema defaults are applied** — the envelope is exactly what the gateway received, so an
  absent key and an explicit `null` are different calls.
- **Unicode is NOT normalized** — `NFC` and `NFD` are different calls at the byte level. The
  human-facing renderer (a later slice) is what flags confusables/bidi; the fingerprint stays
  faithful to the bytes.

**Rejected, fail closed:** duplicate object keys; non-finite numbers; **unsafe integers** (beyond
±(2^53−1) — they must travel as strings, so an `Int64`/`BigInteger` upstream can't see a different
value than was fingerprinted); lone UTF-16 surrogates; trailing content after the value; and input
over the limits (256 KiB, 10 000 nodes, 64 KiB per string, depth 32). The gateway then **forwards
the exact canonical bytes it fingerprinted**, so what a human approved is byte-for-byte what runs.

## Conformance vectors

`conformance/kalitka-mcp-call-v2.json` is the published contract: a conforming gateway (in any
language) must reproduce every `canonical` output exactly and reject every `reject` input. The
test suite runs these vectors, so **the test is the conformance check**. The version prefix
covers both the envelope and the canonicalization, so any change is a new prefix.

## Decision + execution state machine

`CallGate` (keyed by fingerprint) turns a classified call into a decision and drives its
lifecycle. Classification is **policy's** (`IToolClassifier`), never the guarded server's
annotations; an **unclassified** tool — including one that appears after an upstream update
(inventory drift) — is **never auto-allowed** (manual approval by default, deny in strict mode).

```
                approve (distinct principals)      claim (one wins)     complete
Pending ─────────────────────────▶ Approved ───────────────▶ ExecutionClaimed ──▶ Executed | Failed
   │  deny → Denied                    │                              │  claim TTL
   │  approval TTL → Expired           └── re-issue resolves here     └── no outcome → OutcomeUnknown
```

- **`ExecutionClaimed` = at-most-once dispatch.** Exactly one claim succeeds, so two automatic
  retries after an approval cannot run a destructive tool twice.
- **A claim that never completes → `OutcomeUnknown`** (fail closed; a late success is refused) —
  the human who approved it sees it ended unknown, never a silent success.
- **Re-issue-safe.** The AI re-sends the same call after approval; it resolves to the same record
  by fingerprint. A changed argument is a different fingerprint — a different, un-approved call.
- **`pending` never holds a session:** `Evaluate` returns `Pending` + Call ID; the caller polls /
  re-issues. Denied stays denied; an unacted approval expires and may be retried fresh.

`CallGate` is the *local* authority (standalone / tests). In production the authority is **Core**
(below); either way the gateway drives it through the same `IApprovalAuthority` seam.

## Core as the authority (`IApprovalAuthority`, `CoreAuthority`)

Who decides is separated from the gateway's fingerprint / classification / forwarding via
`IApprovalAuthority` (`EvaluateAsync` / `ClaimAsync` / `CompleteAsync`). `LocalAuthority` wraps the
in-process `CallGate`; **`CoreAuthority`** is a signed `/agent/*` client that raises an
`mcp:<alias>/<tool>` request in Core (carrying the Call ID the approver sees) and lets **Core own**
the human notification, principals, subject rules, quorum and TTL — the gateway does not
re-implement any of it.

The once-only execution claim is **Core's redeem-once grant**: even if two gateway instances both
see the approval, only one `redeem` succeeds, so a destructive call dispatches at most once —
durable across instances and restarts. On a definite result the Core session is ended with the
outcome; a transport failure after dispatch is still `OutcomeUnknown`.

## Real upstream (`McpUpstream`, over the MCP client SDK)

`McpUpstream` implements `IUpstream` over the official MCP client SDK (`ModelContextProtocol.Core`):
`ListToolsAsync` (SDK-handled pagination) maps each tool's name + raw input schema into the
inventory, and `CallToolAsync` forwards the approved **canonical** call to the real server and maps
its result (a missing `isError` is success, the MCP default). `ConnectStdioAsync(name, command,
args)` launches a stdio upstream (`HttpClientTransport` is available for HTTP). The SDK owns the
wire; the adapter is a faithful mapping (unit-tested), and the live stdio path was verified end to
end against the real `KalitkaMcp` server.

With this the gateway is a working human-in-the-loop MCP enforcement gateway: the first real
`tools/call` flows **fingerprint → renderer → Core approval → durable claim → upstream**. (Deferred
nicety: a `list_changed` push subscription; periodic `RefreshInventoryAsync` covers drift meanwhile.)

## Inventory, drift & the proxy (`GatewayProxy`, over `IUpstream`)

`ToolInventory` snapshots the upstream's tools. A **digest epoch** of the whole snapshot is folded
into each `tool_contract_id`, so any drift shifts every tool's contract id and invalidates every
not-yet-redeemed grant — durably (a digest is restart-stable, unlike a counter). The upstream is
not trusted: a **duplicate tool name** or a **non-object `inputSchema`** rejects the whole snapshot.
`Diff` reports added / removed / **retyped** tools for audit. (`Revision` is a human-facing counter.)

**Classification is bound to the observed contract**, not the name: `IToolClassifier.Classify(alias,
tool, contractHash)`. A new tool, a renamed tool, or a tool whose schema changed all resolve to
`Unclassified` — never auto-allowed — until an admin classifies *that exact contract*. Classifying
by name alone would let a retyped tool inherit the old tool's trust.

`GatewayProxy.HandleAsync(tool, args, AuthenticatedCallContext)` is the orchestration, called every
time the AI issues the call:

1. Look the tool up in the current inventory (unknown/withdrawn → refused; unparseable/unsafe args → refused).
2. Canonicalize args → compute the call fingerprint (with the inventory's `tool_contract_id`).
3. Classify against the observed contract hash → `CallGate.Evaluate`.
4. `Pending` → return a Call ID, **forward nothing**. `Denied` → refuse. `Approved` → **claim once
   and forward once** (the exact canonical bytes) to the upstream. A definite result/error →
   `Executed`/`Failed`; a transport failure after dispatch → **`OutcomeUnknown`** (grant burned, no
   auto-retry — the call may already have run).

`RefreshInventoryAsync` snapshots the upstream, bumps the revision on drift, and returns the diff.
The transport to the upstream is behind `IUpstream`, so the security logic here is independent of
whether the real client is stdio or HTTP (a later slice).

## Human-safe renderer + reviewability (`SafeText`, `ArgumentReviewer`)

The approval UI must never show a request **less safely than the gateway interprets it**.

- **`SafeText.Render(value, kind)`** → styled tokens + an overall risk. Control / bidi / invisible
  characters become explicit `[U+XXXX NAME]` tokens (never raw). For a **security identifier**:
  mixed scripts are a **warning**, mixed + confusable is **high-risk**, a single national script
  (e.g. «Сергей») is *not* a warning; a **Displayed / Skeleton / Raw** triple is surfaced for
  suspicious values. For **free-text** reason, only dangerous characters are flagged (no
  over-colouring). `ToTextMarkers` is the weakest-channel form (Telegram / e-mail) and enforces the
  invariant: **no raw dangerous character survives**.
- **Confusables** live in `Unicode`, a pinned self-contained table (Unicode 15.1) — a curated
  subset plus the UTS #39 skeleton, structured so the full table is *generated from `confusables.txt`
  at build* later. No runtime Unicode dependency; a Unicode bump is an explicit security change.
- **`ArgumentReviewer.Review`** — a small payload is shown in full; a large one is `TooLarge` with
  its size, SHA-256 and a bounded preview, never silently trimmed under an Approve button. A tool
  with `require_reviewable_arguments` **refuses** an opaque/oversized payload.

Published vectors: `conformance/renderer-vectors.json` (renderer) alongside the call vectors.

## Tests

- `JcsTests` — the published vectors, V8-derived number boundary vectors, and the
  fingerprint-safety properties (reorder → identical, `1`≡`1.0`, missing≠null, NFC≠NFD, array
  order significant, duplicate keys rejected).
- `FingerprintTests` — identical calls match; every authority dimension (arguments, tool,
  contract, subject, workload, upstream alias) changes the fingerprint; Call ID format.
- `CallGateTests` — auto-allow runs once; approval flow; **second claim refused** (at-most-once);
  required-two distinct principals; unclassified → manual / deny; approval + claim expiry
  (`OutcomeUnknown`, no late success); denied stays denied; fingerprint isolation.
