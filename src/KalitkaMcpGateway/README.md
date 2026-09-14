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

```
call_fingerprint = SHA-256(
    "kalitka-mcp-call-v1" ‖ upstream_alias ‖ tool_name ‖ tool_contract_id
                          ‖ subject ‖ workload ‖ JCS(arguments) )

tool_contract_id = SHA-256( upstream_id ‖ tool_name ‖ inventory_revision ‖ JCS(inputSchema) )
```

- **`tool_contract_id`** binds the contract the gateway *observed* (the real `inputSchema`, not
  the server's self-reported version). A changed contract makes an old grant un-redeemable.
  `description`/`title`/`icons` are excluded (a typo fix must not invalidate live grants);
  `outputSchema` is out in v1 (the authority is over the input operation).
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

Duplicate object keys and non-finite numbers are **rejected** (fail closed).

## Conformance vectors

`conformance/kalitka-mcp-call-v1.json` is the published contract: a conforming gateway (in any
language) must reproduce every `canonical` output exactly and reject every `reject` input. The
test suite runs these vectors, so **the test is the conformance check**. The version prefix
covers both the envelope and the canonicalization, so any change is a new prefix.

## Tests

- `JcsTests` — the published vectors, V8-derived number boundary vectors, and the
  fingerprint-safety properties (reorder → identical, `1`≡`1.0`, missing≠null, NFC≠NFD, array
  order significant, duplicate keys rejected).
- `FingerprintTests` — identical calls match; every authority dimension (arguments, tool,
  contract, subject, workload, upstream alias) changes the fingerprint; Call ID format.
