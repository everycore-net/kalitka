# Kalitka MCP server — control plane (v1)

An MCP server that lets an AI talk to **Kalitka itself**: raise an access request, poll it,
end a session. It is deliberately the *requesting* half only — there is **no `approve_request`
tool**. A workload that could both ask for and grant access would make the human in the loop
decoration; approval stays in human channels (web console, Telegram, Teams, app).

```
Claude / other MCP host ──stdio (JSON-RPC)──▶ kalitka-mcp ──signed /agent/*──▶ Kalitka Core
                                              (just another signed agent)      (a human approves)
```

This is **part 1** of the MCP work (server onto the control plane). Part 2 — the gateway in
front of *other* MCP servers, with call-fingerprint binding and safe rendering — is separate.

## Transport

stdio for v1. It is the first transport, **not an architectural boundary**: the tools
(`KalitkaTools`) and the Core client are transport-agnostic, so an HTTP/OAuth transport (where
the OAuth token carries the workload and the delegated human) slots in without touching them.

## Tools

| Tool | Maps to | Notes |
|---|---|---|
| `kalitka.request_access` | `POST /agent/v1/requests` | Returns `{request_id, state}` — almost always `waiting`. Never approves. A `409`/`refused` means policy declined up front. |
| `kalitka.get_request` | `GET /agent/v1/requests/{id}` | `waiting` → `approved` (with a one-time grant) → or `denied`/`gone`. Poll; a human takes minutes. |
| `kalitka.end_session` | `POST /agent/v1/sessions/end` | Release access early. |

The AI names the human it acts for via `subject_identity` (routing only, always *claimed* — a
desktop client is impersonable, so it is never trusted for self-approval, per the
subject-approval rule). When absent, the workload acts for itself.

## Identity and auth

The server is just another Kalitka agent: it holds an ECDSA P-256 key (portable, PKCS#8 file)
and signs every `/agent/*` call with the `kalitka-agent-sig-v1` scheme — no reusable secret is
sent. `provider_hint: software`, `assurance: unverified` (honest: a desktop MCP host can be
impersonated by anything running as that user).

## Configuration (`Kalitka` section, or `Kalitka__*` env vars)

| Key | Meaning |
|---|---|
| `CoreUrl` | Base URL of Kalitka Core. |
| `KeyPath` | PKCS#8 signing-key file (created on first run). |
| `StatePath` | Where the assigned agent id is remembered. |
| `EnrollmentToken` | One-time token from a Core admin, used once on first run. |

## Enrollment

Create an agent in the Kalitka admin console with `access.request` (and `grant.redeem` if the
server will also consume grants), scope it to the resources it may request, mint a one-time
enrollment token, and set `Kalitka:EnrollmentToken`. On first run the server registers its
public key, receives an agent id, and persists it; then blank the token.

## Registering with an MCP host (example)

```json
{
  "mcpServers": {
    "kalitka": {
      "command": "dotnet",
      "args": ["/path/to/kalitka-mcp.dll"],
      "env": { "Kalitka__CoreUrl": "https://gate.everyco.re", "Kalitka__EnrollmentToken": "<one-time>" }
    }
  }
}
```

## What the tests prove

- **`WireParityTests`** — a signature from the server's P-256 key verifies byte-for-byte under
  Core's `AgentSignatures`; the key persists across restarts.
- **`ToolContractTests`** — the exported tool surface is exactly `request_access` / `get_request`
  / `end_session`, and **no tool named `approve_*` exists** — the design invariant, asserted.
- **`CoreRoundTripTests`** — the server enrolls and raises a real request against the **live
  Core pipeline**; polling stays `waiting` until a human (a direct `GateService.Decide`, never
  the AI) approves it, which yields the grant; an out-of-scope resource is `403`.
- A stdio handshake smoke (`initialize` + `tools/list`) confirms the real MCP wire protocol.

## Deferred

First-class `reason` (untrusted justification shown to the approver), `list_my_grants`, HTTP/
OAuth transport, and everything gateway-side (part 2).
