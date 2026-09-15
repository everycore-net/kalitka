# Kalitka Windows agent

A Windows Service that lets a local, untrusted user process ask Kalitka Core for
just-in-time access — and, crucially, lets Core **trust who is asking**. The service reads
the caller's identity from the OS (the SID off the named-pipe token), not from anything the
caller typed, so it may hold the sudo-grade `subject.assert` capability. A generic CLI agent
cannot: it could only echo a string.

```
untrusted user process ──local named pipe──▶ Kalitka Windows Service
                                              • impersonate pipe token → SID + account
                                              • beneficiary = account tail, subject = os:DOMAIN\user
                                              • sign with ECDSA P-256 CNG key (TPM when present)
                                              ────HTTPS, kalitka-agent-sig-v1────▶ Core /agent/v1/requests
```

The public agent is meant to be **useful on its own** (per the open-core boundary): it carries
the agent protocol, the asserted `sid:` subject, and **RDP JIT** (below). Deferred: MSI/
packaging, multiple concurrent pipe connections, per-resource policy on the pipe. Commercial
modules (Application Broker, Credential Provider) live elsewhere and talk via the published
pipe contract.

## RDP JIT — temporary Remote Desktop access

The agent grants just-in-time RDP by adding the approved subject to the local **Remote Desktop
Users** group for the life of a grant, then removing them — and it does so in a way that
survives a restart.

```
caller ──pipe {"action":"rdp"}──────────▶ agent raises rdp:<host> (subject asserted) → returns id
caller ──pipe {"action":"rdp_activate","requestId":id}▶ agent polls; on approval redeems and adds
                                                       the caller's SID to Remote Desktop Users
                                                       until the grant's exact expiry
```

- **Add on redeem, remove on expiry.** The grant's Core-approved subject must be the caller
  activating (`beneficiary-mismatch` otherwise). Membership is by **SID** against the group's
  **well-known SID** (S-1-5-32-555), so it is locale-safe (the group name is resolved, never
  assumed) and cannot be spoofed by name.
- **A Core outage never extends access.** Expiry is a locally known time; a sweeper removes
  expired leases on a 60 s cadence with no Core call.
- **Survives a restart.** Leases are written to a **write-ahead journal** before the group is
  changed; on startup the agent reconciles — dropping anything already expired and re-asserting
  anything still valid.

The service must run with rights to change local group membership (LocalSystem or an
administrative service account).

## Enrollment capabilities

For RDP JIT the agent needs `access.request`, `grant.redeem` and (for asserted subjects)
`subject.assert`, scoped to `rdp:*` (and whatever else it brokers).

## Runtime

`net10.0-windows`. Core stays on net9 — the two only meet over HTTP with the versioned
`kalitka-agent-sig-v1` wire scheme, so the runtimes need not match. Build and test with the
.NET 10 SDK:

```
dotnet build src/KalitkaAgent.Windows/KalitkaAgent.Windows.csproj -c Release
dotnet test  tests/KalitkaAgent.Windows.Tests/KalitkaAgent.Windows.Tests.csproj -c Release
```

## Configuration (`appsettings.json`, section `Kalitka`)

| Key               | Meaning                                                            |
|-------------------|-------------------------------------------------------------------|
| `CoreUrl`         | Base URL of Core, e.g. `https://gate.everyco.re` or `http://localhost:8080`. |
| `PipeName`        | Local pipe untrusted processes connect to (`\\.\pipe\<name>`).     |
| `KeyName`         | Persisted CNG key name. TPM provider first, software KSP fallback. |
| `StatePath`       | Where the assigned agent id is remembered (defaults under ProgramData). |
| `RdpJournalPath`  | Write-ahead journal of active RDP leases (defaults under ProgramData). |
| `EnrollmentToken` | One-time token from a Core admin, used once on first run.          |

The private key never leaves the CNG provider; only the SPKI is exported (for enrollment)
and the provider signs each request (IEEE P1363, 64 bytes — what Core's `ecdsa-p256` suite
verifies natively).

## Enrollment

1. In Core's admin UI, create an agent with capabilities `access.request` **and**
   `subject.assert`, scoped to the resources it may request (e.g. `ssh:*`), and mint a
   one-time enrollment token. (Granting `subject.assert` is deliberately conspicuous — it
   shows a `privileged` badge and its own audit event.)
2. Put the token in `Kalitka:EnrollmentToken` and start the service. On first run it creates
   its CNG key, registers the public half, receives an agent id, and persists it. The token
   is then spent; blank it out.

## The pipe protocol

Newline-delimited JSON, one request / one response per connection. The caller chooses only
the action and resource (and optionally a command); the subject and user always come from the
OS token, never the payload.

| Request | Meaning |
|---|---|
| `{"resource":"ssh:host-01","command":"..."}` | Raise a generic request (default action). → `{status,id,state}` |
| `{"action":"rdp"}` | Raise an RDP request for this host. → `{status,id,state}` |
| `{"action":"rdp_activate","requestId":"<id>"}` | On approval, redeem and grant RDP until expiry. → `{status,granted,expires_at}` (or `{granted:false,state:"waiting"}`) |

### Exercise it live (PowerShell, as the untrusted user)

```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'kalitka-agent', 'InOut')
$pipe.Connect(5000)
$sw = new-object System.IO.StreamWriter($pipe); $sw.AutoFlush = $true
$sr = new-object System.IO.StreamReader($pipe)
$sw.WriteLine('{"resource":"ssh:host-01"}')
$sr.ReadLine()      # -> {"status":200,"id":"...","state":"waiting"}
$pipe.Dispose()
```

The service log shows the resolved caller (`Request from CONTOSO\anna (sid S-1-5-21-…)`),
proving the subject came from the token, not the request.

## What the tests prove

- **`WireParityTests`** — a signature from the CNG key verifies under Core's own
  `AgentSignatures`; the key id and canonical string are byte-identical; tampering fails.
  This is the one thing that must be exactly right.
- **`CoreRoundTripTests`** — the agent's `CoreClient`, signing with the CNG key, is accepted
  by the **real Core pipeline**; the OS-asserted subject is trusted only with `subject.assert`
  (else `claimed-not-asserted`), and a wrong key is a 403. Includes the full RDP path: raise
  `rdp:` → human approves → poll → redeem returns the approved subject + exact expiry.
- **`RdpEnforcerTests`** — add on grant, remove exactly at expiry (no Core call — a control-plane
  outage never extends access), revoke early, and startup reconcile (drop expired, re-assert
  valid) — all deterministic against a fake group and clock.
