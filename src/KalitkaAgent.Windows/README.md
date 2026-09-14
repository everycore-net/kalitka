# Kalitka Windows agent (thin slice)

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

This is the **thin slice**: one pipe, one asserted-subject request, enrollment on first run.
Deferred: MSI/packaging, session-end/redeem, reconnect/liveness, multiple concurrent
connections, per-resource policy on the pipe.

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
the resource (and optionally a command); the subject and user come from the OS.

Request:  `{"resource":"ssh:host-01","command":"systemctl restart nginx"}`
Response: `{"status":200,"id":"<request-id>","state":"waiting"}`

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
  (else `claimed-not-asserted`), and a wrong key is a 403.
