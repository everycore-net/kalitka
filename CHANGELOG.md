# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Windows agent 0.6.0 — end the lease when the person logs off (RDP session accounting).** A grant
  used to linger to its TTL even after the human left. Now an RDP logoff frees it immediately and
  tells Core the session closed, completing the lifecycle Core already modelled (`session.started` at
  redeem → `session.ended` on report):
  - `RdpLogoff.TryParse` — a pure parse of a Security-log 4634 (logoff) of logon type 10 for a real
    account. A 4634 is a genuine logoff, not a mere disconnect (4779), so a session that can be
    reconnected rightly keeps its grant until reconnect-and-logoff or the TTL sweep.
  - `RdpLogoffWatcher` — on a qualifying logoff it ends the matching lease early: deny access +
    dejournal locally (authoritative, Core reachable or not), then report `session.end` to Core
    (best-effort; a reconcile closes anything a Core outage missed). Under the same `Kalitka:RdpWatch`
    switch as the denied-logon watcher.
  - `CoreClient.EndSessionAsync` (POST `/agent/v1/sessions/end`) and `RdpEnforcer.LeaseForSid` (map a
    logged-off SID to its Core session). Shared `Sids.IsAccount` helper across the parsers.
  - 36 agent tests (was 30). Dev/test-only, no mars deploy.

- **Windows agent 0.5.0 — auto-raise on a denied RDP logon (the 4625 watcher).** With gating on, a
  person needs no client at all: they just try to connect, the OS refuses (they lack the logon
  right), and the agent turns that refusal into an approval. Closes the loop hard mode opened.
  - `RdpDenial.TryParse` — a pure parse of a Security-log 4625 into an actionable denial: RDP logon
    type (10), status/substatus `0xC000015B` (logon-type-not-granted, in either field), a real
    account SID. The identity comes from the event's `TargetUserSid`/`TargetUserName` — LSA-asserted
    when it refused the account, so `subject.assert` stays honest, never anything the person typed.
  - `SecurityLogWatcher` — subscribes to the Security log for 4625 and raises for each qualifying
    denial, with a per-subject in-flight fold so a logon storm never starts a second poll loop (Core
    dedups the request too, from 0.46.0). Off by default (`Kalitka:RdpWatch`); reading the Security
    log needs the agent to run as SYSTEM.
  - `RdpActivator` — the one place a Core grant becomes local access: redeem the one-time grant,
    confirm the approved subject is exactly the account being enabled, then hand the lease to the
    enforcer. Shared by the pipe path and the watcher (the beneficiary check now lives in one place),
    and drives the full raise→poll→grant loop for the watcher, which has nobody to poll for it. The
    enrolled agent id is handed from `Worker` to the watcher via a one-shot `AgentIdentity`.
  - 30 agent tests (was 19). Dev/test-only, no mars deploy.

- **Windows agent 0.4.0 — RDP-JIT hard mode (default-deny via a deny group + LSA).** Soft mode
  (add to Remote Desktop Users on grant) is honest but fail-open: nothing stops a login the box
  already allows by other means. Hard mode is fail-closed — the subject sits, by default, in a
  Kalitka-owned group that carries `SeDenyRemoteInteractiveLogonRight`, so their RDP login is refused
  until a grant lifts them out:
  - New `IRdpAccess` strategy factored out of the enforcer (which keeps owning the lease lifecycle,
    journal and session teardown): `AllowListAccess` (soft — grant adds, deny removes) and
    `DenyListAccess` (hard — grant lifts out of the deny group, deny puts back). The lifecycle is
    identical; only the direction inverts.
  - New `ILsaPolicy` / `WindowsLsaPolicy` (LSA policy API): assigns the deny-logon right to the deny
    group's SID once at startup (idempotent). `WindowsLocalGroup` generalised to create a named group
    (`NetLocalGroupAdd`) and resolve its SID.
  - Selected by `Kalitka:RdpHardMode` (default `false`, preserving today's soft behaviour);
    `Kalitka:DenyGroupName` defaults to `Kalitka-Gated`. Hard mode requires the agent to run with
    rights to change local groups and local policy. Precondition: the gated population must be in the
    deny group at rest — `Deny` restores that after every lease, so once Kalitka has mediated one
    login the subject stays default-denied.
  - 19 agent tests (was 15). Dev/test-only, no mars deploy.
- **Windows agent 0.3.0 — RDP-JIT session termination (the token-outlives-removal fix).** Removing
  someone from Remote Desktop Users (or, later, adding them back to a deny group) does **not** eject a
  session that is already open: the access token was assembled at logon and outlives the group change.
  So closing a lease now means "remove the right **plus** terminate the session":
  - New `ISessionKiller` / `WtsSessionKiller` (via `wtsapi32`): enumerates the local terminal-services
    sessions, resolves each session's owner SID, and logs off the ones matching the lease. Session 0
    (services) is skipped. Runs as SYSTEM, which `WTSLogoffSession` requires.
  - Wired into every lease-closing path — `Revoke`, `Sweep` (expiry), and startup `Reconcile` of an
    already-expired lease. Ordering is remove-from-group **then** kill-session, so no new logon races
    the teardown. Best-effort by design: a kill failure is logged, never blocks the group removal or
    journal cleanup, so a lingering token can never leave a phantom lease behind.
  - 6 agent tests (was 5). Because the net10/Windows agent reaches Windows security APIs, a new
    `agent-windows` CI job runs its tests on a real Windows runner — the same gating standard as Core.

## [0.46.0] - 2026-09-15

### Added

- **RDP-JIT groundwork — request dedup and per-subject rate-limit (the Core prerequisite).** The RDP
  just-in-time path (owner design) has the host agent raise a request when it sees a logon-denied
  event; that fires repeatedly, so the engine now folds repeated identical requests and throttles a
  stuck user:
  - **Dedup:** a raise carrying a machine-readable subject (`os:`/`sid:`) reuses a still-waiting
    request for the same `(resource, subject)` instead of creating a duplicate, and returns it without
    re-notifying — a 4625 storm for one person and host becomes one approval, not a flood. Checked
    *before* the rate limit, so folding onto your own pending request is never throttled. Requests
    without a subject identity (web visitors, plain agents) are untouched.
  - **Per-subject rate-limit:** the sliding window now also keys on the subject, not just the IP —
    every user behind one agent shares that agent's IP, so a per-IP limit alone can't throttle a
    single stuck client. Same `MaxRequestsPerIp`/`RateWindowMinutes` window.
  - Benefits every agent axis, not just RDP. 5 tests. Core suite 426. (The Windows hard-mode agent —
    deny-group `SeDenyRemoteInteractiveLogonRight`, session termination, the 4625 watcher — is the
    next slice, dev/test-only per the narrowed signing freeze.)

## [0.45.0] - 2026-09-15

### Added

- **RADIUS channel — confirm before login, no browser, one implementation for RD Gateway / VPN /
  Citrix / Wi-Fi 802.1X.** kalitka can now be the auth server a gateway (RD Gateway via NPS, a VPN,
  Citrix, Wi-Fi 802.1X) points at: the client sits on "Connecting…" while the person taps approve on
  their phone — the approval happens **before** login, on the first attempt, with no browser. Pure
  .NET on the BCL, not blocked by the code-signing freeze, and a new **input channel to the same
  engine** (same `rdp:` resources, same approval/quorum/audit) rather than a new model.
  - **Codec** (RFC 2865/2869): parse/build, the User-Password cipher, the Response Authenticator, and
    the Message-Authenticator (verified on requests, added to responses). Hand-rolled on MD5/HMAC-MD5,
    which is all RADIUS needs.
  - **Approval exchange**, Duo-shaped and stateless across rounds: verify the primary credentials
    ourselves (an **LDAP bind** to the DC), raise the approval, answer **Access-Challenge** to hold
    the wait (a human thinks longer than one RADIUS timeout, so the gateway re-sends with our signed
    `State` and we answer Challenge again until the decision — then Access-Accept / Access-Reject).
  - **Honest scope:** RADIUS gates the **perimeter**, not a host (it rarely knows the target machine),
    so the approval names the gateway (NAS-Identifier) and this **composes with a host agent** — RADIUS
    decides who enters at all, the agent who reaches a specific machine. The username routes to the
    person via the usual subject mechanism.
  - **Off by default**, and the UDP listener is **not exposed publicly** — a deployment enables it,
    sets the shared secret, and points a gateway at it. Credential verification is fail-closed: LDAP
    when `LdapUrl` is set, a dev-only `RadiusAcceptAnyCredentials` switch, else deny. RADIUS's MD5
    shared-secret is legacy — run it in a protected segment or over RADIUS/TLS. New options
    `RadiusEnabled`, `RadiusPort`, `RadiusSharedSecret`, `RadiusResource`, `RadiusChallengeSeconds`,
    `RadiusAcceptAnyCredentials`, `LdapUrl`, `LdapBindFormat`. Deps: `System.DirectoryServices.Protocols`
    (first-party; LDAP needs libldap on Linux at runtime, only on that path).
  - 14 tests (codec: User-Password round-trip incl. multi-block, Response & Message-Authenticator,
    malformed packets; the exchange: challenge→approve→accept, bad creds, denial, tampered State,
    wrong-secret authenticator). Core suite 421.

## [0.44.0] - 2026-09-15

### Added

- **Microsoft/Entra for visitors and device enrolment (provider seam, part 2).** 0.43.0 put the
  provider seam under the admin plane; now the **visitor fast-path** and **device enrolment** run
  through the same seam, so the M365 case is actually closed — a Microsoft employee at the gate signs
  in with their work account instead of ringing and waiting.
  - **Visitor sign-in** is now `/login/{scheme}` (a button per configured provider on the gate form)
    with one shared `/oauth2/callback` (the provider rides in the signed, browser-bound state). Each
    provider gates its own visitor allowlist: Google's domains/addresses, and Entra's
    `MicrosoftEmails`/`MicrosoftDomains` — or, with neither, tenant-wide entry **only** when
    `MicrosoftAllowedTenants` restricts the tenant (else fail-closed, so a multi-tenant authority
    never silently admits the world). Identity stays `scheme:subject`, the session is minted per
    `SessionScope` exactly as before.
  - **Enrolment** picks the provider too (a picker when more than one is configured); the invite is
    still bound to an e-mail and matched against the IdP-proven address regardless of provider, and
    the created principal / granted approver are keyed on the provider-neutral actor.
  - The invariants were re-checked and hold across providers: per-host `SessionScope` default, revoked
    key = blocked, `WebAuthnRequireDeviceBound`, and Entra's `tid+oid` keying / tenant gating /
    single-tenant-default. 5 tests (Entra visitor allowlist incl. the fail-closed multi-tenant case,
    the form's per-provider buttons, state carrying the scheme). Core suite 407.
  - **To enable Microsoft for visitors**, register `https://<GateHost>/oauth2/callback` (and
    `/enroll/callback` for enrolment) in the Entra app, alongside the admin `/admin/oauth2/callback`.

## [0.43.0] - 2026-09-15

### Added

- **Sign-in provider seam + Microsoft/Entra for the control plane.** The admin login was Google-only;
  the German mid-market it targets usually runs Microsoft 365 and had no fast path. A thin
  `IIdentityProvider` seam (`AuthorizationUrl` + `Resolve` → a provider-neutral `ProvenIdentity`) now
  sits behind `AdminAuth`, with `GoogleAuth` and a new `MicrosoftAuth` registered through an
  `IdentityProviders` registry; the login page shows a button per configured provider. A new provider
  is one registration, nothing downstream changes.
  - **Provider-neutral identity.** The audit actor / operator principal / quorum key on
    `scheme:subject` — `google:<sub>` or `ms:<tid>:<oid>` — never the e-mail. `AdminIdentity` carries
    its scheme (defaulting to `google`, so pre-seam sessions and callers are unchanged); the admin
    session cookie round-trips it (legacy 3-field cookies still read as Google). The quorum's
    "an unlinked console admin counts as itself" rule is now provider-neutral, so a **Microsoft admin
    is a first-class approver** and can satisfy a quorum.
  - **Entra safety (owner review).** Identity is keyed on the stable `tid+oid`, not the mutable
    e-mail/UPN. A multi-tenant authority (`organizations`/`common`) is dangerous — any Microsoft
    account can complete the flow — so `MicrosoftAllowedTenants` gates the `tid` in the provider, and
    a single-tenant authority (put your tenant id in `MicrosoftTenant`) is the safe default. The
    `id_token` is read over the TLS server-to-server exchange (no JWKS handling), the same trust model
    as the Google path. Each installer registers their own Entra app; redirect URI is the same
    `/admin/oauth2/callback`. New options `MicrosoftClientId/Secret`, `MicrosoftTenant`,
    `MicrosoftAllowedTenants`.
  - Scope: the **admin control plane**. The visitor Google fast-path and device-enrolment sign-in stay
    Google for now and adopt the same seam next. 8 tests (tenant gating, tid+oid keying, e-mail
    fallback, registry, a second provider driving login end to end, legacy-cookie compatibility).
    Core suite 404.

## [0.42.0] - 2026-09-15

### Added

- **Passkey as a way past the gate — visitor login ([[fido2]] slice 1).** A visitor can now pass a
  guarded host with a **passkey** instead of ringing the bell or Google sign-in — the fast path for
  people on neither (the target German mid-market usually has Microsoft 365, i.e. no Google fast path
  today). It is deliberately **not an identity provider**: a passkey recognises a credential *we*
  registered, a cryptographic allowlist — the crypto version of today's weak "remember this IP /
  name" (`aip`/`ain`).
  - **A visitor cannot self-register** (that would be an IdP): "remember this device" is offered only
    *after* a normal approval — the register endpoints require the session that approval just minted.
  - **Login** proves a discoverable credential (no `allowCredentials`); on success the gate mints the
    **same session a manual approval would**, per-host or domain-wide following `SessionScope` (the
    0.4.0 lesson). Nothing bypasses: unguarded hosts are untouched, a **revoked key is blocked**, and
    `WebAuthnRequireDeviceBound` refuses a cloud-synced passkey where policy demands a device-bound
    one. Sign-counter clone detection and one-time login nonces as elsewhere.
  - Separate `VisitorPasskeyStore`/`VisitorPasskeyService` — a distinct population from operator
    passkeys (approvers) and agents (requesters): a visitor credential only lets its holder *in* and
    can raise nothing. Reuses every WebAuthn crypto primitive. Admin `/admin/passkeys` lists
    remembered devices (name, scope, fingerprint) and revokes them. New audit events
    `passkey.remembered` / `passkey.used` / `passkey.revoked`. Built provider-neutral — no new
    `google:` coupling, leaving room for the Microsoft/Entra provider seam next.

### Changed

- **Device audit vocabulary aligned** with `agent.*`: `webauthn.registered`→`device.enrolled`,
  `webauthn.removed`→`device.revoked`, `webauthn.clone_alarm`→`device.clone_alarm`, so history
  filters line up.
- **Revoking a device now also drops that operator's push subscriptions**, so a revoked device stops
  receiving pushes (they re-enable notifications on a device they still hold) — not just the key.

### Tests

11 new (visitor passkey register→login round-trip, per-host vs domain scope, revoke=blocked, replay,
tamper, device-bound policy, endpoint auth; per-principal push removal). Core suite 396.

## [0.41.0] - 2026-09-14

### Added

- **Enrolment QR, a device fingerprint, and the "defer" (device-signed-only) receiver — the tail of
  the device-onboarding story ([[fido2]] slice C follow-ups, [[app-launch]]).**
  - **Invite QR:** the enrolment invite now renders as an inline SVG QR of the invite link (phone
    camera opens it), shown only to the signed-in admin and never e-mailed; the link carries a
    one-time token, not a secret to photograph. The QR uses a small, single-purpose MIT encoder
    (`Net.Codecrete.QrCodeGenerator`, pure-managed, no native/image deps) with our own SVG rendering
    so the page stays self-contained — QR at link sizes needs multi-block Reed-Solomon interleaving
    and mask optimisation, which (unlike our JCS/WebPush formalism) has no security surface and no RFC
    vector to self-test, so a vetted encoder is the proportionate choice.
  - **Device fingerprint:** every registered device shows a short fingerprint of its key in the same
    Crockford base32 alphabet as the gateway Call ID (`XXXX-XXXX`), in the device lists, so a person
    can confirm the right device bound and it is named the same everywhere.
  - **Defer receiver (device-signed-only approval):** a request can be raised with `require_signed=1`
    (via `/agent/v1/requests` — the entry the iOS shield uses when it defers a decision) so it can be
    **approved only by a device signature**, never a chat tap or a session click; a denial stays
    unsigned (fail-safe). The engine enforces it in `Decide`; the admin UI hides the session-approve
    buttons for such requests. The rest of the chain — routing the push to the person, the device
    signature, the caller polling the outcome — already existed (Slices A/B), so `defer` is these
    parts made to guarantee out-of-band proof of intent.
  - 8 tests (fingerprint alphabet/shape/stability, QR SVG rendering, defer: unsigned approve refused,
    device-signed approve accepted, unsigned deny allowed). Core suite 385.

## [0.40.0] - 2026-09-14

### Added

- **Device enrolment — invite → IdP sign-in → device, and admin device management ([[fido2]] slice
  C, [[product-direction]] onboarding).** An admin invites a person by e-mail; the invite is a
  **one-time capability** that must end in a **Google sign-in as the invited account** — so an
  intercepted invite cannot enrol a stranger's device (it is bound to that account and burned once).
  On success the person is granted approve rights and a session, and lands in the app to register a
  passkey (Slice A) and enable push (Slice B).
  - `EnrollService`: mint invite → `/enroll?t=…` link; the landing redirects to the IdP with a
    signed, browser-bound state; the callback verifies the state, matches the proven e-mail to the
    invite, burns the invite (`IReplayStore`), grants approve rights and links the principal, then
    issues a normal operator session — so registration, push and approval reuse everything from
    Slices A/B unchanged. New `/enroll` + `/enroll/callback` (needs the Google redirect URI
    `https://<GateHost>/enroll/callback` registered), `/admin/enroll` (issue invites), option
    `EnrollmentInviteMinutes`.
  - **Runtime-granted approve rights** (`OperatorApprovers`): the piece that makes enrolment end to
    end — an operator can be given the ability to approve without editing the deployment's
    `ApproverEmails` env list. It composes with that list (the union is what
    `AdminAuth.ResolvePermissions` grants) and is revocable at once; enrolment grants it, and the
    admin `/admin/enroll` page lists and revokes it.
  - **Admin device management:** `/admin/devices` now shows every registered device across operators
    (for admins) with per-device revoke, alongside your own devices. Revoking unlinks the device's
    identity so it no longer resolves in the quorum.
  - 11 tests (approver grant/compose/revoke, enrolment happy path + wrong-account + single-use +
    browser-binding + bad-invite, admin invite issuance and CSRF). Core suite 377.
  - Deferred to a follow-up: rendering the invite as a **QR image** (shown as a link today), and the
    iOS-shield **`defer`** receiver.

## [0.39.0] - 2026-09-14

### Added

- **Installable PWA approval channel with Web Push — approvals without Telegram, an app store, or a
  legal entity ([[fido2]] slice B).** The gate now serves an installable web app (`/admin/app`, a
  `manifest.webmanifest`, a root-scope service worker, an icon) and sends **Web Push** notifications,
  so an operator gets a push on their phone and confirms with a device signature — the Slice-A
  ceremony — in a home-screen app. Web push works on Android and iOS 16.4+ (add to Home Screen
  first), so the same channel serves business (where Telegram is banned), solo, and Family, and is
  the future receiver for the iOS shield's `defer`.
  - **Web Push crypto on the BCL, no library:** RFC 8291 message encryption over RFC 8188
    `aes128gcm` (ECDH P-256 + HKDF-SHA256 + AES-128-GCM) and RFC 8292 VAPID (ES256 JWT), all on the
    framework's `ECDiffieHellman`/`HKDF`/`AesGcm`/`ECDsa`. Pinned to the **RFC 8291 §5 test vector**:
    the header frames exactly as the RFC specifies and the body decrypts to the RFC's plaintext with
    the RFC's user-agent key — spec interop, not a self-consistency check.
  - **`PushNotifier : INotifier`** plugs into the existing fan-out (Telegram, e-mail, now push) with
    no engine change: it pushes to the resolved operator's registered devices, or to every device
    when the routing asks the admins, and prunes any subscription the push service reports as gone.
    VAPID keys are generated once and kept in the shared config store; subscriptions are bound to the
    operator's principal, so a push reaches the person, not a global list.
  - The service worker shows the notification and deep-links the tap into the request's signing UI.
    New options `VapidSubject`, `PushTtlSeconds`. 13 tests (RFC 8291 vector + round-trip, VAPID JWT
    verification, subscription store, notifier targeting/pruning, public assets, app-shell auth,
    subscribe round-trip). Core suite 366.

## [0.38.0] - 2026-09-14

### Added

- **Device-signed approval — a decision signed by a key, not "a button was pressed" (WebAuthn,
  [[fido2]] slices 1+2).** An approver registers a passkey / security key and confirms a request by
  touching it; the WebAuthn challenge **is** the decision (an `ApprovalEnvelope` over `{request id,
  decision, timestamp, policy-context hash, nonce}`, length-prefixed with the same framing as the
  audit hash), so the assertion is a signature over *this* decision, by a credential we can name.
  The signed envelope is the reusable core the future native app and the iOS shield's `defer` path
  will sign too.
  - **Registration** (`/admin/devices`): RP ID = the gate host, `attestation: none`, ES256/EdDSA.
    The COSE public key is converted to SPKI and verified through the **same `IAgentSignatureSuite`**
    that verifies agents — one home for the algorithms, and the provider/assurance vocabulary extends
    to passkeys. The device is linked to the operator's principal (`app:<id>`), so a device-signed
    approval counts as that human in the quorum — provably the same person as their admin login.
  - **Signed decision** (`/admin/requests/decide-signed`): the assertion is verified server-side
    (origin, RP-ID-hash, `type=webauthn.get`, constant-time challenge compare, UP/UV flags,
    signature via the suite, signature-counter clone detection), the nonce is burned once
    (`IReplayStore`), and the proof (credential id, authenticator data, clientDataJSON, signature)
    is stored on the audit event **inside the same atomic state+audit transaction** — a decision and
    its proof commit together. The proof rides on a new `AuditEvent.Proof` field (kept out of the
    chain hash so the existing chain is untouched) and is made tamper-evident by a short commitment
    folded into the hashed `Metadata`.
  - **Assurance:** a cloud-synced passkey (WebAuthn BE flag) is *not* device-bound; the UI labels it
    honestly, and `WebAuthnRequireDeviceBound` lets a high-assurance policy refuse a synced key —
    the same idea as the TPM assurance level.
  - **Dependencies:** WebAuthn attestation/COSE parsing uses `System.Formats.Cbor` — a small, stable
    first-party Microsoft package (not part of the shared framework), taken instead of a whole
    third-party WebAuthn stack. The ES256 DER→IEEE-P1363 conversion and the SPKI verification reuse
    existing code; no `Fido2NetLib`.
  - New `WebAuthnService`/`WebAuthnStore`, `ApprovalEnvelope`/`WebAuthn` helpers, shared `Framing`
    and `Base64Url`. Options: `WebAuthnRpId`, `WebAuthnOrigin`, `WebAuthnUserVerification`,
    `WebAuthnRequireDeviceBound`, `WebAuthnChallengeMinutes`. 21 tests (COSE/DER conversion, the two
    ceremonies end to end against a software authenticator, replay/expiry/policy-drift/clone/origin,
    HTTP E2E with the proof committed and the chain still intact). Core suite 353.
  - This is the approval channel that does not need Telegram, an app store, or a legal entity — the
    PWA shell and Web Push (next slice) layer on top of this same signed decision.

## [0.37.0] - 2026-09-14

### Added

- **Operational metrics on a Prometheus `/metrics` endpoint (audit follow-up #6).** The four signals
  the audit named, with no metrics SDK or exporter dependency — a self-contained registry that
  renders Prometheus text, the same own-it-outright choice the product makes for its other formalism
  (JCS, the audit chain):
  - `kalitka_decisions_total{decision,reason}` — every decision, counted at the *same* seam as the
    audit log (`MeteredDecision`), so the metric cannot drift from the log. This is the audit's
    **denial-reason distribution** (filter `decision="denied"`) and gives approval/ask rates too.
  - `kalitka_time_to_approval_seconds` — a fixed-bucket histogram (5s … 1h) of the time from a
    request being raised to its approval.
  - `kalitka_pending_requests` — a gauge of the queue depth, read live from the request store at
    scrape time.
  - `kalitka_notify_fallback_total{reason}` — how often approval notification fell back to the admins
    (`subject-unmapped`, `operator-unreachable`).
  - The endpoint is **guarded** (Traefik routes the whole host, so an open `/metrics` would be
    public): it accepts the internal secret via `X-Kalitka-Internal` **or** `Authorization: Bearer`,
    so a stock Prometheus can scrape with `authorization.credentials_file` — no secret in the scrape
    config. 13 tests (registry rendering & bucketing, engine wiring, endpoint auth). Core suite 337.

## [0.36.0] - 2026-09-14

### Security

- **Config tightening propagates before the cache TTL (asymmetric freshness guard).** The 10s config
  cache lets a change reach other instances with a bounded lag. That is harmless when a rule is
  *relaxed* — the worst case is a few extra seconds of asking — but on the decision path a snapshot
  that has not yet seen a *tightening* made on another instance would wrongly grant authority: let
  traffic bypass a just-armed gate, or honour an allow that was just revoked. (No cluster runs today;
  this closes the property, not a live hole.)
  - `IConfigStore` gains a monotonic **`Generation()`** counter, advanced on every `Mutate`. The
    shared backends (**SQLite**, **Postgres**) advance it *in the same transaction* as the write, so
    it is shared and monotonic across instances; the single-node backends keep it in process.
  - New `ConfigGeneration` guard is consulted **only on the authority-granting direction**: before
    permitting, a reader whose snapshot is older than a 1s confirm window checks the generation (a
    cheap counter read, not a blob re-parse) and reloads if it was superseded. The deny/enforce
    direction never pays, so a loosening simply rides the slower TTL — the asymmetry the audit asked
    for. Wired into the armed-host gate (`ApprovalEngine.IsEnforced`) and the allow auto-permit
    (`AccessLists.IsAllowed`); a missed block is not accelerated (it still faces approval, grants
    nothing). Net: a tightening reaches the grant path within ~1s, a loosening within the 10s TTL.
  - 9 tests (the primitive; SQLite generation shared across instances; arming/allow-revocation reach
    the grant path before the TTL; disarming/allow-grant ride the TTL). Core suite 324. Deliberately
    no pub/sub or event bus — disproportionate to a cluster that does not yet exist.

## [0.35.0] - 2026-09-14

### Security

- **Session-signing key rotation without logging everyone out (overlap window).** Until now the HMAC
  master secret was a single value: rotating it (a leak, a scheduled roll) invalidated every session
  cookie and OAuth state at once — every approver bounced to re-login mid-flight. Now both signers
  accept a *previous* secret on **verification only**; new tokens are always signed with the current
  secret. Set the previous to the old value and the current to the new one, and existing sessions stay
  valid through an overlap window; clear the previous once a session lifetime has passed.
  - `TokenSigner(master, previousMaster?)` and `SessionService(hmac, clock, previousSecret?)` verify
    against the current key, then the previous one, both constant-time (`FixedTimeEquals`). Purpose
    isolation (HKDF per key id) still holds across the overlap — a previous-master token cannot cross
    purposes. New config key `HmacSecretPrevious` (empty = no overlap), wired through `Program.cs` and
    `ApprovalEngine`.
  - 11 rotation tests (TokenSigner + SessionService: previous verifies, current-only signs, purpose
    isolation across the window, previous rejected once dropped, OAuth state overlap). Core suite 315.

## [0.34.0] - 2026-09-14

### Security

- **SafeText backported to the main approval surface — one standard of rigour.** The audit noted
  the MCP gateway's human-safe renderer was more formalised than main kalitka; the fix is to use the
  *same* code, not a second one. `SafeText` + the pinned `Unicode` facts are extracted into a shared,
  dependency-free `Kalitka.Text` library that both Core (net9) and the gateway (net10) reference.
  - Core now renders the approver-facing fields — the SSH **command** (the crux of what is approved),
    the visitor **subject**, the **target** and the **source address** — through `SafeText` in both
    the **Telegram** approval message and the **admin** request views. A bidi override, invisible
    character or confusable can no longer reach the human deciding able to reorder or disguise what
    they read: dangerous characters become explicit `[U+XXXX NAME]` markers (enforced on the weakest
    channel, Telegram), mixed/confusable scripts are flagged. Previously these were only
    HTML-encoded, which stops markup injection but not deceptive Unicode.
  - Pure refactor for the gateway (SafeText/Unicode moved to the shared lib, no behaviour change).
    3 backport tests (bidi in command, control in subject, plain command unchanged). Core suite 304.

## [0.33.0] - 2026-09-14

### Security

- **Tamper-evident audit log (hash chain + signed checkpoint).** The audit log is what kalitka's
  whole pitch rests on — *provable* approval (quorum, four-eyes, "who allowed the bank client to
  start") — and until now append-only was only a convention: anyone with database access could
  rewrite history. Now every event carries a monotonic `seq` and the SHA-256 hash of the previous
  event (`AuditHash`, length-prefixed framing backported from the MCP gateway's fingerprint), so
  altering or reordering any event breaks the chain.
  - `IAuditStore.VerifyChain` recomputes the chain and reports the first broken `seq`. Implemented
    across all backends: **SQLite** (chain serialized by SQLite's single writer — the async path
    opens an IMMEDIATE transaction, the atomic path already holds the write lock), **Postgres**
    (a transaction-scoped **advisory lock** serializes appends across nodes), and in-memory.
  - **Existing logs are backfilled** on migration (rows chained in `(ts, id)` order) — a verifiable
    baseline from which any future tampering is caught, so upgrading a live DB doesn't fail
    verification.
  - **`AuditIntegrity`** signs the chain head (seq + hash + time) with the server key — a checkpoint
    a customer can keep to also catch *truncation* (dropped recent events), not just in-place edits;
    a broken chain is never signed. Surfaced at **`/admin/audit/verify`** (Integrity nav): chain
    status, first bad link, and the exportable signed checkpoint.
  - From the owner's architecture/security audit; this was its #1, "the product's core claim depends
    on it." 7 tests (in-memory + SQLite chain/tamper/backfill/checkpoint) + a Postgres chain/tamper
    test in CI. No breaking change (additive columns, backfill).

## [0.32.0] - 2026-09-14

### Added

- **Policy copilot — the deterministic backbone (`PolicyCopilot` + `/admin/policies/copilot`).**
  The "kalitka produces authority" half of the copilot, built on the ready `explain`/`simulate`.
  A proposed change (an `Upsert`/`Remove`, from a human in the console now — or an LLM translating
  intent later) is never trusted to be safe: `PolicyCopilot.Preview` runs `PolicyService.Simulate`
  against **every current agent** (so an expansion can't hide in a context the caller forgot),
  classifies the fleet-wide impact (No change / Restriction / Authority expansion / Mixed), and
  lists the affected agents with their field-level deltas. `Apply` is human-only and **refuses to
  apply an authority expansion without an explicit confirmation**; a pure restriction applies
  directly. The copilot never decides what is allowed — it retells a deterministic impact and gates
  the apply. Admin surface at `/admin/policies/copilot` (Draft/Change: propose → preview impact →
  apply with the confirm gate). The natural-language drafter is a pluggable intent layer on top
  (pending an owner decision on the LLM dependency); the authority stays deterministic and testable.
  7 tests (`PolicyCopilotTests` + an admin endpoint smoke). No schema change.

### Added

- **MCP Gateway — real upstream MCP client (`src/KalitkaMcpGateway` → 0.6.0).** `McpUpstream`
  implements the `IUpstream` seam over the official MCP client SDK (`ModelContextProtocol.Core`):
  `ListToolsAsync` (SDK-handled pagination) maps each tool's name + raw input schema into the
  inventory, and `CallToolAsync` forwards the approved canonical call to the real server and maps
  its result (a missing `isError` is success, the MCP default). `ConnectStdioAsync` launches a
  stdio upstream. The SDK owns the wire; the adapter is a faithful mapping, unit-tested, and the
  live stdio path was verified end to end against the real `KalitkaMcp` server. With this, the
  first real `tools/call` flows through fingerprint → renderer → Core approval → durable claim →
  upstream. **This makes the gateway a working human-in-the-loop MCP enforcement gateway**, not
  just a security foundation. (Deferred nicety: a `list_changed` push subscription; periodic
  `RefreshInventoryAsync` covers drift meanwhile.) 117 gateway tests in CI.

- **MCP Gateway — Core as the authority (`src/KalitkaMcpGateway` → 0.5.0).** The gateway no longer
  decides approvals itself: an `IApprovalAuthority` seam separates *who decides* from the gateway's
  fingerprint / classification / forwarding. `LocalAuthority` wraps the in-process `CallGate`
  (standalone / tests); **`CoreAuthority`** makes the gateway a signed `/agent/*` client that raises
  an `mcp:<alias>/<tool>` request in Core (carrying the Call ID the approver sees) and lets **Core
  own** the human notification, principals, subject rules, quorum and TTL — the gateway stops
  re-implementing any of it.
  - **The once-only execution claim is Core's redeem-once grant** — durable and shared across
    instances/restarts: even if two gateway instances both see the approval, only one `redeem`
    succeeds, so a destructive call dispatches at most once. On a definite result the session is
    ended with the outcome; a transport failure after dispatch is still `OutcomeUnknown`.
  - Integration-tested end to end against the **real Core pipeline** (`CoreAuthorityTests`): raise →
    a human `GateService.Decide`s → poll approved → redeem (claim) → forward once; a re-issue after
    completion cannot re-dispatch (grant spent); a denied request is refused and never forwarded.
  - 114 gateway tests in CI. **Next:** real MCP discovery (`tools/list` + pagination/`list_changed`)
    then real `tools/call` over the MCP SDK, behind the existing `IUpstream` seam.

- **MCP Gateway — human-safe renderer + reviewability limits (`src/KalitkaMcpGateway` → 0.4.0).**
  The approval UI must never show a request *less safely than the gateway interprets it*.
  - **`SafeText.Render`** turns an argument value into styled tokens + an overall risk. Control /
    bidi / invisible characters become explicit `[U+XXXX NAME]` tokens (never emitted raw); mixed
    scripts are a **warning** and mixed + confusable is **high-risk**; a whole word in one national
    script (e.g. «Сергей») is *not* itself a warning; free-text reason flags only dangerous chars,
    no over-colouring. A **Displayed / Skeleton / Raw** triple is surfaced for suspicious
    identifiers. The model is channel-agnostic; `ToTextMarkers` is the weakest-channel form
    (Telegram / e-mail) and the invariant is enforced there — **no raw dangerous character ever
    passes through**.
  - **Confusables via a pinned, self-contained table** (`Unicode`, pinned to 15.1) — a curated
    subset with the UTS #39 skeleton mechanism, structured so the full table is *generated from
    `confusables.txt` at build* later; a Unicode bump is then an explicit, reviewed security change,
    not a surprise runtime-dependency shift. Published **renderer conformance vectors**.
  - **Reviewability limits** (`ArgumentReviewer`): a small payload is shown in full; a large one is
    **not silently trimmed under an Approve button** — it is `TooLarge` with its size, SHA-256 and a
    bounded preview. A tool with `require_reviewable_arguments` (new `ToolClass` flag) **refuses** an
    opaque/oversized payload rather than let a human rubber-stamp what they cannot see; the verdict
    is attached to the gateway result for audit.
  - 17 more tests (112 total in the gateway, in CI).

### Security

- **MCP Gateway — 0.3.1 security hardening of the fingerprint boundary** (before any live wire,
  the cheapest time to fix it). From an owner review of 0.3.0:
  - **Unambiguous framing (→ `kalitka-mcp-call-v2`).** The fingerprint and `tool_contract_id` now
    join fields with **length-prefixed** framing, not a `0x00` delimiter — so a value containing a
    NUL can no longer shift a boundary and collide two different calls.
  - **Fingerprint == executed args.** The canonicalizer rejects **unsafe integers** (beyond
    ±(2^53−1); they must travel as strings, per I-JSON), and the gateway now **forwards the exact
    canonical bytes it fingerprinted** — closing the split where a big integer could hash the same
    but reach an `Int64`/`BigInteger` upstream as a different value.
  - **Transport failure after dispatch is `OutcomeUnknown`, not `Failed`.** A timeout / cancel /
    broken pipe after the call was sent may mean it already ran; the grant is burned as unknown
    (surfaced to the approver), never auto-retried nor recorded as a proven failure. Only a
    definite upstream result/error is `Executed`/`Failed`.
  - **Approval is not a standing permission.** New `ApprovedTtl`, checked **atomically at claim**;
    a stale approval cannot execute. The `NoApproval` path no longer overwrites an active record,
    so two identical concurrent auto-allowed calls cannot both dispatch.
  - **JCS hostile-input limits:** reject trailing content after the value and lone UTF-16
    surrogates; cap input bytes (256 KiB), nodes (10 000), string length (64 KiB) and depth (32).
  - **Inventory is not trusted:** a duplicate tool name or a non-object `inputSchema` rejects the
    whole snapshot; the contract id now folds in a **durable digest epoch** of the whole snapshot
    (deterministic and restart-stable) instead of a local counter.
  - **Typed identity in the binding:** `HandleAsync` takes an `AuthenticatedCallContext` (workload
    id + assurance, subject id + asserted/claimed) and the fingerprint binds all of them, so one
    identity string can't stand for two trust levels.
  - **Published end-to-end conformance vectors** (schema → contract id → canonical args →
    fingerprint → Call ID), so a third-party gateway can prove the whole pipeline, not just JCS.
  - **Migrated to net10.0** (LTS to Nov 2028); CI now provisions both the .NET 9 and .NET 10 SDKs.
  - 95 gateway tests in CI.

### Added

- **MCP Gateway — tool inventory, drift detection & proxy orchestration (`src/KalitkaMcpGateway`
  → 0.3.0).** The gateway now turns a `tools/call` into a decision and forwards it (over an
  `IUpstream` seam) only after a human approved the exact call.
  - **`ToolInventory`** snapshots the upstream's tools at a revision; `tool_contract_id` folds in
    the revision, so bumping it invalidates every not-yet-approved request against the old
    inventory. `Diff` surfaces added / removed / **retyped** tools for audit.
  - **Classification is bound to the observed contract** (`IToolClassifier.Classify(alias, tool,
    contractHash)`): a new, renamed, or schema-changed tool resolves to `Unclassified` — never
    auto-allowed — until an admin classifies that exact contract. Classifying by name alone would
    let a retyped tool inherit the old tool's trust.
  - **`GatewayProxy.HandleAsync`** — canonicalize args → fingerprint → classify → `CallGate` →
    on approval, **claim once and forward once** (the at-most-once guarantee), completing with the
    upstream's success/error; `Pending` never forwards (a normal result with a Call ID); unknown/
    withdrawn tools and unparseable arguments are refused. `RefreshInventoryAsync` bumps the
    revision on drift and returns the diff.
  - 12 more tests (73 total in the gateway, in CI), driven by a fake upstream. The real MCP client
    to a live upstream (stdio/HTTP) and wiring approval to Core's human channels are next.

- **MCP Gateway — decision + execution state machine (`src/KalitkaMcpGateway` → 0.2.0).** The
  gateway's security core on top of the fingerprint: classification from policy and the call
  lifecycle that makes approval mean something.
  - **Classification is policy's, never the guarded server's** (`IToolClassifier` / `ToolClass`):
    `NoApproval`, `NeedsApproval{required}`, or `Unclassified`. An unclassified tool — including
    one that appears after an upstream update (inventory drift) — is **never auto-allowed**:
    manual approval by default, deny in strict mode.
  - **`CallGate` state machine**, keyed by fingerprint: `Pending → Approved →
    ExecutionClaimed → Executed | Failed`, plus `Denied`, `Expired`, `OutcomeUnknown`.
    `ExecutionClaimed` is the **at-most-once** gate — exactly one claim wins, so two retries after
    an approval can't run a destructive tool twice. A claim that never reports an outcome expires
    to **`OutcomeUnknown`** (fail closed; a late success is refused) rather than silent success.
    Approvals count **distinct principals**; an unacted approval expires and may be retried fresh;
    a **denied** call stays denied on re-issue. Re-issue-safe: the AI re-sends the same call and it
    resolves by fingerprint (a changed argument is simply a different, un-approved call).
  - 12 more tests (61 total in the gateway, in CI). In-memory for this slice — the upstream MCP
    proxy, `tools/list` drift detection, Core-notification and the human-safe renderer are next.

- **MCP Gateway — security foundation (`src/KalitkaMcpGateway`, 0.1.0, public/AGPL).** The first
  slice of the guarded proxy in front of another MCP server: the canonical **call fingerprint**
  a grant binds to, so nothing (tool, contract, subject, workload, arguments) can change between
  approval and execution — a human who approves `restart_vm(dev-01)` can never have
  `restart_vm(prod-web-01)` execute against it.
  - **`Jcs.Canonicalize`** implements **RFC 8785** exactly: objects sorted by UTF-16 code units,
    minimal string escaping (lowercase `\u00xx`), and ECMAScript `Number::toString` for numbers —
    **not** a platform `ToString`; the formatting is applied per the spec steps and pinned by
    **V8-derived boundary vectors**. Two v1 rules, both fail-safe: no schema defaults (absent ≠
    `null`) and no Unicode normalization (NFC ≠ NFD at the byte level; confusables are the
    renderer's job later). Duplicate keys and non-finite numbers are rejected.
  - **`CallFingerprint`** — `call_fingerprint = SHA-256(scheme ‖ upstream_alias ‖ tool ‖
    tool_contract_id ‖ subject ‖ workload ‖ JCS(args))`; `tool_contract_id` binds the *observed*
    `inputSchema` + inventory revision (excludes description/title/icons and, in v1, outputSchema);
    a human-quotable Call ID (`7DM4-R9KT-2F81`, Crockford base32) shown everywhere the call is.
  - **Published conformance vectors** (`conformance/kalitka-mcp-call-v1.json`) run in CI — the
    test *is* the conformance check, so a third-party gateway can prove identical canonicalization.
  - net9, no external deps; in CI (unlike the net10/Windows agents). Later slices: the proxy,
    policy match on `mcp:<server>/<tool>`, the `pending`→…→`Executed` state machine, and the
    human-safe renderer + reviewability limits.

- **Windows agent — RDP JIT (`src/KalitkaAgent.Windows` → 0.2.0).** The public agent now grants
  just-in-time Remote Desktop access: on an approved+redeemed grant it adds the Core-approved
  subject to the local **Remote Desktop Users** group for the grant's lifetime, then removes
  them — and survives a restart. This is what makes the public Windows agent useful on its own
  (per the open-core boundary), alongside the agent protocol and asserted `sid:` subject.
  - Pipe protocol gains `{"action":"rdp"}` (raise `rdp:<host>` for the caller, subject asserted)
    and `{"action":"rdp_activate","requestId":...}` (on approval, redeem + add to the group until
    the exact expiry). The grant's Core-approved subject must be the caller activating, else
    `beneficiary-mismatch`.
  - Membership is by **SID** against the group's **well-known SID** (S-1-5-32-555) — locale-safe
    (the group name is resolved, never assumed) and unspoofable by name.
  - **A Core outage never extends access:** expiry is a locally known time; a 60 s sweeper removes
    expired leases with no Core call. **Survives restart:** a write-ahead journal records the lease
    before the group is changed, and startup reconcile drops expired leases and re-asserts valid
    ones.
  - Tests: `RdpEnforcerTests` (add/expire/revoke/reconcile, deterministic against a fake group +
    clock) and an RDP round-trip in `CoreRoundTripTests` (raise → approve → poll → redeem returns
    the approved subject + exact expiry). Requires rights to change local group membership
    (LocalSystem). Not in CI (net10/Windows-only).

- **MCP server onto the control plane — v1 (`src/KalitkaMcp`, 0.1.0).** An MCP server (stdio,
  official `ModelContextProtocol` SDK) that lets an AI talk to Kalitka *itself*: `kalitka.request_access`,
  `kalitka.get_request`, `kalitka.end_session`. There is **no `approve_request` tool, by construction**
  — a workload that both asks and approves makes the human decoration; a reflection test asserts
  the absence as an invariant. The server is just another signed `/agent/*` client (portable
  ECDSA P-256, `kalitka-agent-sig-v1`), so the control plane needs no MCP-specific endpoint.
  - Part 1 of the MCP track (server); part 2 (gateway in front of other MCP servers, with
    call-fingerprint binding and safe rendering) is separate.
  - stdio is the first transport, **not an architectural boundary** — tools and the Core client
    are transport-agnostic, so HTTP/OAuth slots in later. `subject_identity` is claimed (routing
    only; a desktop host is impersonable → never trusted for self-approval).
  - Tests: signature parity with Core's `AgentSignatures`; the exact tool surface + no `approve_*`;
    a real round-trip against the live Core pipeline (enroll → request → stays `waiting` until a
    human approves → grant; out-of-scope resource is 403); plus a stdio `initialize`/`tools/list`
    handshake smoke. Not in CI (built separately). Deferred: first-class `reason`,
    `list_my_grants`, HTTP/OAuth transport.

- **Windows agent — thin end-to-end slice (`src/KalitkaAgent.Windows`, 0.1.0).** A Windows
  Service (net10.0-windows; Core stays on net9, they meet only over the versioned
  `kalitka-agent-sig-v1` HTTP scheme) that makes app-side JIT access *trustworthy*: an
  untrusted local process connects over a named pipe, the service impersonates the pipe token
  to read the caller's SID + account from the OS, and raises a signed request to Core with the
  **OS-asserted** subject (`os:DOMAIN\user`) — never a caller-typed string. This is why it may
  carry `subject.assert` where a generic CLI cannot.
  - ECDSA P-256 key in a CNG provider — Microsoft Platform Crypto Provider (TPM-backed) with a
    software-KSP fallback; private key non-exportable, signatures IEEE P1363 (64 bytes), which
    Core's `ecdsa-p256` suite verifies natively.
  - Enrolls once with a one-time token (registers the SPKI, persists the agent id); every
    request is signed, no reusable secret is ever sent.
  - Tests prove the two things that matter: a CNG signature verifies byte-for-byte under
    Core's `AgentSignatures` (`WireParityTests`), and the agent's `CoreClient` is accepted by
    the **real Core pipeline** with the subject trusted only when `subject.assert` is held —
    else `claimed-not-asserted`, and a wrong key is 403 (`CoreRoundTripTests`).
  - Not in CI (Windows-/net10-only, built separately); deferred: MSI/packaging,
    session-end/redeem, reconnect/liveness, concurrent connections.

## [0.31.0] - 2026-09-14

### Added

- **`policies.explain` + `policies.simulate` — deterministic policy reasoning in core, no AI.**
  Built first (ahead of the MCP server, gateway and policy copilot) precisely so the copilot,
  when it comes, can only *retell* a deterministic trace, never invent one. Both go through the
  **same composition** the request engine uses (`PolicyService.Compose`), so an explanation or
  an impact analysis can never disagree with what a real request would get.
  - **Explain** — for one concrete request context (resource + agent tags + optional profile):
    which policies were considered and, in plain words, why each did or didn't match; the
    effective decision; and the provenance of each strictest value (`approvals=2 from prod-ddl`).
    Surfaced read-only at `/admin/policies/explain` (shareable GET URL). This is also the
    "would this launch/call be allowed?" primitive the `app:` and MCP tracks need.
  - **Simulate** — the impact of a proposed change (`Upsert`/`Remove`, unsaved) on a context,
    classified deterministically as **No effective change | Restriction | Authority expansion |
    Mixed change**, field by field. A policy set only restricts an agent's own authority, so a
    *change* is comparable; `Authority expansion` / `Mixed` (a request that was harder is now
    easier — fewer approvers, longer TTL, `subject required→optional`, a dropped constraint, a
    widened principal list) is flagged `RequiresApproval` — that is what must earn its own
    approval. (Corrects the earlier over-strong "a policy only restricts": the invariant is that
    *changes* are deterministically comparable, not that a change cannot expand authority.)

## [0.30.2] - 2026-09-14

### Security

- **`subject.assert` treated as a sudo-grade capability — loud to grant, loud to revoke.**
  With subject approval live (0.30.1), an agent holding `subject.assert` can assert *who the
  subject is*, and that assertion feeds both authorization and the quorum. That is authority
  over the decision, not just the ability to raise a request — so a generic agent must never
  carry it (only the Windows/macOS trusted executor should), and handing it out or taking it
  back must never be a quiet line in a diff.
  - **Its own audit event.** Granting `subject.assert` at agent creation, at enrollment-token
    mint, or via reconcile now emits a distinct `agent.privileged_capability`
    event (`granted`/`revoked` <cap>) alongside the ordinary enrollment/profile-applied entry —
    queryable on its own, not buried in a metadata blob.
  - **Marked in the reconcile diff and the admin UI.** A privileged capability shows with a
    `!` marker in the profile-applied audit diff (`caps: +!subject.assert`) and a distinct
    `privileged` pill / badge on the reconcile overview, the agent detail page, and the
    profiles table — impossible to miss beside an ordinary capability run.
  - No new grant path: the 0.16-0.17 snapshot/reconcile model already guarantees that editing
    a profile never arms an already-enrolled agent. A grant still requires a deliberate,
    confirmed reconcile (it is an expansion); this slice only makes that grant conspicuous.

### Notes

- No schema change; store layer untouched. `AgentCapabilities.Privileged` is the single
  source of truth for what counts as sudo-grade (today: `subject.assert`), so future
  capabilities of this class inherit the audit/diff/UI treatment automatically.

## [0.30.1] - 2026-09-13

### Security

- **Subject approval: the two boundaries of `self`, fixed before it gets teeth.** Routing
  (0.30.0) took `subject_identity` straight from the request body — fine for *addressing* a
  notification, but unsafe the moment a subject can approve its own action. This slice draws
  the line before app-launch arrives.
  - **A subject that gates approval must be asserted by a trusted executor, not the
    requester.** New agent capability `subject.assert`: only such an agent's subject is
    `asserted` (usable for subject-approval); a generic agent's `--subject-identity` stays
    `claimed` (routing only). Windows will assert the SID from the OS security context; the
    CLI cannot choose it. (Also closes a live gap: a caller could set the subject and thereby
    suppress admin notification.)
  - **`ApprovalSelf` replaced by an explicit, orthogonal `subject: optional | required |
    forbidden`.** `required` = the subject **must** approve **and** `RequiredApprovals`
    distinct principals in total (`required:1`→subject alone; `required:2`→subject + one
    other); `forbidden` = the requester may not approve at all (clean four-eyes). Distinctness
    is by operator principal, never by channel.
  - **The subject must be the grant's beneficiary** — a request for `--user Administrator`
    can't be satisfied by a different subject's tap (`beneficiary-mismatch`). **No admin
    fallback under `required`:** an unmapped/untrusted/mismatched subject is refused up front
    (`subject-unmapped` / `claimed-not-asserted` / `beneficiary-mismatch` / `subject-required`
    / `subject-unreachable`, all 409, audited) rather than silently dropping the requirement.

### Notes

- New column `requests(subject_mode)` in SQLite + Postgres (idempotent); non-breaking.
  Migration: an `ApprovalSelf` policy is superseded by `subject: required` (recreate it; the
  field is day-old and had no deployed use). Verified: a claimed subject can't satisfy
  `required`; beneficiary≠subject and unmapped are refused, not fallen back; `required:2`
  needs the subject and one other (two channels of one person still count once);
  `forbidden` refuses the requester's own approval. Full suite (268) green incl. Postgres.
  Design: `docs/design/subject-approval.md` (with claude-fd). Now safe for the Windows agent.

## [0.30.0] - 2026-09-13

### Added

- **Per-request notification routing — ask the right person, not always the admins.** The
  forward half of operator principals (0.27.0 resolved an *answer* to a person; this routes
  a *request* to the person who must be asked). A request carries a machine-readable
  **`subject_identity`** (identity-shaped, e.g. `os:CONTOSO\anna`, `sid:S-1-5-…`), which the
  gate resolves to an operator principal and asks **them**.
  - `PrincipalService.IdentitiesOf(principalId, scheme?)` — the reverse of `Resolve`. Each
    notifier targets its own scheme (`telegram:`, `email:`) from the resolved identities; a
    request with no `subject_identity` asks the admins exactly as before.
  - **`NotifyRouting`** is resolved once per request and passed to every notifier
    (`INotifier.Announce` now takes it). An unmapped subject **falls back to the admins and
    is audited** (`notify.fallback`) — never silent. The fallback never lowers a policy's
    approval requirement (a `quorum(2)` stays a quorum however it was routed).
  - **Policy `self`** (`ApprovalSelf`) routes a request to its own subject — the person
    confirms their own action, and **only they** are asked; everything else asks the
    operator *and* the admins. `self` is explicit per policy, so 0.19.3's distinct-approver
    rule for a quorum is never quietly undermined. `kalitka-agent request` gains
    `--subject-identity`.

### Notes

- New column `requests(subject_identity)` in SQLite + Postgres (idempotent); non-breaking.
  Verified: a mapped subject asks the operator + admins, a `self` policy asks only the
  operator, an unmapped subject falls back to admins + audits it, an ordinary request is
  unchanged, and `IdentitiesOf` is the reverse of `Resolve`. Full suite (262) green incl.
  Postgres. Unblocks app-launch self-confirmation, the solo tier, and the demo stand.
  Design: `docs/design/notification-routing.md` (with claude-fd).

## [0.29.0] - 2026-09-13

### Added

- **Pluggable agent signature suites + SPKI key material (the seam before a Windows agent).**
  `AgentSignatures` no longer knows Ed25519 concretely; verification goes through
  `IAgentSignatureSuite` (`CanHandle`/`ValidatePublicKey`/`Verify` over SPKI), with
  **Ed25519** and **ECDSA-P256** registered. The canonical signed string is unchanged, so
  the wire scheme stays `kalitka-agent-sig-v1` — this is additive, not a protocol break.
  - **SPKI is the canonical key form.** Public keys are stored as `SubjectPublicKeyInfo`, so
    the algorithm is derived from the credential, never declared beside it or chosen by the
    caller (no algorithm-confusion downgrade). New enrolment is **SPKI-only** (`IsValidSpki`);
    keys registered before this — raw 32-byte Ed25519 — are normalised to SPKI **on read**, so
    they keep verifying untouched. `kalitka-agent` now sends the full SPKI.
  - **Key id = fingerprint** `base64url(SHA-256(SPKI))` for new keys — idempotent
    re-registration of the same key. Legacy random ids are left as-is (the `X-Kalitka-Key-Id`
    header is an optional filter, so they keep matching until they rotate out).
  - **ECDSA-P256 on the wire:** SHA-256 + IEEE **P1363** (r‖s), exactly 64 bytes — DER is
    rejected, never sniffed (a leading `0x30` is a plausible P1363 byte, not a discriminator).
  - **Claimed vs verified, two fields on a key:** `provider_hint` (`software` |
    `windows-platform` | `apple-secure-enclave` | `unknown` — a local claim) and `assurance`
    (`unverified` default | `attested-tpm` | `attested-secure-enclave` — what Core verified).
    Policy will read `assurance` only; until attestation exists the console says "Platform
    Crypto Provider — not remotely attested", never "TPM protected".

### Notes

- No schema change — agent keys are stored as JSON, so the two new fields are additive.
  Verified: Ed25519 SPKI and legacy raw both verify (incl. the OpenSSL interop known-answer
  vector), ECDSA-P256 P1363 verifies and DER is rejected, the suite is chosen from the key
  not the signature, raw & SPKI of one key share a fingerprint, and new enrolment is SPKI-only.
  Full suite (257) green incl. Postgres. Unblocks the Windows agent (ECDSA P-256 via CNG /
  Microsoft Platform Crypto Provider) with no BouncyCastle in the client. Design:
  `docs/design/agent-identity.md` (with claude-fd).

## [0.28.0] - 2026-09-13

### Added

- **Hardened SSH CA signer boundary.** The CA private key is a serious trust boundary —
  anyone who can *read* it can mint certificates outside kalitka. The CA-touching step
  (redeem + sign) is now the `kalitka-ssh sign-redeem` subcommand, meant to run as a
  dedicated `kalitka-ca` user behind a privilege boundary:
  - `KALITKA_SSH_SIGN_CMD` (e.g. `sudo -n -u kalitka-ca /usr/local/bin/kalitka-ssh`) makes
    `connect`/`sign` delegate signing: the public key crosses on **stdin**, the certificate
    comes back on **stdout**, so the calling operator's process never opens the CA key (no
    cross-user file access needed). Unset = in-process signing (simple/dev only).
  - `sign-redeem` takes **nothing** about the cert's contents from the caller — principal,
    force-command, source-address and expiry all come from Core's redeem — so the boundary
    protects the key material; cert contents were already bound to the approval (0.25.1/0.26).
    A tight sudoers rule (`sign-redeem *` only) and an HSM/separate-host signer are the
    documented next steps; this is the seam for them.

### Notes

- Pure client-side — no `Kalitka.dll` change; reuses redeem/provisioned/session-end. Both
  paths verified with `ssh-keygen -L`: in-process and delegated (pubkey via stdin, cert via
  stdout) produce the same cert — correct principal, `force-command` and `source-address`,
  and no session-id leakage into the cert. Completes the deeper-SSH track (0.25–0.28).

## [0.27.0] - 2026-09-13

### Added

- **Operator principals — a quorum counts people, not channels.** A quorum (`required: 2`)
  used to count only `google:<sub>`; a Telegram tap or e-mail link could not be a second
  person. Now an **operator principal** at `/admin/principals` binds a human's channel
  identities (`google:<sub>`, `telegram:<user_id>`, and — by the same model —
  `slack:<team>:<user>`, `teams:<tenant>:<oid>`, `app:<id>`), and the quorum counts
  **distinct principals**:
  - a Telegram (later Slack/Teams/app) approval by a **linked** identity counts as that
    operator, so it can satisfy four-eyes;
  - the **same operator on two channels counts once** — one human cannot satisfy a quorum
    alone;
  - an **unlinked Google admin still counts as itself** (no setup for the common case); any
    other unlinked identity can satisfy a single approval but not a quorum.
  - Channels are transports of one control plane: adding a channel is a new identity scheme
    to link — the quorum logic does not change. An identity belongs to at most one operator
    (enforced on save); CRUD is audited (`principal.*`) and stored in the shared config
    (durable/cluster-wide). New permission `principals.manage` (in the policy-admin bundle,
    which full admin has).

### Notes

- No schema change — operator principals live in the shared config store (SQLite/Postgres/
  JSON), like policies. Verified: a linked Telegram approval reaches a quorum, the same
  person on two channels dedupes, an unlinked identity does not count, an unlinked Google
  admin still does, and an identity cannot be linked to two operators. Full suite (250)
  green incl. Postgres. This unblocks **Slack / Teams / first-party app** as transports of
  the one control plane.

## [0.26.1] - 2026-09-12

### Added

- **Policy-bound `source-address` + principal allow-lists (completing 0.26).** Two more
  restrict-only controls, carried through the grant with the same discipline as `command`
  (0.26.0) — the signer applies only what Core approved, never a caller argument.
  - **Source-address.** A request can carry a `source_address` (approved CIDR list); redeem
    returns it and `kalitka-ssh --source-address` issues a cert pinned to it
    (`source-address` critical option) — a stolen cert is useless elsewhere. Policy
    `RequireSourceAddress` forbids an unpinned cert for a resource (`source-required`).
    New `requests(source_addr)` column (idempotent).
  - **Principal allow-lists.** Policy `AllowedPrincipals` restricts which logins a request
    may ask for (e.g. `deploy`/`readonly`, never `root`); a disallowed login is refused up
    front (`principal-not-allowed`). Several matching policies **intersect** — a login must
    be permitted by every one. (The cert principal was already bound to the approved subject
    in 0.25.1.)
  - Both `source_address` and the two policy flags are shown to the approver (Telegram +
    web request detail) and settable on the Policies admin page.

### Changed

- **README brought up to date.** It framed kalitka only as a web doorbell and still
  said the SSH gate had "no certificates"; it now describes the three access axes —
  web, SSH (login gate + JIT/force-command certificates), and database JIT (SQL Server /
  PostgreSQL, ephemeral/grant/action, bounded grants, crash recovery) — the current admin
  console surface, policy profile-match / require-command, i18n, and the broader test suite.

## [0.26.0] - 2026-09-12

### Added

- **Command-aware approval + SSH `force-command` certificates.** A request can carry the
  exact command the operator wants to run; the approver sees it, it is recorded, and it is
  returned on redeem so an SSH-cert signer can force it — the session can run only that
  command. The SSH analogue of 0.24's stored-procedure actions: *sergej → prod-01 → exactly
  `systemctl restart nginx` → approved by N people.*
  - New request field **`command`** (stored, shown in the Telegram notification and the web
    request detail, recorded in `access.requested`); redeem returns the **approved**
    `command`, bound the same way as the principal (0.25.1) — the signer forces only what
    Core approved, never a caller argument. `kalitka-agent request --command`, and
    `kalitka-ssh connect/sign --command '…'` issues a cert with `force-command`.
  - **Policy `RequireCommand`** (restrict-only): a matching resource may forbid open-shell
    access — a request with no command is refused up front (`command-required`, HTTP 409),
    so no one is asked to approve an open shell that policy disallows. Toggle it on the
    Policies admin page. Command-aware quorum rides on the existing profile/tags matching
    (`env:prod` → 2 approvers).

### Notes

- New column `requests(command)` in SQLite + Postgres, added idempotently; non-breaking.
  Verified: the approved command flows to redeem and into the cert's `force-command`
  critical option (`ssh-keygen -L`), a `RequireCommand` policy refuses a command-less
  request, and the full suite (242) is green incl. Postgres. Follow-ups (roadmap):
  policy-bound `source-address` and the richer `requested → approved` principal mapping
  (0.26.1); hardened CA signer boundary (0.27).

## [0.25.1] - 2026-09-12

### Fixed

- **SSH certificate principal is now bound to the approved identity (security).** Before,
  `kalitka-ssh --principals <x>` fed `ssh-keygen -n` a value chosen *after* approval, so an
  approved request for one login could be signed into a certificate for another (e.g.
  `root`) — the approved identity and the certificate principal were not cryptographically
  linked. Now redeem returns the Core-approved **`subject`** (the request's user), and the
  signer uses **only** that as the principal; the `--principals` argument is removed. The
  principal is validated to a safe charset before signing.
- **Certificates cannot outlive the granted authority (security invariant).** Validity was
  rounded up to whole minutes (and a just-expired grant still got a fresh minute). The cert
  end is now the grant's exact `expires_at` (raw epoch seconds, `-V 0x<start>:0x<exp>`, a
  5-second negative start absorbing clock skew), and issuing is **refused** if the grant has
  already expired.
- **Truthful SSH outcome.** `kalitka-ssh connect` no longer swallows `ssh`'s exit code and
  report every attempt as `closed`. It preserves and returns the real exit code, and reports
  the session as `connection-failed` on `ssh` 255 (connection/auth failure) versus `closed`
  for a session that actually ran.

### Notes

- Small additive Core change: redeem now returns `subject` (the approved principal). Verified
  end to end: redeem carries the approved user, the signer binds the cert principal to it and
  refuses an expired grant, and the cert end matches `expires_at` exactly (`ssh-keygen -L`).
- Known follow-ups (roadmap): richer `requested_principals → policy → approved_principals`
  mapping and policy-bound `force-command` / `source-address` land with the sudo/command-aware
  work (0.26); a hardened CA signer boundary (privileged helper / HSM-backed signer, so the
  calling user cannot read the CA key) is 0.27.

## [0.25.0] - 2026-09-12

### Added

- **JIT SSH access via short-lived certificates (`deploy/ssh/kalitka-ssh`).** The
  certificate analogue of the DB connector, same architecture: Core → signed grant →
  local tool that **holds the SSH CA key** → target host. Core never holds the CA key; it
  only decides yes/no.
  - `kalitka-ssh connect --host H [--user U]` on a bastion mints an **ephemeral** keypair,
    raises an access request, waits for approval, signs a **short-lived OpenSSH user
    certificate** (principals from the request, validity from the grant's `expires_at`, so
    it reflects any access policy and cannot outlive the granted authority), then `exec`s
    `ssh`. The certificate **self-expires** — nothing to revoke, no orphan, and a crash
    leaves no standing access.
  - The cert's key-id is `kalitka:<session-id>`, tying sshd's auth log to the kalitka
    audit trail; conservative cert options by default (`permit-pty` only — no agent/port/X11
    forwarding), overridable. `kalitka-ssh keygen` creates the CA and prints the public key
    for hosts' `TrustedUserCAKeys`; `sign --pubkey FILE` is the lower-level path.

### Notes

- Pure client-side — no `Kalitka.dll` change; reuses request/poll/redeem/provisioned/
  session-end and the `expires_at` from 0.23.4. Certificate issuance verified with
  `ssh-keygen -L` (correct principal, `kalitka:<session>` key-id, ~grant-TTL validity,
  restricted extensions). Complements the PAM approval gate; next SSH steps: sudo-aware
  approvals and certificate source-address/force-command from policy.

## [0.24.0] - 2026-09-12

### Added

- **Usage-controlled database actions (`kalitka-db-agent action`).** For an unambiguous,
  pre-approved operation, handing out an interactive login is the wrong shape and counting
  "uses" of an interactive session is meaningless. Action mode is the honest alternative:
  **no login is handed out** — the profile designates a DBA-vetted stored procedure, and
  on approval the connector runs it **once** and reports **exactly one use**
  (`POST /agent/v1/sessions/use`). One approval, one call, one honest use — the only place
  `max_uses` is meaningful.
  - The **procedure name and parameter set are trusted config** (`DB_ACTION_MAP`); the
    caller supplies only parameter **values**, bound as literals — nothing caller-supplied
    is ever SQL. The procedure body is the whole security boundary.
  - The connector executes the procedure as the agent's own least-privilege identity
    (`EXECUTE` on exactly these procedures — see `roles.sql`; on PostgreSQL the procedure
    is `SECURITY DEFINER` so `EXECUTE` alone suffices), only ever after Kalitka approves. A
    use is spent **only on success**; a failed action counts as none (`provision-failed`).
    An access policy can raise the bar per action profile as for role profiles.
  - Works on both engines (`driver_run_action`): SQL Server `EXEC`, PostgreSQL `CALL`.

### Notes

- Pure client-side — no `Kalitka.dll` change (`max_uses`/`use` shipped in 0.23.1). Verified
  against **SQL Server 2022** and **PostgreSQL 16**: the vetted procedure executes, an
  injection attempt in a parameter value is stored as inert literal data (the table is left
  intact), and the `EXECUTE`-only agent cannot touch the table directly. Completes the 0.23
  database axis; SSH deepening (JIT certificates, sudo-aware) is next.

## [0.23.5] - 2026-09-12

### Added

- **PostgreSQL connector (5th slice of 0.23).** A second engine on the 0.23.4 contract:
  the shared lifecycle (`kalitka-db-lib`) and crash-recovery reconcile are reused
  **unchanged** — only a new `deploy/db/drivers/postgres` and `roles-postgres.sql`. Set
  `DB_ENGINE=postgres`. Same grant/profile/session semantics, same bounded-grant and
  crash-recovery guarantees.
  - PostgreSQL has no separate login/user: profile roles are `NOLOGIN` **group roles**
    (`kalitka_readonly`, `kalitka_writer`) carrying the privileges; an ephemeral
    principal is a `LOGIN` role that is a **member** and inherits them. Its privileges
    come via membership, so it has no per-database ACLs of its own and `DROP ROLE` removes
    it cluster-wide and cleanly; teardown `ALTER ROLE … NOLOGIN` first, so authentication
    is revoked immediately even if a `DROP` is delayed by leftover owned objects.
  - The agent authenticates as a **`CREATEROLE NOINHERIT`** role with `ADMIN OPTION` on
    the group roles — enough to create/drop ephemeral roles and manage membership, never a
    superuser. Orphan-sweep provenance is stamped in the role's `COMMENT` (`pg_roles` has
    no creation timestamp).

### Notes

- Pure client-side connector — no `Kalitka.dll` change. Reconcile decision table +
  provenance gate verified against **PostgreSQL 16** on the unchanged shared lib
  (local-expiry drop while Core is down, locally-valid keep, orphan-max-age drop, and the
  agent's own role left untouched). Next in 0.23: **0.24 — usage-controlled DB actions**
  (stored-procedure/action profiles with real `max_uses`).

## [0.23.4] - 2026-09-12

### Added

- **DB-connector abstraction + crash recovery (4th slice of 0.23).** The shared
  lifecycle and a narrow provisioning contract are extracted from the SQL Server
  connector *before* a second engine, and — the point of the slice — orphaned access is
  reconciled after a crash. `always deprovisions on exit` only held for a graceful exit;
  an ungraceful death (OOM/SIGKILL/host panic) after `CREATE LOGIN` left a principal that
  physically outlived the agent while its TTL lived only in Core.
  - **Engine-agnostic structure.** `deploy/db/kalitka-db-lib` owns the lifecycle
    (request→approve→redeem→provision→report→hold→deprovision→end→**reconcile**) and the
    gate protocol; a per-engine driver (`deploy/db/drivers/<engine>`) owns only the SQL
    (`driver_provision`/`driver_deprovision`/`driver_ledger_*`/`driver_enumerate`). SQL
    Server is the first driver; `DB_ENGINE` selects it. PostgreSQL (0.23.5) drops on unchanged.
  - **Durable provenance = correctness.** Written *before* provisioning, cleared *after* a
    clean teardown, both carrying `expires_at`: a **local journal** (survives a process
    crash) and an **in-DB ledger** `KalitkaProvisionedPrincipals` (survives loss of the
    agent host). Ephemeral principals are named `kalitka_<session-id>`.
  - **`kalitka-db-agent reconcile`** (run at boot and on a timer) decides per principal:
    known + locally expired → drop even offline (`local-expiry`); known + locally valid →
    keep (a Core outage is never on its own a reason to revoke); Core reachable + not open
    → drop (`core-confirmed`); a Kalitka-owned principal past `OrphanAbsoluteMaxAge`
    (default `2 × MaxGrantTtl`) → drop (`orphan-max-age`). It **never** drops a principal
    without reliable Kalitka provenance.
  - **Core additions:** the session carries the grant's `expires_at` (returned on redeem);
    **`GET /agent/v1/sessions/{id}` → `{state, expires_at}`** for a liveness check; and
    **`POST /agent/v1/sessions/reconciled`** records a crash-recovery revoke with its
    distinct reason (audited `session.reconciled`) — so a cleanup made without Core
    confirmation is always explainable. `kalitka-agent` gains `liveness` and `reconciled`.

### Notes

- New column `sessions(expires_at)` in SQLite + Postgres, added idempotently for upgrades;
  non-breaking. Reconcile decision table + provenance gate verified against SQL Server 2022
  (local-expiry drop while Core is down, locally-valid keep, orphan-max-age drop, and a
  non-Kalitka login left untouched). Next in 0.23: **PostgreSQL** on this contract.

## [0.23.3] - 2026-09-12

### Added

- **Reference DB-agent connector for SQL Server (`deploy/db/kalitka-db-agent`),
  completing 0.23.** The local half of the database-JIT architecture: it runs next to
  SQL Server, turns an approved kalitka grant into real, time-boxed SQL access, and
  removes it when the grant ends. Core stays the control plane and holds no DB-admin
  credential — *kalitka brokers authority, not database credentials.*
  - Delegates the protocol (raise / poll / redeem / report) to `kalitka-agent`, so
    every gate call is Ed25519-signed; it only adds the SQL provisioning.
  - Maps a grant **profile** to a predefined SQL role **locally** (`DB_PROFILE_MAP`);
    Core only ever sends the profile name, never raw SQL. Two modes: **ephemeral**
    (default) creates a JIT login+user → role → `DROP`, returning the credential to the
    operator out of band (Core never sees it); **grant** adds an existing `--login` to
    the role and removes it after. **Always deprovisions on exit** (Enter, Ctrl-C, TTL,
    or error) and reports `session.provisioned` / `provision-failed` / `session.ended`.
  - Ships `roles.sql` (the predefined roles + the agent's **least-privilege**
    provisioning identity — `ALTER ANY LOGIN`/`ALTER ANY USER` + `ALTER` on the mapped
    roles, not `db_owner`/`sysadmin`; a **gMSA** with integrated auth on Windows),
    a config example, and a README. Identifiers are charset-restricted and
    bracket-quoted before reaching T-SQL.

### Notes

- Pure client-side connector — no `Kalitka.dll` change; the server-side protocol it
  uses landed in 0.23.2. Next in 0.23: **PostgreSQL** + a general database-connector
  abstraction.

## [0.23.2] - 2026-09-12

### Added

- **SQL Server resource model + provisioning protocol (second slice of 0.23).** The
  bounded-grant model now spans any agent-brokered resource, not just SSH: a database
  agent raises requests for a **`db:<server>/<database>`** resource, an access policy can
  raise the bar on a specific **grant profile**, and the connector reports back whether
  it actually provisioned the grant.
  - Agent requests take an explicit **`resource`** (any scheme — `db:sql01/orders`,
    `sudo:…`, `ssh:…`), validated to a sane charset; the SSH hooks keep their
    `ssh:<host>` shorthand. The authenticated agent may only raise resources it is
    scoped to, and a grant is now issued for **any agent resource** (not only `ssh:`) —
    never for a `web:` visitor request.
  - **Policy on the grant profile.** `AccessPolicy` gains a `MatchProfile` glob (e.g.
    `sql-dba`, `sql-*`), so four-eyes can be required for DDL/DBA profiles while
    read-only stays single-approval. Restrict-only and most-restrictive-wins as before.
  - New **`POST /agent/v1/sessions/provisioned`**: the connector reports the grant was
    applied (audited `session.provisioned`) or **failed** (the session is closed as
    `provision-failed`, since access was never really granted). `kalitka-agent` gains a
    `provisioned --session-id [--error MSG]` subcommand and a `request --resource` flag.

### Notes

- *Kalitka brokers authority, not database credentials.* Core hands the connector a
  server-side profile and bounds; it holds no DB-admin credentials and issues no
  arbitrary SQL permissions. The reference DB-agent connector — existing-principal
  `GRANT`/`REVOKE` or ephemeral login/role/`DROP` under a least-privilege service
  identity (gMSA) — lands in 0.23.3. No schema change; non-breaking.

## [0.23.1] - 2026-09-12

### Added

- **Universal bounded-grant model (first slice of 0.23, DB-agnostic).** A grant — and
  the session it starts — now carries a server-side **`profile`** (e.g. `sql-readonly`,
  `sql-writer`; opaque to Core, the connector knows what it means) and an optional
  **use budget**. A grant ends on the *first* of: its TTL / session expiry (0.22), its
  uses being spent, or an explicit revoke. *Kalitka carries the authority (profile +
  bounds); it never holds database credentials.*
  - Agents raise a request with `profile` and `max_uses`; on redeem the response
    returns the `profile` so the connector knows what to provision, and the session is
    created with the use budget (`remaining_uses`, `-1` = unlimited).
  - New **`POST /agent/v1/sessions/use`** reports one use of a granted operation:
    it decrements the budget and, when it reaches zero, closes the session as `spent`
    (the connector then revokes). An unlimited grant reports `-1` and never spends.
  - `/admin/sessions` shows the profile and uses-left. `kalitka-agent` gains
    `request --profile/--max-uses` and a `use --session-id` subcommand.

### Notes

- This is the DB-agnostic Core foundation. The SQL Server resource model + provisioning
  protocol (0.23.2) and the reference DB-agent connector — existing-principal
  `GRANT`/`REVOKE` or ephemeral login/role/`DROP`, under a least-privilege service
  identity — (0.23.3) build on it. Core does not count arbitrary SQL transactions;
  `max_uses` fits an unambiguous operation (e.g. a pre-approved stored procedure). New
  columns `requests(profile, max_uses)` and `sessions(profile, remaining_uses)` in
  SQLite + Postgres, added idempotently for upgrades. Non-breaking.

## [0.22.0] - 2026-09-12

### Added

- **SSH session correctness.** A live sessions view at `/admin/sessions` (subject,
  resource, agent, started, state, request) surfaces the request ↔ grant ↔ agent ↔
  session linkage. An admin can **revoke** an open session out of band (outcome
  `revoked`, audited). And a session left open past its max lifetime
  (`SessionMaxHours`, default 24) is **auto-closed as `expired`** on the next sweep, so
  a crashed or missed close hook never leaks a permanently-open session.
- The SSH client hooks now keep the session ids in a **LIFO stack per user** (one id
  per line): concurrent logins by the same user push their own id and each logout pops
  one, so they no longer overwrite each other. This removes the previous "one active
  session per user" assumption; any equivalent session a given logout does not close is
  caught by the server-side expiry above.

### Notes

- Permissions: viewing `/admin/sessions` needs `requests.read`, revoking needs
  `requests.decide`. No schema change (the sessions table already carries the outcome).
  This is the SSH-foundation baseline the deeper SSH work (JIT certificates,
  sudo/command-aware) will build on — after 0.23.

## [0.21.3] - 2026-09-12

### Added

- **Secretless enrolment (final slice of 0.21).** An agent can now enrol with **only**
  a token and a generated public key — no usable shared secret is ever created. The
  server accepts key-only (secretless), secret-only (the migration path), or both; for
  key-only it stores an empty, non-verifiable secret hash, so the agent can authenticate
  *only* by signature. `kalitka-agent enroll` is secretless by default (generates the
  key, registers its public half, sends no secret). Enrolment with neither a key nor a
  secret is refused (`no-credential`). The agent detail page shows **Secretless** when
  an agent has no usable shared secret.

### Notes

- This completes 0.21: the reference client (0.21.1), migration observability (0.21.2)
  and secretless enrolment (0.21.3). With new agents key-only and the Auth badges
  showing who still uses the fallback, the migration window can be closed on schedule —
  after which the per-agent and global shared secrets, the legacy `/agent/*` aliases and
  the associated code can be removed. Non-breaking.

## [0.21.2] - 2026-09-12

### Added

- **Migration observability (second slice of 0.21).** Each agent now records how it
  last authenticated — `last_auth_method` (`signature` | `secret`), `last_key_id` (the
  key that signed), and `last_signed_at` — updated on every authenticated call. The
  `/admin/agents` list shows an **Auth** badge (green `signature` with the key id, or
  amber `secret`) and the agent detail page shows the method and last-signed time. So,
  before removing the shared secrets, it is objective which agents have moved to signed
  authentication and which still use the fallback.

### Notes

- New `last_auth_method` / `last_key_id` / `last_signed_at` columns on the agents table
  (SQLite + Postgres, added idempotently for upgrades); the store's `TouchLastSeen` is
  replaced by `RecordAuth`, which also captures the method. Non-breaking. Server changed
  — the gate needs a redeploy (schema migration is automatic).

## [0.21.1] - 2026-09-12

### Added

- **`kalitka-agent` — the reference client (first slice of 0.21).** A small, universal
  agent runtime (`deploy/kalitka-agent`, bash + OpenSSL 3): it holds the Ed25519
  private key and speaks the `/agent/v1/*` protocol, building the canonical request,
  timestamp, nonce and **signature** itself. Subcommands: `keygen`, `pubkey`, `enroll`,
  `request`, `poll`, `redeem`, `session-end`, `heartbeat`. It signs when a key is
  present and falls back to the shared secret otherwise, so strong (signature-based)
  credentials are used automatically. This is where the 0.20 server capability becomes
  a real end-to-end path: without a signing client, signed requests were unreachable in
  the SSH flow.
- The SSH PAM hooks (`deploy/ssh/`) are now **thin wrappers** around `kalitka-agent`;
  any future agent (DB, sudo, …) gets the same credential model for free.

### Fixed

- `deploy/ssh/README.md` was stale — it still described the pre-0.15 `/agent/request`,
  `/agent/status`, `/agent/redeem`, `/agent/session/end`; rewritten for `/agent/v1/*`,
  `kalitka-agent`, and key-based credentials.

### Notes

- The client/server signature interop (bash + OpenSSL 3 → the server's BouncyCastle
  verify) is proven by a known-answer vector generated with OpenSSL and asserted in the
  test suite. Server code is unchanged from 0.20.2, so the gate needs no redeploy;
  install `kalitka-agent` on the SSH hosts. Migration observability
  (`last_auth_method`, …) and a secretless enrolment mode follow in 0.21.2 / 0.21.3.

## [0.20.2] - 2026-09-11

### Added

- **Key rotation and revocation (second slice of 0.20).** A registered signing key can
  be **removed** from the agent detail page (`agent.key_removed` audited); the agent's
  other keys and its shared secret keep working. **Rotation** is add-the-new then
  remove-the-old: because an agent may hold several keys at once, both are valid during
  the overlap, so there is no window without a working key.
- **Enrolment can carry a public key.** A self-enrolling agent may submit its Ed25519
  public key alongside the token and secret, so it starts key-based immediately (the
  key is registered and `agent.key_added` audited).

### Notes

- Completes the signing-key lifecycle for signed requests. The per-agent shared secret
  and the legacy global secret still work in parallel; dropping them (and the `/agent/*`
  aliases) is later, after the migration window. Non-breaking.

## [0.20.1] - 2026-09-11

### Added

- **Ed25519 signed-request agent auth (first slice of 0.20).** An agent can register
  one or more Ed25519 public keys and then authenticate by **signing each request**
  instead of sending a reusable secret. The signature (`X-Kalitka-Signature`, base64)
  covers a canonical string binding the scheme version, method, path, body hash,
  timestamp and a nonce — so it cannot be replayed against a different request; a 5-minute
  timestamp window plus a single-use nonce (the replay store) stop replay of the same
  one. Chosen over mTLS because a signed request reaches the app unchanged whatever the
  reverse proxy does with TLS. Headers: `X-Kalitka-Agent-Id`, `X-Kalitka-Signature`,
  `X-Kalitka-Timestamp`, `X-Kalitka-Nonce`, optional `X-Kalitka-Key-Id`; scheme
  `kalitka-agent-sig-v1`.
- **Register a key** from the agent detail page (`agent.key_added` audited). Keys
  round-trip in SQLite and Postgres (new `keys` column, added idempotently for
  upgrades). Ed25519 via BouncyCastle (pure-managed — no native dependency, safe on the
  Alpine image).

### Notes

- Signed requests are the **preferred** auth path; the per-agent shared secret and the
  legacy global secret keep working in parallel through the migration window. Key
  rotation and revocation come in 0.20.2; dropping the shared secret and the `/agent/*`
  aliases is later, after the window. Non-breaking.

## [0.19.3] - 2026-09-11

### Added

- **Policy enforcement: approval quorum (final slice of 0.19).** A policy's
  `RequiredApprovals` now holds a request open until that many **distinct** approvers
  have signed off. A denial from any channel still denies at once.
- **Distinct-approver-principal.** For a quorum > 1, only an authenticated
  control-plane identity (`google:<sub>`) counts as a distinct approver — the same
  person approving via Telegram and via the web, or an e-mail link, must not satisfy
  four-eyes. Telegram/e-mail may still deny, notify, and satisfy an ordinary single
  approval (`RequiredApprovals` = 1), but do not count toward a quorum. Each recorded
  approval writes `access.approval_noted` (with the running count); the admin request
  detail shows `N / M`.

### Notes

- Storage: `required_approvals` on the requests table (added idempotently for
  upgrades) and a `request_approvals(request_id, principal)` table whose primary key
  makes an approval idempotent and the count race-free across nodes (SQLite + Postgres;
  in-memory keeps a per-request set). Completes 0.19 (tag-driven policy: surface in
  0.19.1, grant-TTL in 0.19.2, quorum here). With no policy raising the bar, every
  request still needs exactly one approval — non-breaking.

## [0.19.2] - 2026-09-11

### Added

- **Policy enforcement: grant lifetime (second slice of 0.19).** When an SSH grant is
  issued, the matching access policies' `GrantTtlMinutes` now applies — the grant is
  minted with the **shorter** of the global lifetime and the policy's, so a policy can
  only ever shorten a grant, never extend it past the global `OneTimeMinutes`
  (restrict-only). Policies are selected by the requesting agent's tags (`AgentIdentity`
  now carries them). Agents whose tags match no policy, and the legacy global-secret
  caller, keep the default lifetime.

### Notes

- Still to come in 0.19.3: the approval quorum (`RequiredApprovals`) with the
  distinct-approver-principal rule. With no policies defined, nothing changes.

## [0.19.1] - 2026-09-11

### Added

- **Tag-driven access policies — the surface (first slice of 0.19).** A policy matches
  a request by resource glob (`ssh:*`) and tags that must all be on the requesting
  agent (`env:prod`), and carries constraints — `RequiredApprovals` and an optional
  `GrantTtlMinutes`. A policy **only ever restricts**: the agent's own authority
  (capability + allowed resource) is checked first, and a policy can never grant a new
  capability or resource. Several matching policies combine the strictest way — most
  approvals (`max`), shortest grant (`min`) — so there is no rule ordering. Managed at
  `/admin/policies`; CRUD is audited (`policy.created` / `updated` / `deleted`), with
  the same append-only revision history as profiles.
- **Policy permissions.** New `policies.read` / `policies.manage` and a **PolicyAdmin**
  bundle; full admin gets them automatically.

### Notes

- This slice ships the model, storage, matching/combination and the console — it is
  **not yet enforced** on the approval flow. Grant-TTL enforcement follows in 0.19.2
  and the approval quorum (with the distinct-approver-principal rule) in 0.19.3, so the
  behaviour change lands deliberately and in reviewable steps. Additive and
  non-breaking: with no policies defined, every request needs one approval and the
  default grant lifetime, exactly as before.

## [0.18.0] - 2026-09-11

### Added

- **Admin RBAC — permission-based, with two narrow roles beside full admin.** The
  control plane is now gated per-permission (`requests.read`, `requests.decide`,
  `history.read`, `agents.read`, `agents.manage`, `profiles.manage`,
  `enrollment.manage`); roles are just bundles of those. Two narrow roles let you
  grant less than full admin:
  - `ApproverEmails` → **Approver** — read/approve/deny access requests + read history.
  - `AgentAdminEmails` → **AgentAdmin** — manage agents, profiles, enrollment and
    reconciliation.

  `AdminEmails`/`AdminDomains` are unchanged and mean **full admin** (every
  permission) — existing deployments keep working exactly as before. Membership is
  additive: an address on several lists gets the union of their permissions.

### Notes

- Every admin endpoint enforces a permission (a denied page GET redirects to the
  dashboard, a denied mutation is 403); the nav only shows sections you can use, but
  that is UX — the endpoint checks are the boundary. Effective permissions are
  **resolved from the current config on each request**, not frozen into the session,
  so removing an address from an allowlist revokes access at once. A policy/config
  role will be added when a standalone policy surface exists. Non-breaking.

## [0.17.2] - 2026-09-11

### Added

- **Brand mark in the interfaces.** The kalitka logo (the cyan tile with the white
  glyph) now appears as the favicon on every page and as the mark beside the wordmark
  in the visitor pages, the admin top bar, and the admin login card. It is inlined as
  a 64×64 PNG data-URI (`Brand.cs`), so the pages stay self-contained — no asset
  request, nothing extra to fail. The visitor accent is aligned to the brand cyan
  (`#11dbea`).

## [0.17.1] - 2026-09-11

### Fixed

- **Admin login loop.** The admin session cookie was `SameSite=Strict`, but the
  console is entered through the Google OIDC callback — a cross-site redirect chain.
  The browser withheld the just-set cookie on the redirect to `/admin/dashboard`, the
  guard saw nothing, and bounced back to the login page forever. It is now
  `SameSite=Lax` (state-changing POSTs remain CSRF-protected, so this does not weaken
  the plane). Regression-tested end to end against a stubbed identity.
- **`SetSessionMinutes` overwrote the whole settings blob** instead of read-modify-
  write — latent data loss once a second setting exists. Now merges.
- **Store schema upgrades.** The agent stores add `tags`/`provenance` columns
  idempotently (`ALTER TABLE`), so a database created by 0.14/0.15 no longer breaks
  every read after an upgrade (`CREATE TABLE IF NOT EXISTS` never adds columns).

### Added

- **Localized visitor pages (English, German, Russian).** The pages a visitor or
  e-mail approver sees are rendered in the browser's language (negotiated from
  `Accept-Language`, English fallback); the admin console stays English. New
  `Localization.cs`.
- **kalitka.app visual identity.** Visitor pages restyled to the brand (near-black,
  one cyan accent, square mark + wordmark, localized tagline). Every page carries a
  quiet source-offer footer, satisfying the AGPL §13 network-use obligation.

### Security

- **Agent grant issuance now checks the poller's scope** (`GrantService.IssueGrant`):
  an approved request's grant is no longer handed to an agent not scoped to redeem
  that resource, and the `grant.created` event is attributed correctly. (Redeem
  already re-checked; this closes the least-privilege gap on the issuing side.)
- **OAuth login is bound to the browser that started it.** Both the admin and visitor
  flows set a short-lived nonce cookie at login start and require it to match the
  nonce inside the signed OAuth state at the callback — defeating login-CSRF /
  forced-login.
- **Admin CSRF token now expires** with the session instead of being valid until
  `HmacSecret` rotation.
- **Constant-time comparison** for the Telegram-webhook, internal-switch, and legacy
  global-agent secrets (they used `==`; registered-agent secrets and signed tokens
  already used fixed-time compares).

### Docs

- `SECURITY.md` corrected: per-host session scope is the default (since 0.16), not
  unshipped. Added `THIRD-PARTY-NOTICES` (MaxMind Apache-2.0 attribution, etc.).

## [0.17.0] - 2026-09-11

### Added

- **Profile reconciliation — deliberate, audited apply of profile changes to existing
  agents.** 0.16 snapshots a profile onto an agent at create/enroll and then never
  touches it; 0.17 adds the missing half without turning profiles into a policy
  engine. Each profile-managed agent records the profile revision it was last synced
  to (`AppliedProfileRevision`) and the hostname its templates were expanded with.
  Reconciliation is a **three-way merge** anchored to that revision: only what the
  *profile* changed between then and now is applied; anything an admin changed by hand
  on the agent (added or removed) is preserved. The agent's own snapshot stays the
  source of truth.
- **Expansion always needs confirmation.** A change that *grants* the agent a new
  capability or resource never applies silently — it requires explicit confirmation
  (upholding the 0.16 no-silent-expansion invariant). Removals and tag changes apply
  directly; a bulk "apply all safe changes" covers those in one step.
- **Reconcile console at `/admin/reconcile`.** Previews the pending diff per agent
  (`+added` / `-removed` capabilities, resources and tags, with the revision move),
  flags expansions, and applies per agent or in bulk. The agent detail page shows the
  same drift panel. Every apply writes an `agent.profile_applied` audit event whose
  note carries the **diff**, not just the fact.

### Fixed

- **File config backend dropped unknown keys.** On the JSON-file backend (the
  single-instance default), only `lists`/`enforced`/`settings` were persisted, so
  agent profiles introduced in 0.16 silently vanished; any other key now maps to a
  `<key>.json` file in the same data directory. SQLite/Postgres were unaffected.

### Notes

- Additive and non-breaking. Profile provenance round-trips in SQLite and Postgres
  (new `provenance` column); agents not created from a profile are simply unmanaged
  and never appear in reconcile. Tested: drift detection, the override-preserving
  delta apply (added and removed), expansion-needs-confirmation, reductions applying
  without it, deleted-profile safety, the audited diff, and the admin apply flow end
  to end.

## [0.16.0] - 2026-09-11

### Added

- **Agent profiles — templates + classification, not a policy system.** A profile
  carries capabilities, resource *templates* (`ssh:{hostname}`, `sudo:{hostname}`)
  and default tags. Creating or enrolling an agent **from** a profile expands the
  templates against a concrete hostname and **snapshots** the result onto the agent —
  whose own capabilities/resources/tags stay the source of truth. Editing a profile
  afterwards **never silently changes** an already-created agent (an explicit,
  audited "apply to existing agents" is future work). Profiles are managed at
  `/admin/profiles` and CRUD is audited
  (`agent.profile_created` / `updated` / `deleted`).
- **Tags / groups.** Agents carry `key:value` tags (from a profile or the create
  form) for inventory and search; the `/admin/agents` list can be filtered by tag.
  Metadata for now — policy selection ("all `env:prod` need two approvers") comes
  later.
- **Operation capabilities.** Capabilities may be operations (`access.request`,
  `grant.redeem`, `session.end`), as profiles express them, in addition to the
  pre-0.16 resource-scheme form (`ssh`). Either authorises a matching operation, so
  agents created before 0.16 keep working.

### Notes

- Additive and non-breaking: the legacy global `AgentSecret` and scheme-capability
  agents are unchanged. Tags round-trip in SQLite and Postgres; profiles live in the
  shared config store (files / SQLite / Postgres). Tested: template expansion, the
  profile snapshot, the **no-silent-expansion** invariant, profile-CRUD audit, and
  operation-plus-scheme capability authorization.

## [0.15.0] - 2026-09-11

### Added

- **Versioned agent protocol `/agent/v1/*`.** The agent API has a canonical, RESTful
  namespace: `POST /agent/v1/requests`, `GET /agent/v1/requests/{id}`,
  `POST /agent/v1/grants/redeem`, `POST /agent/v1/sessions/end`,
  `POST /agent/v1/enroll`, `POST /agent/v1/heartbeat`. The unprefixed `/agent/*`
  paths remain as **deprecated aliases** (same handlers) so already-deployed PAM
  hooks keep working; legacy calls now carry a `Deprecation` response header. The
  reference PAM hooks (`deploy/ssh/`) use the v1 paths.

### Notes

- Redeeming a grant still starts the session atomically (0.11), so there is no
  separate `sessions/start` step — `grants/redeem` returns the `session_id`.
- Still to come on this line: dropping the global `AgentSecret` after the migration
  window, and agent profiles / tags / admin RBAC / public-key (mTLS) credentials.

## [0.14.0] - 2026-09-11

### Added

- **Agent registry — every agent is an identifiable, revocable, resource-scoped
  principal.** `/agent/*` callers authenticate as a registered `Agent`
  (`X-Kalitka-Agent-Id` + `X-Kalitka-Agent-Secret`) instead of a single shared
  secret. An agent has a stable id, a hashed secret (PBKDF2), a status
  (pending/active/disabled/revoked), a capability list and an allowed-resource list.
  Authorization requires **both** the capability and a covering resource — a valid
  credential is never a licence for a resource the agent isn't scoped to. `agent_id`
  is propagated end to end (`actor=agent:<id>` on access.requested / grant.* /
  session.*; the session records the canonical id, the self-reported hostname is only
  metadata).
  - `IAgentStore` (in-memory / SQLite / Postgres, same backend precedence), separate
    from the request store; a revoked agent is revoked across every node.
- **Enrollment.** One-time, single-use, expiring enrollment tokens (reusing
  `OneTimeTokenService` + `IReplayStore`): an admin mints a token for a profile
  (a *pending* agent), the machine self-enrols at `POST /agent/enroll` with its own
  generated secret, and the agent goes active. `POST /agent/heartbeat` (and any
  authenticated call) updates `last_seen`.
- **Control plane `/admin/agents`.** List, detail, create (secret shown **once**),
  generate enrollment token, disable / enable / rotate (new secret shown once) /
  revoke — CSRF-protected. Lifecycle emits `agent.enrollment_created` / `enrolled` /
  `disabled` / `enabled` / `credential_rotated` / `revoked`.
- **Migration.** The legacy global `AgentSecret` / `AgentResources` still work for
  one window (now **deprecated**); registry creds take precedence. The reference PAM
  hooks accept either (`KALITKA_AGENT_ID` + secret, or the legacy secret).

### Notes

- Tested to the mandatory isolation set: cross-agent credential rejected,
  disabled/revoked rejected, unauthorized resource/capability denied, enrollment
  token single-use and expiry, rotation invalidates the old secret, two nodes see a
  revocation, `agent_id` survives request → grant → session → audit, legacy mode
  still works. Postgres agent store exercised in CI.
- Not yet (a later slice): the `/agent/v1/*` protocol namespace and, after the
  migration window, removing the global `AgentSecret`.

## [0.13.0] - 2026-09-11

### Added

- **Postgres backend — true multi-node.** Set `PostgresConnectionString` and the
  durable stores — pending requests, replay, sessions **and** audit — all live in
  one Postgres database, so several kalitka instances share the same state and their
  atomic transitions hold across the cluster (state and audit commit in one
  transaction, since they share the connection). Same seams and guarantees as the
  SQLite backend, in Postgres SQL (`PgRequestStore` / `PgReplayStore` /
  `PgSessionStore` / `PgAuditStore` / `PgAtomicWork`). New opt-in dependency
  `Npgsql`, loaded only on the Postgres path.
- **Shared config across instances.** The block/allow lists, armed hosts and
  runtime settings moved behind an `IConfigStore` (files / SQLite / Postgres), so
  config is shared too — not just the live state. Writes are an atomic
  read-modify-write (SQLite `IMMEDIATE` transaction; Postgres transaction advisory
  lock), so two instances editing a list at once don't lose each other's entries;
  reads use a short in-memory cache, so a change propagates cluster-wide within a
  bounded lag (~10s) rather than instantly. The file backend keeps the existing
  `lists.json` / `enforced.json` / `settings.json` for single-instance deployments.
- Backend precedence throughout: `PostgresConnectionString` > `StateDbPath` /
  `AuditDbPath` (SQLite) > in-memory / files.

### Notes

- With Postgres, kalitka is genuinely multi-node: live state, audit **and** config
  are shared, and the atomic guarantees hold across instances. Tested against real
  Postgres in CI (a service container): resolve / redeem / close once-only,
  concurrency (one winner), atomic rollback of a redeem's four effects, config RMW
  with no lost updates, and a wired end-to-end run on Postgres.
- Config propagation is eventually-consistent within the cache TTL (~10s) — fine
  for allow/block lists and arming; not an instantaneous cluster broadcast.

## [0.12.0] - 2026-09-11

### Added

- **Pluggable geolocation with an on-box MaxMind option (privacy).** Geo is now a
  seam, `IGeoLookup`, with three providers: a local MaxMind GeoLite2/GeoIP2 database
  (`MaxMindGeoLookup`, set `GeoDbPath`) so **no visitor IP leaves the machine** —
  the GDPR-friendly answer; the existing HTTP lookup (`HttpGeoLookup`, `GeoUrl`);
  and none (`NullGeoLookup`). DI picks MaxMind when `GeoDbPath` is set (and the file
  exists — otherwise it falls back rather than downing the gate), else HTTP when
  `GeoUrl` is set, else off. Geolocation stays notification-only and never blocks or
  fails a request. New setting `GeoDbPath`; new opt-in dependency `MaxMind.GeoIP2`,
  loaded only on the MaxMind path.

### Changed

- **License: MIT → AGPL-3.0-or-later.** kalitka is now licensed under the GNU Affero
  GPL v3 (see [LICENSE](LICENSE)). This closes the "run a modified copy as a network
  service without giving anything back" gap and is the basis for an optional separate
  **commercial license**. Contributions are made under a Contributor License
  Agreement ([CLA.md](CLA.md), [CONTRIBUTING.md](CONTRIBUTING.md)), which is what
  keeps dual-licensing possible. **Releases up to and including 0.11.0 remain
  available under the MIT License** — the change is not retroactive.

## [0.11.0] - 2026-09-10

### Added

- **Transactional state + audit — audit integrity, not just durable state.** After
  0.10.0 state and audit were both durable but still two steps: a state transition
  could commit while its audit append failed, leaving access without its history.
  Now, when `StateDbPath` and `AuditDbPath` point at the **same** SQLite file, each
  state change and its audit event commit in **one transaction** — a failure of any
  part rolls back the whole. The pairs made atomic:
  - `resolve request + access.approved/denied` (in `ApprovalEngine.Decide`);
  - `consume grant + start session + grant.redeemed + session.started` — all four
    in one commit, so there is never a consumed grant without its session and both
    events (in `GrantService.Redeem`);
  - `close session + session.ended` (in `GrantService.EndSession`); a repeat close
    matches no open row and is a harmless no-op, not a second transition.
- **`IAtomicWork` / `IWorkScope` unit-of-work seam (B-lite).** The scope exposes
  only storage primitives (`TryResolve`, `TryConsumeReplay`, `StartSession`,
  `EndSession`, `AppendAudit`) — no business operations — so sequencing stays in
  the engine / grant service and a future provider carries no domain logic. The
  durable stores gained transaction-bound cores (`ResolveCore`, `ConsumeCore`,
  `StartCore`/`EndCore`, `AppendCore`); `SqliteAtomicWork` runs a set in one local
  transaction. Registered only when state and audit share one SQLite file.

### Notes

- **No new dependency, migration story unchanged.** SQLite does transactions, so
  this needs no Postgres and no config beyond pointing both paths at one file.
  In-memory and separate-file setups keep the sequential best-effort append —
  honest, because in-memory loses state and audit together on a crash (no gap) and
  separate files cannot span a transaction. True multi-*node* (Postgres) is the
  next step (0.12) and inherits this transaction design.
- Tested to the failure paths, not just the happy one: an append failure inside a
  redeem rolls back the consume, the session and both events; an append failure on
  close leaves the session open.

## [0.10.0] - 2026-09-10

### Added

- **Durable, shared live state (SQLite) — the single-node multi-instance step.**
  A new `StateDbPath` keeps the live state that used to be in-memory-only —
  pending requests, consumed one-time tokens (replay), and sessions — in one
  SQLite file. Set it and that state survives a restart, and the atomic
  transitions the engine and grant flow depend on hold across **every process
  pointed at the same file**, not just within one. Empty keeps all three in
  memory (today's behaviour: single instance, lost on restart).
  - `SqliteRequestStore` / `SqliteReplayStore` / `SqliteSessionStore`, each
    behind its existing seam (`IRequestStore` / `IReplayStore` / `ISessionStore`).
    The load-bearing operations are single conditional statements — resolve-once
    and grant-once are a guarded `UPDATE`, redeem-once is
    `INSERT … ON CONFLICT DO NOTHING`, close-once is a guarded `UPDATE` — so the
    database enforces the same "exactly one caller wins" the in-memory lock did.
  - The DI factories pick SQLite when `StateDbPath` is set and the in-memory
    stores otherwise, mirroring how `AuditDbPath` already selected the audit store.

### Changed

- **`IRequestStore.TrySetGrant` — the grant is issued atomically in the store.**
  `EnsureGrant` used to read a request and mutate it in place, which only works
  when `Get` returns the shared object. With a durable backend `Get` returns a
  copy, so the issue-once step moved into the store (a guarded `UPDATE`), the same
  shape as `TryResolve`. Two status polls landing on two instances can no longer
  mint two redeemable grants for one approval.

### Notes

- **What SQLite here does and does not buy.** It is the single-*node* step:
  durable across restarts and safe for several processes sharing one file. True
  multi-*node* is the same seam with a Postgres backend — the transitions are
  already conditional SQL, so that is a mechanical swap. Still per-instance, and
  deliberately out of scope here: the enforced-hosts / settings / lists JSON and
  the in-memory rate-limit and mute windows.
- The 0.8.1 state-then-append audit caveat is unchanged: a durable state store
  makes the *state* survive, but state and its audit event are still two steps.

## [0.9.0] - 2026-09-10

### Added

- **An approval is no longer an entry — SSH access is a one-time grant with a
  session.** When an `ssh:` request is approved, kalitka issues a short-lived,
  single-use *grant*. The PAM agent redeems it exactly once to start a session
  and reports when the session ends, so the audit log finally distinguishes "a
  human said yes" from "this login actually happened". A second approved login
  needs a second grant; a replayed grant is refused.
- **`grant.*` / `session.*` audit events.** `grant.created` (on approval),
  `grant.redeemed` and `session.started` (on redemption), `session.ended` (on
  logout) — each resource-scoped to the SSH host and carrying `grant_id` /
  `session_id`, so a session can be followed end to end. This retires the 0.8.1
  caveat that `session.*` were reserved and a PAM `exit 0` was all the log knew.
- **`ISessionStore` / `InMemorySessionStore`.** Records a live session
  (`session_id`, `grant_id`, `request_id`, subject, resource, `agent_id`,
  started/ended, outcome); atomic close so a session ends exactly once. The seam
  is where a durable, multi-instance session backend plugs in next.
- **Agent endpoints for the lifecycle.** `GET /agent/status` now returns the
  one-time `grant` alongside the state; `POST /agent/redeem` consumes it once and
  returns a `session_id` (`409` on replay); `POST /agent/session/end` closes it.
- **Session-close PAM hook** ([`deploy/ssh/kalitka-session-end.sh`](deploy/ssh/kalitka-session-end.sh)).
  Wired into PAM's `session` stack (`optional`, so a logout is never wedged), it
  reports the session end. The approve hook redeems the grant on entry and hands
  the session id to the close hook through `/run/kalitka/session-<user>`.

### Changed

- The single-use guarantee reuses the `IReplayStore` seam introduced for
  one-time e-mail tokens: redeeming a grant is the one atomic "consume the jti"
  step that turns a signed token into a capability.

### Notes

- Correlating exactly one session id per PAM close across concurrent logins by
  the same user is best-effort in this slice (one file per user under `/run`);
  robust per-session correlation is deeper-SSH work. An allow-list skip grants
  entry directly and starts no session — there is nothing to redeem.
- The state-then-append audit caveat from 0.8.1 still stands: durable,
  multi-instance stores (request/replay/session) are the next step, and only
  then is "compliance-grade immutable audit" a claim worth making.

## [0.8.1] - 2026-09-10

### Security

- **Access lists are resource-scoped.** Every allow/block entry now carries a
  resource (`web:*`, `web:<host>`, `ssh:*`, `ssh:<host>`), and a decision made for
  one resource no longer leaks to another — remembering the name `root` for an SSH
  host cannot wave in a web visitor named `root`, and a web allow-list never
  becomes an SSH auto-approval. `input` is now `subject` (types: ip | subject |
  country). **Legacy entries without a resource are read as `web:*`**, preserving
  web behaviour without turning old lists into PAM policy. Buttons on a request
  scope to that request's resource; manual `/allow` `/block` default to `web:*`.
- **The agent secret is separate from the internal secret.** `/agent/*` (SSH
  hosts) is guarded by `AgentSecret` / `X-Kalitka-Agent`; `/internal/*`
  (administrative) keeps `InternalSecret` / `X-Kalitka-Internal`. A compromised
  SSH host can no longer reach the administrative endpoints.
- **Agent resource binding (groundwork).** `AgentResources` optionally restricts
  which resources an agent may raise (e.g. `ssh:prod-01`), so a shared secret
  cannot claim `ssh:domain-controller-01`. Empty = any; a per-agent credential
  registry comes later.
- **SSH hook hardening.** `/etc/kalitka-approve.conf` must be root:root, and curl
  has bounded `--connect-timeout`/`--max-time` so a hung request cannot hold an
  SSH login past the poll window.

### Notes

- The audit records the state transition first, then appends the event, so a
  disk/IO failure could leave a decision without its durable event. Fine for now;
  "compliance-grade immutable audit" would need a transactional/outbox store —
  not claimed yet. And `session.started`/`session.ended` are still reserved:
  a PAM `exit 0` means "kalitka allowed it", not that the SSH session ran.

## [0.8.0] - 2026-09-10

### Added

- **SSH approval gate (experimental) — the first PAM axis.** A small `pam_exec`
  hook ([`deploy/ssh/`](deploy/ssh/)) raises an access request for `ssh:<host>`
  after sshd authenticates, then blocks until a human approves through any
  channel; on approval the session continues. A thin vertical slice — no
  certificates, credential brokering or proxy — that proves the mechanic end to
  end and records it in the audit log against the `ssh:` resource. It is a second
  factor, never the only one, and fail-closed (keep a break-glass path).
- Internal `/agent/request` and `/agent/status` endpoints (guarded by
  `X-Kalitka-Internal`) and a resource-centric `RaiseAction`, so a non-HTTP
  frontend reuses the same judging, channels and audit as a visitor request.

### Changed

- A pending request now carries a `Resource` (`web:<host>`, `ssh:<host>`), and
  the audit records that — the event envelope is genuinely resource-centric.

## [0.7.0] - 2026-09-10

### Added

- **Durable audit log.** `/admin/history` is now a queryable audit log rather than
  a peek at memory: resource-centric events with a fixed envelope (`id`,
  `timestamp`, `event_type`, `actor`, `subject`, `resource`, `request_id`,
  `grant_id`, `channel`, `metadata`), filterable by actor / resource / event and
  paged. Event types are `access.requested|approved|denied`, `admin.login`,
  `admin.login_denied` now, with `grant.*` / `session.*` reserved for the PAM
  axes so they fit without a schema change.
- **`IAuditStore` seam.** In-memory by default (a bounded ring); set `AuditDbPath`
  for a **SQLite** store that survives restarts — the single, first-party runtime
  dependency (`Microsoft.Data.Sqlite`), append-only, no ORM. New setting:
  `AuditDbPath`.

### Changed

- `GateService.Decide` is async now (the audit append is awaited, not
  fire-and-forget). No external behaviour change.

## [0.6.1] - 2026-09-10

### Security

- **Admin sessions are re-checked against the allowlist on every request.**
  Removing someone from `AdminEmails`/`AdminDomains` now revokes their session
  immediately, instead of leaving a valid cookie until it expires.
- **One central guard for the `/admin` protected routes** (a route-group filter)
  rather than each endpoint checking for itself — a new admin endpoint cannot be
  added without the auth check.

### Changed

- The audit actor for an admin is now the stable Google `sub` (`google:<sub>`),
  not the e-mail; the e-mail remains the display/audit identity (logged at login).

## [0.6.0] - 2026-09-10

### Added

- **E-mail approval channel.** With SMTP configured, a new request also mails the
  operators (`AdminEmails`) an approve and a deny link — a second channel beside
  Telegram, over the same engine. Empty `SmtpHost` disables it.
- **One-time capabilities.** The links are signed, single-use, short-lived tokens
  (`OneTimeMinutes`, default 15). A token points at a request and an action, not
  the decision's parameters; the action is resolved on the server at redemption.
  Opening a link (`GET /action`) only shows a confirmation page and consumes
  nothing — safe against mail-scanner pre-fetch; the `POST` consumes the token
  (`IReplayStore`) once and resolves the request. New settings: `Smtp*`,
  `OneTimeMinutes`.

### Internal

- `TokenSigner` gains the `one-time:v1` key; `OneTimeTokenService`, `IReplayStore`
  (`InMemoryReplayStore`), `IEmailSender` (`SmtpEmailSender`) and `EmailNotifier`
  (a second `INotifier`) are the pieces. `GateService` now announces to every
  registered `INotifier`, not Telegram alone.

## [0.5.1] - 2026-09-10

### Fixed

- **A request now resolves exactly once, atomically.** With two channels
  (Telegram and the web plane) an Approve and a Deny could in principle race and
  both take effect. The transition is now a single guarded step, so only the
  first wins and the list side-effect happens at most once.

### Internal

- Pending requests live behind a new `IRequestStore` seam (`InMemoryRequestStore`
  today) whose `TryResolve` carries that atomic guarantee. It is the place a
  durable/shared backend plugs in later for multi-instance — and the same shape
  the one-time-token replay store will take.

## [0.5.0] - 2026-09-10

### Added

- **Web control plane at `/admin`.** A second, authenticated channel over the
  same engine — dashboard, the waiting requests, one-request approve/deny/
  remember/block, and recent history — server-rendered, no build step. Telegram
  stays an independent channel; the console is additive.
  - **Admin login is Google OIDC + an explicit allowlist**, separate from who may
    enter guarded hosts: `AdminEmails` (exact match, primary) and `AdminDomains`
    (a broader, explicitly-enabled mode). With neither set the web login is
    disabled (fail-closed). Only a verified e-mail gets in; the stable Google
    `sub` keys the session. Register `https://<host>/admin/oauth2/callback` with
    Google.
  - The admin session is a separate signed cookie on its own derived key
    (`admin:v1`, `SameSite=Strict`, `Path=/admin`, short absolute lifetime), so
    web access to a guarded app grants nothing on `/admin`. State-changing actions
    are POSTs with a CSRF token.

### Changed

- Audit `actor` is now a typed string (`telegram:<id>`, `google:<email>`) instead
  of a bare Telegram id, so approvals stay distinguishable per channel.

### Internal

- New `TokenSigner` (HKDF-derived per-purpose keys) backs the admin session and
  its CSRF/state tokens; the visitor session is unchanged for now (no logout).
  `ApprovalEngine` gained a read-only `PendingSnapshot()` for the console.

## [0.4.0] - 2026-09-10

### Changed

- **Google sign-in is now per-host by default (`SessionScope=Application`).**
  It used to grant a session for *every* guarded host under the cookie domain;
  now it grants only the host it signed in for, exactly like a manual approval. A
  sibling host asks again — a single click, since Google remembers the account.
  **Breaking** if you relied on one sign-in opening all siblings: set
  `SessionScope=Domain` to restore that. Manual approvals are unchanged (always
  per-host).

### Added

- `SessionScope` option — `Application` (default) or `Domain`.

### Internal

- Extracted `SessionService` (the signed session and OAuth-state tokens) out of
  `ApprovalEngine`, with direct crypto tests, so the security-critical token code
  is small and testable on its own. No behaviour change.

## [0.3.0] - 2026-09-10

### Added

- **More reverse proxies.** A new status-only `/authz` endpoint for nginx
  `auth_request` — it answers `200` or `401` (never a redirect), and nginx does
  the redirect to the gate itself with `error_page`. Example configs for nginx
  and Envoy `ext_authz` join the existing Traefik one. Traefik, Caddy and Envoy
  use `/auth` (the `302`); nginx uses `/authz`. Both endpoints share one verdict,
  and both accept a trailing path prefix so Envoy's `path_prefix` works. A new
  [Reverse proxies](README.md#reverse-proxies) section explains which endpoint
  each proxy uses. Examples:
  [`deploy/nginx/kalitka.conf`](deploy/nginx/kalitka.conf),
  [`deploy/envoy/kalitka.yaml`](deploy/envoy/kalitka.yaml).

### Changed

- Internal refactor: `GateService` split into `ApprovalEngine` (the decision
  core, free of HTTP and Telegram), `INotifier`/`TelegramNotifier` (the Telegram
  face), and a thin `GateService` facade. No behaviour change — it makes room for
  more proxies and other notifiers without reopening the core.

## [0.2.1] - 2026-09-09

### Added

- **Test suite** (25 tests) covering the security-critical paths: forged and
  proxied `X-Forwarded-For`, cookie tampering / expiry / secret rotation, the
  `/auth` decision for armed, unarmed and bypass cases, the 401-vs-redirect
  split for sub-resources, wrong webhook secret, non-admin callback, and
  callback replay against resolved and expired requests. Time is injected via
  `TimeProvider`, so the time-based tests are deterministic.

### Changed

- `TelegramClient` now sits behind `ITelegramClient`, and `GateService` takes a
  `TimeProvider` — both to make the above testable, no behaviour change.

### Fixed

- **Sub-resources without a session now get `401`, not a redirect.** A `302` to
  the gate's HTML page is only meaningful to a top-level navigation. A WebSocket
  handshake cannot follow it, an XHR/fetch reads the HTML as its payload, and a
  single-page app behind the gate hung on a blank screen. The request kind is
  read from the browser's Fetch Metadata (`Sec-Fetch-Mode`; `Accept` as a
  fallback for older clients): only a real navigation is redirected, everything
  else fails cleanly with `401`. This is the "Single-page apps and a redirect
  gate" caveat, turned from a caveat into correct behaviour.
- `appsettings.json` carried JSON "comment" keys under `Logging:LogLevel` whose
  values were parsed as log levels and threw on first use. Removed; the tests
  caught it.

### Dependencies

- Adopted the safe GitHub Actions bumps (checkout, setup-dotnet, login,
  metadata, build-push). Major bumps of the .NET base images are held back and
  ignored by Dependabot — that is a runtime baseline change, done deliberately.

## [0.2.0] - 2026-09-09

First public release. The product is already whole — Telegram approval, allow
and block lists, optional Google sign-in, per-host arming, mute, session
control — so it ships now rather than waiting for thirty more features.

Not yet here: an automated test suite (tracked in the issues) and per-host
isolation of the Google session (see Known limitations).

### Added

- **Trusted proxies.** `TrustedProxies` (CIDR list) decides whether forwarded
  headers are believed at all. Requests that did not arrive from one of these
  are judged on the address the connection actually came from.
- **Rate limiting.** A sliding window per address (`MaxRequestsPerIp`,
  `RateWindowMinutes`) and a ceiling on requests waiting for an answer
  (`MaxPending`). Over the limit the door stays silent — the same answer a
  blocked caller gets, so there is nothing to learn from it.
- **Audit log.** One structured line per decision: request id, host, client
  address, identity, admin and reason. Secrets, tokens and cookie values are
  never logged.
- **`/allow` and `/block`.** Fill either list before anyone rings, instead of
  only being able to react to a request.

### Changed

- **`X-Forwarded-For` is read from the right**, past known proxies, instead of
  taking the leftmost entry. A proxy only ever appends on the right; everything
  to the left is whatever the caller wrote. Reading it the obvious way let a
  visitor choose their own address — and with it their own place on the allow
  list.
- **Redirect targets must be a currently guarded host**, not merely a name under
  the same domain. A forged `Host` header could otherwise steer visitors to a
  name that was never guarded.
- **Telegram callbacks expire.** A decision was already terminal after the first
  press; now the request also has to still be within its lifetime, so an old
  button cannot resurrect one.

### Security

- Startup refuses `BypassNetworks` without `TrustedProxies`. Behind a proxy every
  visitor would otherwise appear to come from the proxy, and a bypass range
  containing that address would wave everyone through while the configuration
  looked entirely correct.

### Known limitations

- A Google sign-in grants a session for every guarded host under the cookie
  domain. Manual approvals are already per-host. Per-host isolation of the
  Google session is tracked as a feature (one-time hand-off token) and is not in
  this release.

### Upgrading

Set `TrustedProxies` to the range your reverse proxy connects from. For Docker:

```
docker network inspect proxy -f '{{(index .IPAM.Config 0).Subnet}}'
```
