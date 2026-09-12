# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
