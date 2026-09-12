# Database JIT access — SQL Server (reference connector)

Give someone time-boxed SQL Server access that a human approves in kalitka — the
same door, from a phone or the web console — and that **removes itself** when the
grant ends. This is the first database axis and the reference for others.

```
kalitka-db-agent access --database orders --profile sql-readonly --user sergej
   → raises an access request for db:sql01/orders (profile sql-readonly) in kalitka
   → you approve on Telegram / the web console / an e-mail link
   → the agent redeems a one-time grant → a session starts
   → the agent provisions SQL access for the profile and prints the credential
   → you use it; on Ctrl-C / Enter / TTL the agent DROPs it and closes the session
   → the request, its approval and the whole session are in /admin/history
```

## The architecture (locked)

```
kalitka Core  --signed grant-->  kalitka-db-agent  -->  SQL Server
 (control plane)                  (local connector)
```

**Core is the control plane and never holds a DB-admin credential.** It decides who
/ to what / with which profile / under what conditions, and records it. A grant
carries only a server-side **profile** — `sql-readonly`, `sql-writer`, `sql-dba`,
`sql-order-correction` — never raw SQL. The connector, running next to SQL Server,
is the only thing that knows what a profile *means* and the only thing that touches
the database. *kalitka brokers authority, not database credentials.*

The protocol half (raise / poll / redeem / report) is delegated to `kalitka-agent`,
so every gate call is **Ed25519-signed** with the same credential model as the SSH
hooks; this connector only adds the SQL provisioning on top.

## Profiles → roles

A profile maps, **locally**, to a predefined SQL role (`DB_PROFILE_MAP`):

| profile                | role (default)             | grants                          |
| ---------------------- | -------------------------- | ------------------------------- |
| `sql-readonly`         | `kalitka_readonly`         | `SELECT`                        |
| `sql-writer`           | `kalitka_writer`           | `SELECT, INSERT, UPDATE, DELETE`|
| `sql-order-correction` | `kalitka_order_correction` | `EXECUTE` on one vetted proc    |
| `sql-dba`              | *(unmapped — opt-in)*      | see below                       |

These are **user-defined** roles, not the built-in `db_datareader`/`db_datawriter`:
you cannot `GRANT ALTER` on a fixed role, so a least-privilege agent (one that is not
`db_owner`) cannot manage fixed-role membership. A user-defined role is `ALTER`-able by
the agent and is tighter and clearer anyway. Define your roles once with `roles.sql`,
then map profile names to them in the config.

`sql-dba` is **not mapped by default**: real `db_owner` membership cannot be handed
out by a least-privilege agent (it would have to be `db_owner` itself). Wire JIT DBA
consciously if you need it — see the note at the end of `roles.sql`.

## Provisioning modes

- **ephemeral** (default, preferred): create a JIT `LOGIN`+`USER`, add it to the
  role, and `DROP` both when the grant ends. The random password is generated on the
  agent host and returned **to you**, out of band — Core never sees it.
- **grant**: add an **existing** principal (`--login`) to the role for the session
  and remove it afterwards. Use when the person already has a SQL identity.

Either way the agent deprovisions on a **graceful** exit — Enter, Ctrl-C, the
`--ttl-min` window, or an error mid-flight all run the same teardown. An *ungraceful*
death (OOM/SIGKILL/host panic) is handled by reconcile, below.

## Crash recovery (`kalitka-db-agent reconcile`)

"Deprovisions on exit" only holds for a graceful exit. If the process or host dies
right after `CREATE LOGIN`, the SQL login physically outlives the agent while its TTL
lives only in Core. So the connector treats **durable provenance as correctness**, not
convenience, and ships a reconcile pass that revokes what a crash left behind. Run it
**at boot and on a timer** (systemd timer / cron).

Two durable records are written *before* provisioning and cleared *after* a clean
teardown, both carrying `expires_at`:

- a **local journal** (`$KALITKA_DB_STATE/journal/<session-id>`) — survives a process
  crash; and
- an **in-DB ledger** (`dbo.ProvisionedPrincipals`, its own `kalitka_agent` database) —
  survives loss of the agent host itself.

Ephemeral principals are named **`kalitka_<session-id>`**, so Kalitka-ownership and the
session are always derivable from the name alone. `reconcile` decides per principal
(**fail conservative on uncertainty, but never extend authority past a locally-known
expiry**):

| state                              | action |
| ---------------------------------- | ------ |
| known + locally expired            | DROP (`local-expiry`) — even if Core is down |
| known + locally valid              | KEEP — a Core outage is *not* a reason to drop |
| Core reachable, says revoked/closed/expired/unknown | DROP (`core-confirmed`) |
| Core unreachable + uncertain       | KEEP |
| Kalitka-owned, older than ceiling  | DROP (`orphan-max-age`) |

Core unavailability is **never on its own** grounds to revoke; a locally-known expiry
always is. The sweep **never** drops a principal without reliable Kalitka provenance (a
ledger row or the `kalitka_<session-id>` name) — it will never `DROP LOGIN some_login`
just for being old. `OrphanAbsoluteMaxAge` (default `2 × MaxGrantTtl`) is the only
unconfirmed cleanup, for a Kalitka-owned principal whose journal *and* ledger are gone;
keep it ≥ your longest grant TTL. Every revoke is audited with its reason
(`session.reconciled`), so an unconfirmed cleanup is always explainable after the fact.

## Bounded grants

The universal bounded-grant model applies: a grant ends on the *first* of its
`expires_at` (mandatory ceiling), a `--max-uses` budget being spent (only where one
operation is unambiguous — a pre-approved stored procedure — never for counting
arbitrary SQL), or an explicit revoke. Interactive (SSMS) access is session + TTL.

## Bounded grants

The universal bounded-grant model applies: a grant ends on the *first* of its
`expires_at` (mandatory ceiling), a `--max-uses` budget being spent (only where one
operation is unambiguous — a pre-approved stored procedure — never for counting
arbitrary SQL), or an explicit revoke. Interactive (SSMS) access is session + TTL.

## Install (on the SQL Server host / a host next to it)

1. `bash`, `curl`, **OpenSSL 3**, and **`sqlcmd`** must be present.
2. Install the reference client, the entrypoint, the shared lib and the engine driver:
   ```
   install -m 0755 -o root -g root kalitka-agent    /usr/local/bin/kalitka-agent
   install -m 0755 -o root -g root kalitka-db-agent /usr/local/bin/kalitka-db-agent
   install -m 0644 -o root -g root kalitka-db-lib   /usr/local/lib/kalitka/kalitka-db-lib
   install -m 0644 -o root -g root drivers/sqlserver /usr/local/lib/kalitka/drivers/sqlserver
   ```
   The entrypoint finds the lib and drivers next to itself or in `/usr/local/lib/kalitka`
   (override with `KALITKA_DB_LIB` / `KALITKA_DB_DRIVER_DIR`). `DB_ENGINE` picks the driver.
3. Enrol this host as a kalitka agent in **/admin/agents** with capability `db` and
   the resources it may provision (e.g. `db:sql01/*`), then generate + register a key
   — exactly like an SSH agent (see [../ssh/README.md](../ssh/README.md)). Its gate
   config is the shared `/etc/kalitka-approve.conf`.
4. Create the predefined roles, the agent's **least-privilege** SQL identity, and the
   ledger database with `roles.sql` (a DBA runs it once). The agent authenticates as that
   identity — on Windows a **gMSA** with integrated auth (`sqlcmd -E`), never a SQL-admin
   password. It gets just `ALTER ANY LOGIN` / `ALTER ANY USER`, `ALTER` on the specific
   roles, and read/write on its own ledger table — enough to provision and reconcile and
   no more; **not** `db_owner`/`sysadmin`.
5. Configure `/etc/kalitka/db-agent.conf` (root:root, 600) from
   `kalitka-db-agent.conf.example`: `DB_SERVER` (must match the resource's `<server>`),
   the profile→role map, `SQLCMD`, `DB_LEDGER_DB`, and the reconcile ceilings.
6. Run `kalitka-db-agent reconcile` **at boot and on a timer** (systemd timer or cron)
   so a crashed session's access never outlives its grant. It is idempotent and safe to
   run while other sessions are live.

## ⚠️ Notes

- **`DB_SERVER` must equal the `<server>` in the resource.** A request for
  `db:sql01/orders` is provisioned here only if `DB_SERVER=sql01`; the agent's
  allowed-resource scope in kalitka is the authority check on top.
- Identifiers (`--database`, `--user`, `--login`) are restricted to `A-Za-z0-9_-` and
  bracket-quoted before they reach T-SQL; a profile with no mapped role is refused and
  reported as `provision-failed`.
- This connector provisions and revokes; it is **not** a SQL proxy and does not sit in
  the query path. Per-transaction limits or query recording need a proxy or
  database-side enforcement — a later axis.

## How it maps to kalitka

- `kalitka-db-agent` calls `POST /agent/v1/requests` with the `db:<server>/<db>`
  resource and the `profile`, polls `GET /agent/v1/requests/{id}`, and on approval
  redeems the one-time `grant` at `/agent/v1/grants/redeem` — which returns the
  authoritative `profile` to provision. An access **policy** may raise the quorum for a
  profile (e.g. four-eyes for `sql-dba`) or shorten the TTL.
  redeem also returns the grant's `expires_at`, which the agent journals so it can
  revoke on a locally-known expiry even while Core is unreachable.
- After applying the role it reports `POST /agent/v1/sessions/provisioned`
  (`session.provisioned`); a provisioning failure reports `--error`, which closes the
  session `provision-failed` — access was never really granted. On teardown it
  `POST`s the session id to `/agent/v1/sessions/end`.
- `reconcile` asks `GET /agent/v1/sessions/{id}` for a session's liveness and, when it
  revokes an orphan, reports `POST /agent/v1/sessions/reconciled` with the reason
  (`core-confirmed` / `local-expiry` / `orphan-max-age`), always audited as
  `session.reconciled`.
- The full trail — `access.requested` / `access.approved`, `grant.created` /
  `grant.redeemed`, `session.started` / `session.provisioned` / `session.ended` /
  `session.reconciled` — is in `/admin/history`, against the `db:` resource.
