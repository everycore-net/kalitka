-- kalitka-db-agent — one-time server setup (run once, by a DBA, per SQL Server).
--
-- Two things live here, and NEITHER is a kalitka runtime credential:
--   1. the predefined roles a grant profile maps to (kalitka never sends raw SQL
--      permissions — only a profile name; the mapping is local, here);
--   2. the least-privilege identity the DB-agent authenticates as, granted just
--      enough to provision and deprovision — NOT db-admin, NOT a SQL-admin password.
--
-- Adjust the database name, the per-role permissions, and the agent identity to your
-- environment. On Windows the agent identity is a gMSA (integrated auth); the
-- SQL-login variant below is for a Linux SQL Server test box.

-- === 1. Profiles -> roles ===================================================
-- IMPORTANT: map profiles to USER-DEFINED roles, not the built-in fixed roles
-- (db_datareader/db_datawriter/db_owner). You cannot GRANT ALTER on a fixed role, so
-- a non-db_owner agent cannot manage fixed-role membership — the agent would have to
-- BE db_owner, which defeats least privilege. A user-defined role can be `ALTER`ed by
-- the agent, and it is also tighter and clearer than a built-in. Define them in the
-- application database:

USE [orders];
GO
IF DATABASE_PRINCIPAL_ID(N'kalitka_readonly') IS NULL CREATE ROLE [kalitka_readonly];
IF DATABASE_PRINCIPAL_ID(N'kalitka_writer')   IS NULL CREATE ROLE [kalitka_writer];
IF DATABASE_PRINCIPAL_ID(N'kalitka_order_correction') IS NULL CREATE ROLE [kalitka_order_correction];
GO
-- Read-only: SELECT across the database.
GRANT SELECT TO [kalitka_readonly];
-- Writer: read + write, no schema/permission changes.
GRANT SELECT, INSERT, UPDATE, DELETE TO [kalitka_writer];
-- Order-correction: ONLY the vetted procedure — this is where a profile becomes as
-- narrow as you like, far tighter than any built-in.
GRANT EXECUTE ON [dbo].[usp_CorrectOrder] TO [kalitka_order_correction];
GO

-- === 2. The agent's least-privilege provisioning identity ===================
-- The agent must be able to: create/drop ephemeral logins+users, and add/remove
-- members of the roles above. It must NOT be db_owner or sysadmin.
--
-- Windows / production (preferred): a gMSA, integrated auth (`sqlcmd -E`). Create a
-- login for it instead of the SQL login below:
--   CREATE LOGIN [DOMAIN\kalitka-db-agent$] FROM WINDOWS;
--
-- Linux test box (SQL auth): a dedicated login, password kept ONLY on the agent host.
IF SUSER_ID(N'kalitka_agent') IS NULL
    CREATE LOGIN [kalitka_agent] WITH PASSWORD = N'CHANGE-ME-on-the-agent-host';
GO

-- Server-level: create/alter/drop logins (for ephemeral mode). This is the broadest
-- right the agent holds; scope the agent host accordingly.
GRANT ALTER ANY LOGIN TO [kalitka_agent];
GO

-- Database-level: create users and manage membership of exactly the kalitka roles.
USE [orders];
GO
IF DATABASE_PRINCIPAL_ID(N'kalitka_agent') IS NULL
    CREATE USER [kalitka_agent] FOR LOGIN [kalitka_agent];
GO
GRANT CONNECT       TO [kalitka_agent];
GRANT ALTER ANY USER TO [kalitka_agent];
-- ALTER on each user-defined role lets the agent ADD/DROP MEMBER without owning it.
GRANT ALTER ON ROLE::[kalitka_readonly]         TO [kalitka_agent];
GRANT ALTER ON ROLE::[kalitka_writer]           TO [kalitka_agent];
GRANT ALTER ON ROLE::[kalitka_order_correction] TO [kalitka_agent];
GO

-- === 3. The provisioning ledger (durable crash-recovery provenance) ==========
-- The agent records every principal it provisions here, WITH its expiry, before it
-- creates anything, and deletes the row after a clean teardown. This survives loss of
-- the agent host (the local journal only survives a process crash), so reconcile can
-- revoke an orphaned principal on a locally-known expiry even while Core is
-- unreachable. Its own database so it is separable and the agent's rights stay narrow.
IF DB_ID(N'kalitka_agent') IS NULL CREATE DATABASE [kalitka_agent];
GO
USE [kalitka_agent];
GO
IF OBJECT_ID(N'dbo.ProvisionedPrincipals') IS NULL
    CREATE TABLE dbo.ProvisionedPrincipals(
        session_id  NVARCHAR(64)  NOT NULL PRIMARY KEY,
        mode        NVARCHAR(16)  NOT NULL,
        db_name     NVARCHAR(128) NOT NULL,
        role_name   NVARCHAR(128) NOT NULL,
        principal   NVARCHAR(128) NOT NULL,
        created_at  BIGINT        NOT NULL,   -- unix seconds
        expires_at  BIGINT        NULL,       -- unix seconds; NULL only if the grant had none
        resource    NVARCHAR(200) NOT NULL,
        profile     NVARCHAR(64)  NOT NULL);
GO
-- The agent (see below) reads and writes only this table.
IF DATABASE_PRINCIPAL_ID(N'kalitka_agent') IS NULL
    CREATE USER [kalitka_agent] FOR LOGIN [kalitka_agent];
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.ProvisionedPrincipals TO [kalitka_agent];
-- For the orphan safety-net sweep the agent lists its own logins (server catalog):
GO
GRANT VIEW ANY DEFINITION TO [kalitka_agent];
GO

-- === 4. JIT DBA (the sql-dba profile) — opt-in, deliberately not here ========
-- Real db_owner/sysadmin membership cannot be handed out by a least-privilege agent:
-- to add someone to db_owner the agent would itself need db_owner. So sql-dba is NOT
-- wired by default. If you genuinely need JIT DBA, either (a) map sql-dba to a broad
-- user-defined role you define here and accept its scope, or (b) grant the agent the
-- necessary authority and map sql-dba:db_owner — a conscious trade-off, not the
-- default. Tighter still (production): a stored procedure WITH EXECUTE AS that performs
-- the membership change, signed by a certificate, with only EXECUTE granted to the
-- agent — so the agent holds no ALTER right at all. Left as a hardening step.
