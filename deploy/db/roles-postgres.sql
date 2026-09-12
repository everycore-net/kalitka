-- kalitka-db-agent — one-time setup for PostgreSQL (run once, by a DBA, as a superuser
-- or a role with CREATEROLE/CREATEDB). The PostgreSQL analogue of roles.sql.
--
-- As on SQL Server, NEITHER of these is a kalitka runtime credential:
--   1. the group roles a grant profile maps to (kalitka never sends raw SQL — only a
--      profile name; the mapping is local, in DB_PROFILE_MAP);
--   2. the least-privilege role the DB-agent authenticates as — CREATEROLE + NOINHERIT
--      with ADMIN on the group roles, so it can create/drop ephemeral roles and manage
--      membership, but is NOT a superuser and does not itself hold the privileges.
--
-- Replace :appdb (the application database) and the agent password to taste.

-- === 1. Profiles -> group roles =============================================
-- NOLOGIN group roles carry the privileges; ephemeral principals become MEMBERS and
-- inherit them. Membership (not a direct grant on the ephemeral role) is what keeps the
-- ephemeral role free of per-database ACLs, so DROP ROLE removes it cleanly later.
CREATE ROLE kalitka_readonly NOLOGIN;
CREATE ROLE kalitka_writer   NOLOGIN;

GRANT CONNECT ON DATABASE orders TO kalitka_readonly, kalitka_writer;
\connect orders
GRANT USAGE ON SCHEMA public TO kalitka_readonly, kalitka_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO kalitka_readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kalitka_writer;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kalitka_writer;
-- Cover tables created later, too.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO kalitka_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kalitka_writer;

-- === 2. The agent's least-privilege role ====================================
-- CREATEROLE to create/drop ephemeral roles; NOINHERIT so it never silently uses the
-- privileges of the groups it administers; ADMIN OPTION on each group so (PG16+) a
-- CREATEROLE role may GRANT/REVOKE that group's membership. Not a superuser.
\connect postgres
CREATE ROLE kalitka_agent LOGIN CREATEROLE NOINHERIT PASSWORD 'CHANGE-ME-on-the-agent-host';
GRANT kalitka_readonly TO kalitka_agent WITH ADMIN OPTION;
GRANT kalitka_writer   TO kalitka_agent WITH ADMIN OPTION;

-- Action-mode profile (sql-order-correction): NO login is handed out — the agent CALLs a
-- DBA-vetted PROCEDURE once per approval and counts it as exactly one use (DB_ACTION_MAP).
-- The procedure body is the whole security boundary — keep it narrow. It must be
-- SECURITY DEFINER (PostgreSQL runs procedures as the INVOKER by default), so it runs as
-- its owner and the agent needs only EXECUTE, not table rights:
--   CREATE PROCEDURE public.usp_correct_order(OrderId int, Reason text)
--     LANGUAGE sql SECURITY DEFINER AS $$ ... $$;
\connect orders
GRANT CONNECT ON DATABASE orders TO kalitka_agent;
GRANT EXECUTE ON PROCEDURE public.usp_correct_order(int, text) TO kalitka_agent;

-- === 3. The provisioning ledger (durable crash-recovery provenance) =========
-- Its own database, owned by the agent; the agent records every principal it provisions
-- here (with expiry) before creating it, and deletes the row after a clean teardown.
CREATE DATABASE kalitka_agent OWNER kalitka_agent;
\connect kalitka_agent
CREATE TABLE kalitka_provisioned_principals(
    session_id  text   PRIMARY KEY,
    mode        text   NOT NULL,
    db_name     text   NOT NULL,
    role_name   text   NOT NULL,
    principal   text   NOT NULL,
    created_at  bigint NOT NULL,   -- unix seconds
    expires_at  bigint,            -- unix seconds; NULL only if the grant had none
    resource    text   NOT NULL,
    profile     text   NOT NULL);
ALTER TABLE kalitka_provisioned_principals OWNER TO kalitka_agent;

-- === 4. JIT DBA — opt-in, deliberately not here =============================
-- As on SQL Server, superuser-equivalent access is not wired by default. If you need
-- JIT DBA, define a broad group role and map sql-dba to it consciously; the agent must
-- have ADMIN on it. Never make the agent a superuser.
