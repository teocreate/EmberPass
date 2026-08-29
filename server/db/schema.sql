-- Schema for the pass system. Applied automatically on start-up (idempotent).

CREATE TABLE IF NOT EXISTS users (
  id            serial PRIMARY KEY,
  email         text NOT NULL UNIQUE,
  -- Null for accounts that only ever sign in through the identity provider.
  password_hash text,
  full_name     text NOT NULL,
  role          text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'staff', 'admin')),
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  -- 'local' or 'oidc': where this account's credentials live.
  auth_source   text NOT NULL DEFAULT 'local',
  -- The provider's stable subject identifier, once the account is linked.
  oidc_sub      text UNIQUE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);

CREATE TABLE IF NOT EXISTS passes (
  id          serial PRIMARY KEY,
  user_id     integer NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  serial      text NOT NULL UNIQUE,
  tier        text NOT NULL DEFAULT 'standard',
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
  valid_from  timestamptz NOT NULL DEFAULT now(),
  valid_until timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash bytea PRIMARY KEY,
  user_id    integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  user_agent text,
  ip         text,
  -- Kept only to pass id_token_hint on RP-initiated logout.
  id_token   text
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

-- One row per scan attempt. The unique jti is what makes a pass token single-use:
-- a replayed token collides with the row written by the original scan.
CREATE TABLE IF NOT EXISTS pass_scans (
  id         bigserial PRIMARY KEY,
  jti        text UNIQUE,
  pass_id    integer REFERENCES passes(id) ON DELETE SET NULL,
  user_id    integer REFERENCES users(id) ON DELETE SET NULL,
  staff_id   integer REFERENCES users(id) ON DELETE SET NULL,
  gate       text,
  result     text NOT NULL,
  offline    boolean NOT NULL DEFAULT false,
  issued_at  timestamptz,
  scanned_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pass_scans_pass_id_idx ON pass_scans (pass_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS pass_scans_scanned_at_idx ON pass_scans (scanned_at DESC);

-- Migrations for databases created before single sign-on was added. Running them
-- unconditionally is safe; every statement is a no-op on an up-to-date schema.
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_sub text;
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_sub_key ON users (oidc_sub);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS id_token text;
