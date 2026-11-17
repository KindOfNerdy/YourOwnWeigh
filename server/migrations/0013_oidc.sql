-- OpenID Connect login. oidc_username is the name an administrator expects the
-- identity provider to report for this account (pre-provisioning); the first
-- login with that name binds the account to the provider's stable subject.
-- sync_token_hash lets accounts without a password use the Sync API.
ALTER TABLE accounts ADD COLUMN oidc_username TEXT;
ALTER TABLE accounts ADD COLUMN sync_token_hash TEXT;
-- One row per login in progress: the state value is also kept in a short-lived
-- cookie, which ties the callback to the browser that started it.
CREATE TABLE IF NOT EXISTS oidc_logins (
  state_hash TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  verifier TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
-- Administrators may narrow their own views (dashboard, readings, Sync API) to
-- the people linked to the account; 1 means every person.
ALTER TABLE accounts ADD COLUMN see_all INTEGER NOT NULL DEFAULT 1;
