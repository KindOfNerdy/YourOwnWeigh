-- Browser accounts. Role "admin" manages the household; role "user" only sees
-- and edits the people linked to the account in account_users.
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user')),
  disabled INTEGER NOT NULL DEFAULT 0,
  oidc_issuer TEXT,
  oidc_subject TEXT,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_oidc ON accounts(oidc_issuer, oidc_subject)
  WHERE oidc_subject IS NOT NULL;
CREATE TABLE IF NOT EXISTS account_users (
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (account_id, user_id)
);
CREATE INDEX IF NOT EXISTS account_users_user ON account_users(user_id);
ALTER TABLE admin_sessions ADD COLUMN account_id INTEGER;
-- Existing installations: the shared admin password becomes the account
-- "admin" (same hash, so the current password keeps working). Browser sessions
-- from before the upgrade carry no account and sign in again once.
INSERT OR IGNORE INTO accounts(username, password_hash, role, created_at)
  SELECT 'admin', value, 'admin', CAST(strftime('%s','now') AS INTEGER)
  FROM settings WHERE key='admin_password';
DELETE FROM settings WHERE key='admin_password' AND EXISTS (SELECT 1 FROM accounts WHERE username='admin');
