CREATE TABLE passkey_credential (
  id            INTEGER   PRIMARY KEY,
  user_id       INTEGER   NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  credential_id BLOB      NOT NULL,
  passkey       BLOB      NOT NULL,
  name          TEXT,
  prf_capable   BOOLEAN   NOT NULL DEFAULT 0,
  created_at    TIMESTAMP NOT NULL,
  last_used_at  TIMESTAMP
);
CREATE UNIQUE INDEX idx_passkey_credential_id ON passkey_credential(credential_id);
CREATE INDEX idx_passkey_user ON passkey_credential(user_id);
