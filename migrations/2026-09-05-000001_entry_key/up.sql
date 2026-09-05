ALTER TABLE user ADD COLUMN encrypted_at TIMESTAMP;

CREATE TABLE entry_key_wrap (
  id            INTEGER   PRIMARY KEY,
  user_id       INTEGER   NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  kind          TEXT      NOT NULL,
  credential_id BLOB,
  wrapped_key   BLOB      NOT NULL,
  kdf           TEXT      NOT NULL,
  wrap_alg      TEXT      NOT NULL,
  created_at    TIMESTAMP NOT NULL
);

CREATE INDEX idx_entry_key_wrap_user ON entry_key_wrap(user_id);
CREATE UNIQUE INDEX idx_entry_key_wrap_cred
  ON entry_key_wrap(user_id, credential_id) WHERE credential_id IS NOT NULL;
