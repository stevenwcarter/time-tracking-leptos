CREATE TABLE magic_link_token (
  id         INTEGER   PRIMARY KEY,
  token_hash BLOB      NOT NULL,
  email      TEXT      NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at    TIMESTAMP,
  created_at TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX idx_magic_token_hash ON magic_link_token(token_hash);
