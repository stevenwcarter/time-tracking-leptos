CREATE TABLE user (
  id            INTEGER PRIMARY KEY,
  email         TEXT      NOT NULL,
  session_epoch INTEGER   NOT NULL DEFAULT 0,
  created_at    TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX idx_user_email ON user(email);
