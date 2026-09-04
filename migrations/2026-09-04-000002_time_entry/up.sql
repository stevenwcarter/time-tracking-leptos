CREATE TABLE time_entry (
  user_id    INTEGER   NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  entry_date TEXT      NOT NULL,
  body       TEXT      NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  PRIMARY KEY (user_id, entry_date)
);
CREATE INDEX idx_time_entry_user_date ON time_entry(user_id, entry_date);
