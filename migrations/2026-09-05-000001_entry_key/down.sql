DROP TABLE entry_key_wrap;
-- SQLite before 3.35 cannot DROP COLUMN; this migration is not reversed in
-- practice, and the column is nullable so leaving it is harmless.
