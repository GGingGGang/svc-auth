ALTER TABLE users
  DROP COLUMN login_locked_until,
  DROP COLUMN login_failure_window_started_at,
  DROP COLUMN login_failures;
