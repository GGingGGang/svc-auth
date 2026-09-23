ALTER TABLE users
  ADD COLUMN login_failures INT NOT NULL DEFAULT 0,
  ADD COLUMN login_failure_window_started_at DATETIME(3) NULL,
  ADD COLUMN login_locked_until DATETIME(3) NULL;
