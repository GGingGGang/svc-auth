CREATE TABLE account_operator_audit (
  id BINARY(16) NOT NULL,
  target_user_id BINARY(16) NOT NULL,
  actor VARCHAR(100) NOT NULL,
  action ENUM('suspend','unsuspend') NOT NULL,
  reason VARCHAR(500) NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY ix_operator_audit_target (target_user_id,created_at),
  CONSTRAINT fk_operator_audit_user FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;