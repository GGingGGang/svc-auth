ALTER TABLE users
  MODIFY COLUMN status ENUM('active','locked','deleting','deleted') NOT NULL DEFAULT 'active',
  ADD COLUMN email_verified_at TIMESTAMP(3) NULL;

UPDATE users SET email_verified_at = created_at WHERE email_verified_at IS NULL;

CREATE TABLE account_action_tokens (
  user_id BINARY(16) NOT NULL,
  purpose ENUM('verify_email','reset_password','change_email') NOT NULL,
  token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  pending_email VARCHAR(320) NULL,
  credential_version BIGINT UNSIGNED NOT NULL DEFAULT 0,
  expires_at TIMESTAMP(3) NOT NULL,
  consumed_at TIMESTAMP(3) NULL,
  PRIMARY KEY (user_id, purpose),
  UNIQUE KEY uq_action_token_hash (token_hash),
  CONSTRAINT fk_action_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE auth_mail_outbox (
  id BINARY(16) NOT NULL,
  user_id BINARY(16) NULL,
  purpose ENUM('verify_email','reset_password','change_email') NOT NULL,
  recipient VARCHAR(320) NOT NULL,
  encrypted_payload VARBINARY(4096) NOT NULL,
  attempts INT UNSIGNED NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  lease_until TIMESTAMP(3) NULL,
  sent_at TIMESTAMP(3) NULL,
  PRIMARY KEY (id),
  KEY ix_mail_pending (sent_at, next_attempt_at, lease_until),
  CONSTRAINT fk_mail_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE account_deletion_outbox (
  event_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  user_id BINARY(16) NOT NULL,
  credential_version BIGINT UNSIGNED NOT NULL,
  requested_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  published_at TIMESTAMP(3) NULL,
  lease_until TIMESTAMP(3) NULL,
  PRIMARY KEY (event_id),
  UNIQUE KEY uq_deletion_request_user (request_id, user_id),
  KEY ix_deletion_pending (published_at, requested_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE account_deletion_services (
  request_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  service VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status ENUM('pending','completed') NOT NULL DEFAULT 'pending',
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (request_id, service)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE account_deletion_receipts (
  receipt_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status ENUM('deleting','completed') NOT NULL DEFAULT 'deleting',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (receipt_hash),
  KEY ix_deletion_receipt_request (request_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
