DROP TABLE IF EXISTS account_deletion_receipts;
DROP TABLE IF EXISTS account_deletion_services;
DROP TABLE IF EXISTS account_deletion_outbox;
DROP TABLE IF EXISTS auth_mail_outbox;
DROP TABLE IF EXISTS account_action_tokens;
ALTER TABLE users
  DROP COLUMN email_verified_at,
  MODIFY COLUMN status ENUM('active','locked','deleted') NOT NULL DEFAULT 'active';
