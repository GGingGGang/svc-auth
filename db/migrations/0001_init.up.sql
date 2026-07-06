-- auth schema. id = UUIDv7 (BINARY(16)). refresh token 은 Redis DB0 (opaque) — 테이블 없음.

CREATE TABLE users (
  id            BINARY(16)   NOT NULL,
  email         VARCHAR(320) NOT NULL,
  password_hash VARCHAR(255) NULL,                 -- argon2id; OIDC 전용 계정이면 NULL
  display_name  VARCHAR(100) NOT NULL,
  timezone      VARCHAR(64)  NOT NULL DEFAULT 'UTC',
  status        ENUM('active','locked','deleted') NOT NULL DEFAULT 'active',
  created_at    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- OIDC delegation (M5). 지금은 빈 테이블 OK.
CREATE TABLE oauth_identities (
  id         BINARY(16)   NOT NULL,
  user_id    BINARY(16)   NOT NULL,
  provider   VARCHAR(32)  NOT NULL,                -- google / github / ...
  subject    VARCHAR(255) NOT NULL,                -- provider 의 sub claim
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_provider_subject (provider, subject),
  CONSTRAINT fk_oauth_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
