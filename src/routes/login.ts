import argon2 from "argon2";
import type { FastifyInstance } from "fastify";
import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";
import { UUID } from "uuidv7";

import type { SigningKey } from "../keys.js";
import {
  checkLoginRateLimit,
  loadLoginSecurityEnv,
  type LoginSecurityEnv,
} from "../loginSecurity.js";
import { issueTokenPair, loadTokenEnv, type TokenEnv } from "../tokens.js";
import { errorResponseSchema, tokenResponseSchema } from "./schemas.js";

export interface LoginRouteOptions {
  pool: Pool;
  redis: Redis;
  signingKey: SigningKey;
  tokenEnv?: TokenEnv;
  loginSecurityEnv?: LoginSecurityEnv;
}

interface LoginBody {
  email: string;
  password: string;
}

const loginBodySchema = {
  type: "object",
  required: ["email", "password"],
  additionalProperties: false,
  properties: {
    email: { type: "string", minLength: 3 },
    password: { type: "string", minLength: 1, maxLength: 512 },
  },
} as const;

interface UserRow {
  id: Buffer;
  password_hash: string | null;
  status: string;
  login_failures: number;
  login_locked: number;
  failure_window_expired: number;
}

export async function loginRoutes(app: FastifyInstance, opts: LoginRouteOptions): Promise<void> {
  const { pool, redis, signingKey } = opts;
  const tokenEnv = opts.tokenEnv ?? loadTokenEnv();
  const securityEnv = opts.loginSecurityEnv ?? loadLoginSecurityEnv();

  app.post<{ Body: LoginBody }>(
    "/login",
    {
      schema: {
        tags: ["auth"],
        summary: "Login with email/password",
        description:
          "성공 시 ES256 access JWT + opaque refresh 토큰(Redis DB0 저장)을 발급한다. " +
          "IP/이메일 단위 rate limit 초과 시 429, 임시 로그인 잠금 중에는 401.",
        body: loginBodySchema,
        response: { 200: tokenResponseSchema, 401: errorResponseSchema, 429: errorResponseSchema },
      },
    },
    async (req, reply) => {
      const { password } = req.body;
      const email = req.body.email.trim().toLowerCase();
      if (Array.from(email).length > 320) {
        return reply.code(401).send({ error: "invalid_credentials" });
      }

      const rateLimit = await checkLoginRateLimit(redis, securityEnv, req.ip, email);
      if (rateLimit.limited) {
        reply.header("Retry-After", String(rateLimit.retryAfterSeconds));
        return reply.code(429).send({ error: "rate_limited" });
      }

      // Serialize verification and count/reset against every concurrent login for this account.
      const conn = await pool.getConnection();
      let userId: string;
      try {
        await conn.beginTransaction();
        const [rows] = await conn.query(
          `SELECT id, password_hash, status, login_failures,
                  login_locked_until > UTC_TIMESTAMP(3) AS login_locked,
                  login_failure_window_started_at IS NULL OR
                    login_failure_window_started_at <= DATE_SUB(UTC_TIMESTAMP(3), INTERVAL ? SECOND) OR
                    (login_locked_until IS NOT NULL AND login_locked_until <= UTC_TIMESTAMP(3)) AS failure_window_expired
             FROM users WHERE email = ? FOR UPDATE`,
          [securityEnv.lockoutWindowSeconds, email],
        );
        const [row] = rows as UserRow[];
        if (!row || !row.password_hash || row.status === "deleted") {
          await conn.rollback();
          return reply.code(401).send({ error: "invalid_credentials" });
        }
        if (row.status === "locked" || row.login_locked) {
          await conn.rollback();
          return reply.code(401).send({ error: "account_locked" });
        }
        if (row.status !== "active") {
          await conn.rollback();
          return reply.code(401).send({ error: "invalid_credentials" });
        }

        const valid = await argon2.verify(row.password_hash, password);
        if (!valid) {
          const failures = (row.failure_window_expired ? 0 : row.login_failures) + 1;
          const locked = failures >= securityEnv.lockoutThreshold;
          await conn.execute(
            `UPDATE users SET login_failures = ?,
              login_failure_window_started_at = CASE WHEN ? THEN UTC_TIMESTAMP(3) ELSE login_failure_window_started_at END,
              login_locked_until = CASE WHEN ? THEN DATE_ADD(UTC_TIMESTAMP(3), INTERVAL ? SECOND) ELSE NULL END
             WHERE id = ?`,
            [failures, row.failure_window_expired ? 1 : 0, locked ? 1 : 0, securityEnv.lockoutDurationSeconds, row.id],
          );
          await conn.commit();
          return reply.code(401).send({ error: locked ? "account_locked" : "invalid_credentials" });
        }

        await conn.execute(
          "UPDATE users SET login_failures = 0, login_failure_window_started_at = NULL, login_locked_until = NULL WHERE id = ?",
          [row.id],
        );
        await conn.commit();
        userId = UUID.ofInner(row.id).toString();
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }
      const pair = await issueTokenPair({ redis, signingKey, tokenEnv, userId });

      return reply.code(200).send({
        access_token: pair.accessToken,
        refresh_token: pair.refreshToken,
        token_type: "Bearer",
        expires_in: pair.expiresIn,
      });
    },
  );
}
