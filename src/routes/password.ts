import argon2 from "argon2";
import type { FastifyInstance } from "fastify";
import type { Pool } from "mysql2/promise";
import type { Redis } from "ioredis";

import { verifyOwnAccessTokenClaims } from "../accessAuth.js";
import type { SigningKey } from "../keys.js";
import { checkPasswordChangeRateLimit, loadLoginSecurityEnv, type LoginSecurityEnv } from "../loginSecurity.js";
import { revokeSessionsBeforeVersion, loadTokenEnv, type TokenEnv } from "../tokens.js";
import { errorResponseSchema } from "./schemas.js";

export interface PasswordRouteOptions {
  pool: Pool;
  redis: Redis;
  signingKey: SigningKey;
  secondaryKey?: SigningKey;
  tokenEnv?: TokenEnv;
  loginSecurityEnv?: LoginSecurityEnv;
}

interface PasswordBody {
  current_password: string;
  new_password: string;
}

export async function passwordRoutes(app: FastifyInstance, opts: PasswordRouteOptions): Promise<void> {
  const { pool, redis, signingKey, secondaryKey } = opts;
  const tokenEnv = opts.tokenEnv ?? loadTokenEnv();
  const securityEnv = opts.loginSecurityEnv ?? loadLoginSecurityEnv();

  app.post<{ Body: PasswordBody }>("/password/change", {
    schema: {
      tags: ["auth"], summary: "Change password and revoke existing credentials",
      description: "현재 비밀번호 재인증, 별도 IP/계정 요청 제한. 성공 시 credential_version 증가로 이전 access/refresh 인증을 거절한다.",
      body: {
        type: "object", required: ["current_password", "new_password"], additionalProperties: false,
        properties: {
          current_password: { type: "string", minLength: 1, maxLength: 512 },
          new_password: { type: "string", minLength: 1, maxLength: 512 },
        },
      },
      response: { 204: { type: "null" }, 400: errorResponseSchema, 401: errorResponseSchema, 429: errorResponseSchema },
    },
    preValidation: async (req, reply) => {
      if (!req.body || typeof req.body !== "object" || Array.isArray(req.body) ||
          Object.keys(req.body).some((key) => key !== "current_password" && key !== "new_password")) {
        return reply.code(400).send({ error: "invalid_request" });
      }
    },
  }, async (req, reply) => {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
    const claims = token ? await verifyOwnAccessTokenClaims(token, signingKey, secondaryKey, tokenEnv) : null;
    if (!claims) return reply.code(401).send({ error: "unauthorized" });
    const newLength = Array.from(req.body.new_password).length;
    if (newLength < 12 || newLength > 128) return reply.code(400).send({ error: "invalid_new_password" });
    const rateLimit = await checkPasswordChangeRateLimit(redis, securityEnv, req.ip, claims.userId);
    if (rateLimit.limited) {
      reply.header("Retry-After", String(rateLimit.retryAfterSeconds));
      return reply.code(429).send({ error: "rate_limited" });
    }

    const conn = await pool.getConnection();
    let nextCredentialVersion: number | undefined;
    try {
      await conn.beginTransaction();
      const [rows] = await conn.query(
        `SELECT password_hash, status, credential_version FROM users
          WHERE id = UUID_TO_BIN(?) FOR UPDATE`,
        [claims.userId],
      );
      const [user] = rows as Array<{ password_hash: string | null; status: string; credential_version: number | string }>;
      if (!user || user.status !== "active" || Number(user.credential_version) !== claims.credentialVersion ||
          !user.password_hash || !await argon2.verify(user.password_hash, req.body.current_password)) {
        await conn.rollback();
        return reply.code(401).send({ error: "invalid_credentials" });
      }

      const passwordHash = await argon2.hash(req.body.new_password, { type: argon2.argon2id });
      nextCredentialVersion = Number(user.credential_version) + 1;
      await conn.execute(
        `UPDATE users SET password_hash = ?, credential_version = credential_version + 1
          WHERE id = UUID_TO_BIN(?)`,
        [passwordHash, claims.userId],
      );
      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }

    try {
      await revokeSessionsBeforeVersion(redis, claims.userId, nextCredentialVersion!);
    } catch {
      // credential_version already rejects every older access/refresh token;
      // the next session listing prunes stale Redis metadata if cleanup failed.
      req.log.error({ error_code: "session_cleanup_failed" }, "password changed; session cleanup deferred");
    }
    return reply.code(204).send();
  });
}
