import argon2 from "argon2";
import type { FastifyInstance } from "fastify";
import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";
import { UUID } from "uuidv7";

import type { SigningKey } from "../keys.js";
import { issueTokenPair, loadTokenEnv, type TokenEnv } from "../tokens.js";
import { errorResponseSchema, tokenResponseSchema } from "./schemas.js";

export interface LoginRouteOptions {
  pool: Pool;
  redis: Redis;
  signingKey: SigningKey;
  tokenEnv?: TokenEnv;
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
    email: { type: "string", minLength: 3, maxLength: 320 },
    password: { type: "string", minLength: 1, maxLength: 512 },
  },
} as const;

interface UserRow {
  id: Buffer;
  password_hash: string | null;
  status: string;
}

export async function loginRoutes(app: FastifyInstance, opts: LoginRouteOptions): Promise<void> {
  const { pool, redis, signingKey } = opts;
  const tokenEnv = opts.tokenEnv ?? loadTokenEnv();

  app.post<{ Body: LoginBody }>(
    "/login",
    {
      schema: {
        tags: ["auth"],
        summary: "Login with email/password",
        description: "성공 시 ES256 access JWT + opaque refresh 토큰(Redis DB0 저장)을 발급한다.",
        body: loginBodySchema,
        response: { 200: tokenResponseSchema, 401: errorResponseSchema },
      },
    },
    async (req, reply) => {
      const { email, password } = req.body;

      const [rows] = await pool.query("SELECT id, password_hash, status FROM users WHERE email = ?", [email]);
      const [row] = rows as UserRow[];

      if (!row || !row.password_hash || row.status !== "active") {
        return reply.code(401).send({ error: "invalid_credentials" });
      }

      const valid = await argon2.verify(row.password_hash, password);
      if (!valid) {
        return reply.code(401).send({ error: "invalid_credentials" });
      }

      const userId = UUID.ofInner(row.id).toString();
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
