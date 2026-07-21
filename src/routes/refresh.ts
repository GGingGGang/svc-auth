import type { FastifyInstance } from "fastify";
import type { Redis } from "ioredis";

import type { SigningKey } from "../keys.js";
import { loadTokenEnv, rotateRefreshToken, type TokenEnv } from "../tokens.js";
import { errorResponseSchema, tokenResponseSchema } from "./schemas.js";

export interface RefreshRouteOptions {
  redis: Redis;
  signingKey: SigningKey;
  tokenEnv?: TokenEnv;
}

interface RefreshBody {
  refresh_token: string;
}

const refreshBodySchema = {
  type: "object",
  required: ["refresh_token"],
  additionalProperties: false,
  properties: {
    refresh_token: { type: "string", minLength: 1 },
  },
} as const;

export async function refreshRoutes(app: FastifyInstance, opts: RefreshRouteOptions): Promise<void> {
  const { redis, signingKey } = opts;
  const tokenEnv = opts.tokenEnv ?? loadTokenEnv();

  app.post<{ Body: RefreshBody }>(
    "/refresh",
    {
      schema: {
        tags: ["auth"],
        summary: "Rotate refresh token",
        description:
          "refresh 토큰은 one-time use — 성공 시 기존 토큰은 즉시 소비 처리되고 새 access+refresh 쌍이 발급된다(sliding 14d). 이미 소비된 토큰 재사용 시 401 과 함께 해당 family 전체가 폐기된다.",
        body: refreshBodySchema,
        response: { 200: tokenResponseSchema, 401: errorResponseSchema },
      },
    },
    async (req, reply) => {
      const result = await rotateRefreshToken({
        redis,
        signingKey,
        tokenEnv,
        refreshToken: req.body.refresh_token,
      });

      if (!result.ok) {
        const error = result.reason === "reuse_detected" ? "refresh_reuse_detected" : "invalid_refresh_token";
        return reply.code(401).send({ error });
      }

      return reply.code(200).send({
        access_token: result.pair.accessToken,
        refresh_token: result.pair.refreshToken,
        token_type: "Bearer",
        expires_in: result.pair.expiresIn,
      });
    },
  );
}
