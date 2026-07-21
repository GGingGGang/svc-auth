import type { FastifyInstance } from "fastify";
import type { Redis } from "ioredis";

import { logoutByRefreshToken } from "../tokens.js";

export interface LogoutRouteOptions {
  redis: Redis;
}

interface LogoutBody {
  refresh_token: string;
}

const logoutBodySchema = {
  type: "object",
  required: ["refresh_token"],
  additionalProperties: false,
  properties: {
    refresh_token: { type: "string", minLength: 1 },
  },
} as const;

export async function logoutRoutes(app: FastifyInstance, opts: LogoutRouteOptions): Promise<void> {
  const { redis } = opts;

  app.post<{ Body: LogoutBody }>(
    "/logout",
    {
      schema: {
        tags: ["auth"],
        summary: "Logout (revoke refresh family)",
        description: "refresh 토큰이 속한 family 전체를 Redis 에서 폐기한다. 알 수 없는 토큰이어도 204 (idempotent).",
        body: logoutBodySchema,
        response: { 204: { type: "null", description: "폐기 완료" } },
      },
    },
    async (req, reply) => {
      await logoutByRefreshToken(redis, req.body.refresh_token);
      return reply.code(204).send();
    },
  );
}
