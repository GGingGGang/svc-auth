import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";

import { isActiveUser } from "../accountStatus.js";
import { verifyOwnAccessToken } from "../accessAuth.js";
import type { SigningKey } from "../keys.js";
import { listSessions, loadTokenEnv, revokeSessionForUser, type TokenEnv } from "../tokens.js";
import { errorResponseSchema } from "./schemas.js";

export interface SessionsRouteOptions {
  pool: Pool;
  redis: Redis;
  signingKey: SigningKey;
  secondaryKey?: SigningKey;
  tokenEnv?: TokenEnv;
}

const sessionSchema = {
  type: "object",
  properties: {
    family_id: { type: "string" },
    created_at: { type: "string" },
    last_active_at: { type: "string" },
  },
  required: ["family_id", "created_at", "last_active_at"],
} as const;

export async function sessionsRoutes(app: FastifyInstance, opts: SessionsRouteOptions): Promise<void> {
  const { pool, redis, signingKey, secondaryKey } = opts;
  const tokenEnv = opts.tokenEnv ?? loadTokenEnv();

  // Shared bearer-token check for both routes below. Replies 401 itself (so
  // callers can just early-return) and returns the authenticated user id.
  async function authenticate(req: FastifyRequest, reply: FastifyReply): Promise<string | undefined> {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : undefined;
    const userId = token ? await verifyOwnAccessToken(token, signingKey, secondaryKey, tokenEnv) : null;
    if (!userId || !await isActiveUser(pool, userId)) {
      await reply.code(401).send({ error: "unauthorized" });
      return undefined;
    }
    return userId;
  }

  app.get(
    "/sessions",
    {
      schema: {
        tags: ["auth"],
        summary: "List this user's active sessions",
        description:
          "Authorization: Bearer <access-token> 필수. 각 항목은 하나의 로그인(=refresh token family)에 대응한다 — 로그인마다 새 family 가 시작되므로 사실상 '기기' 단위 목록.",
        response: {
          200: {
            type: "object",
            properties: { sessions: { type: "array", items: sessionSchema } },
            required: ["sessions"],
          },
          401: errorResponseSchema,
        },
      },
    },
    async (req, reply) => {
      const userId = await authenticate(req, reply);
      if (!userId) return;
      const sessions = await listSessions(redis, userId);
      return reply.code(200).send({ sessions });
    },
  );

  app.delete<{ Params: { familyId: string } }>(
    "/sessions/:familyId",
    {
      schema: {
        tags: ["auth"],
        summary: "Force logout one session",
        description:
          "Authorization: Bearer <access-token> 필수. 해당 family 의 refresh 토큰 전체를 폐기 — /logout 과 동일한 폐기 메커니즘을 " +
          "특정 refresh 토큰 없이(다른 기기를 향해) 호출할 수 있게 한 것. 호출자 소유가 아닌 family_id 는 404 (존재 여부 미노출). " +
          "이미 발급된 access 토큰은 JWKS 전용 검증(../PLAN.md §13 정정 #6) 특성상 즉시 무효화되지 않고 잔여 TTL 만큼 유효하다.",
        params: {
          type: "object",
          required: ["familyId"],
          properties: { familyId: { type: "string" } },
        },
        response: {
          204: { type: "null", description: "폐기 완료" },
          401: errorResponseSchema,
          404: errorResponseSchema,
        },
      },
    },
    async (req, reply) => {
      const userId = await authenticate(req, reply);
      if (!userId) return;
      const revoked = await revokeSessionForUser(redis, userId, req.params.familyId);
      if (!revoked) {
        return reply.code(404).send({ error: "not_found" });
      }
      return reply.code(204).send();
    },
  );
}
