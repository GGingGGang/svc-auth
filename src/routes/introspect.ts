import type { FastifyInstance } from "fastify";
import type { Pool } from "mysql2/promise";

import { verifyOwnAccessToken } from "../accessAuth.js";
import { isActiveUser } from "../accountStatus.js";
import type { SigningKey } from "../keys.js";
import { loadTokenEnv, type TokenEnv } from "../tokens.js";

export interface IntrospectRouteOptions {
  pool: Pool;
  signingKey: SigningKey;
  secondaryKey?: SigningKey;
  tokenEnv?: TokenEnv;
}

export async function introspectRoutes(app: FastifyInstance, opts: IntrospectRouteOptions): Promise<void> {
  const tokenEnv = opts.tokenEnv ?? loadTokenEnv();
  app.get("/introspect", {
    schema: {
      tags: ["auth"], summary: "Check current access-token account status",
      response: {
        200: { type: "object", properties: { active: { type: "boolean" } }, required: ["active"] },
        401: { type: "object", properties: { error: { type: "string" } }, required: ["error"] },
        503: { type: "object", properties: { error: { type: "string" } }, required: ["error"] },
      },
    },
  }, async (req, reply) => {
    reply.header("Cache-Control", "no-store");
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
    const userId = token ? await verifyOwnAccessToken(token, opts.signingKey, opts.secondaryKey, tokenEnv) : null;
    if (!userId) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    let active: boolean;
    try {
      active = await isActiveUser(opts.pool, userId);
    } catch {
      return reply.code(503).send({ error: "unavailable" });
    }
    if (!active) return reply.code(401).send({ error: "unauthorized" });
    return { active: true };
  });
}
