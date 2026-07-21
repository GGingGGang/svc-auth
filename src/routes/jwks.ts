import type { FastifyInstance } from "fastify";

import type { SigningKey } from "../keys.js";

export interface JwksRouteOptions {
  signingKey: SigningKey;
}

export async function jwksRoutes(app: FastifyInstance, opts: JwksRouteOptions): Promise<void> {
  const { signingKey } = opts;

  app.get(
    "/.well-known/jwks.json",
    {
      schema: {
        tags: ["auth"],
        summary: "JWKS public key set",
        response: {
          200: {
            type: "object",
            properties: {
              keys: { type: "array", items: { type: "object", additionalProperties: true } },
            },
            required: ["keys"],
          },
        },
      },
    },
    async (_req, reply) => {
      reply.header("Cache-Control", "max-age=3600");
      return { keys: [signingKey.publicJwk] };
    },
  );
}
