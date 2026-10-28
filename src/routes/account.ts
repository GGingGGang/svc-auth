import type { FastifyInstance } from "fastify";
import type { Pool, RowDataPacket } from "mysql2/promise";

import { activeCredentialVersion } from "../accountStatus.js";
import { verifyOwnAccessTokenClaims } from "../accessAuth.js";
import type { SigningKey } from "../keys.js";
import { loadTokenEnv, type TokenEnv } from "../tokens.js";
import { errorResponseSchema } from "./schemas.js";

export interface AccountRouteOptions {
  pool: Pool;
  signingKey: SigningKey;
  secondaryKey?: SigningKey;
  tokenEnv?: TokenEnv;
}

interface ProfileBody {
  display_name?: string;
  timezone?: string;
}

const profileSchema = {
  type: "object",
  properties: {
    id: { type: "string", format: "uuid" },
    email: { type: "string" },
    display_name: { type: "string" },
    timezone: { type: "string" },
  },
  required: ["id", "email", "display_name", "timezone"],
} as const;

export async function accountRoutes(app: FastifyInstance, opts: AccountRouteOptions): Promise<void> {
  const { pool, signingKey, secondaryKey } = opts;
  const tokenEnv = opts.tokenEnv ?? loadTokenEnv();

  async function authenticate(req: { headers: { authorization?: string } }) {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
    const claims = token ? await verifyOwnAccessTokenClaims(token, signingKey, secondaryKey, tokenEnv) : null;
    if (!claims) return null;
    const version = await activeCredentialVersion(pool, claims.userId);
    return version === claims.credentialVersion ? claims.userId : null;
  }

  app.get("/account", {
    schema: {
      tags: ["auth"], summary: "Get this user's profile", response: { 200: profileSchema, 401: errorResponseSchema },
    },
  }, async (req, reply) => {
    const userId = await authenticate(req);
    if (!userId) return reply.code(401).send({ error: "unauthorized" });
    const [rows] = await pool.query<RowDataPacket[]>(
      "SELECT BIN_TO_UUID(id) AS id, email, display_name, timezone FROM users WHERE id = UUID_TO_BIN(?) AND status = 'active'",
      [userId],
    );
    if (!rows[0]) return reply.code(401).send({ error: "unauthorized" });
    return rows[0];
  });

  app.patch<{ Body: ProfileBody }>("/account", {
    schema: {
      tags: ["auth"], summary: "Update this user's profile",
      body: {
        type: "object", additionalProperties: false, minProperties: 1,
        properties: {
          display_name: { type: "string", minLength: 1, maxLength: 100 },
          timezone: { type: "string", minLength: 1, maxLength: 64 },
        },
      },
      response: { 200: profileSchema, 400: errorResponseSchema, 401: errorResponseSchema },
    },
    preValidation: async (req, reply) => {
      if (!req.body || typeof req.body !== "object" || Array.isArray(req.body) ||
          Object.keys(req.body).some((key) => key !== "display_name" && key !== "timezone")) {
        return reply.code(400).send({ error: "invalid_request" });
      }
    },
  }, async (req, reply) => {
    const userId = await authenticate(req);
    if (!userId) return reply.code(401).send({ error: "unauthorized" });
    const changes: ProfileBody = {};
    if (req.body.display_name !== undefined) {
      const value = req.body.display_name.trim();
      const length = Array.from(value).length;
      if (length < 1 || length > 100) return reply.code(400).send({ error: "invalid_display_name" });
      changes.display_name = value;
    }
    if (req.body.timezone !== undefined) {
      try { new Intl.DateTimeFormat("en", { timeZone: req.body.timezone }); }
      catch (err) {
        if (!(err instanceof RangeError)) throw err;
        return reply.code(400).send({ error: "invalid_timezone" });
      }
      changes.timezone = req.body.timezone;
    }
    const sets: string[] = [];
    const values: string[] = [];
    if (changes.display_name !== undefined) { sets.push("display_name = ?"); values.push(changes.display_name); }
    if (changes.timezone !== undefined) { sets.push("timezone = ?"); values.push(changes.timezone); }
    values.push(userId);
    await pool.execute(`UPDATE users SET ${sets.join(", ")} WHERE id = UUID_TO_BIN(?) AND status = 'active'`, values);
    const [rows] = await pool.query<RowDataPacket[]>(
      "SELECT BIN_TO_UUID(id) AS id, email, display_name, timezone FROM users WHERE id = UUID_TO_BIN(?) AND status = 'active'",
      [userId],
    );
    if (!rows[0]) return reply.code(401).send({ error: "unauthorized" });
    return rows[0];
  });
}
