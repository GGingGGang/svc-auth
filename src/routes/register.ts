import argon2 from "argon2";
import { createHash, randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { Pool } from "mysql2/promise";
import { uuidv7obj } from "uuidv7";
import type { Redis } from "ioredis";
import { encryptMailPayload, type MailConfig } from "../mailer.js";

export interface RegisterRouteOptions {
  pool: Pool;
  redis: Redis;
  registrationMode: "verified" | "demo";
  mailConfig: MailConfig | null;
}

interface RegisterBody {
  email: string;
  password: string;
  display_name: string;
  timezone: string;
}

const registerBodySchema = {
  type: "object",
  required: ["email", "password", "display_name", "timezone"],
  additionalProperties: false,
  properties: {
    email: { type: "string" },
    password: { type: "string" },
    display_name: { type: "string" },
    timezone: { type: "string", minLength: 1, maxLength: 64 },
  },
} as const;

const registerResponseSchema = {
  201: {
    type: "object",
    description: "사용자 생성 성공",
    properties: {
      id: { type: "string", format: "uuid" },
      email: { type: "string" },
      display_name: { type: "string" },
      timezone: { type: "string" },
      verification_required: { type: "boolean" },
    },
    required: ["id", "email", "display_name", "timezone", "verification_required"],
  },
  400: {
    type: "object",
    description: "요청 body 검증 실패",
    properties: {
      statusCode: { type: "integer" },
      error: { type: "string" },
      message: { type: "string" },
    },
    required: ["statusCode", "error", "message"],
  },
  409: {
    type: "object",
    description: "이미 등록된 이메일",
    properties: {
      error: { type: "string" },
    },
    required: ["error"],
  },
} as const;

function isDuplicateEmailError(err: unknown): boolean {
  return typeof err === "object" && err !== null && "code" in err && (err as { code?: unknown }).code === "ER_DUP_ENTRY";
}

async function registrationRateLimited(redis: Redis, email: string, ip: string): Promise<boolean> {
  const emailHash = createHash("sha256").update(email).digest("hex");
  const ipHash = createHash("sha256").update(ip).digest("hex");
  const script = "local m=redis.call('INCR',KEYS[1]); if m==1 then redis.call('EXPIRE',KEYS[1],60) end; local e=redis.call('INCR',KEYS[2]); if e==1 then redis.call('EXPIRE',KEYS[2],3600) end; local i=redis.call('INCR',KEYS[3]); if i==1 then redis.call('EXPIRE',KEYS[3],3600) end; return (m>1 or e>5 or i>20) and 1 or 0";
  return Number(await redis.eval(script, 3, `auth:lifecycle:email:verify:${emailHash}:minute`, `auth:lifecycle:email:verify:${emailHash}`, `auth:lifecycle:ip:verify:${ipHash}`)) === 1;
}

export async function registerRoutes(app: FastifyInstance, opts: RegisterRouteOptions): Promise<void> {
  const { pool, redis, registrationMode, mailConfig } = opts;

  app.post<{ Body: RegisterBody }>(
    "/register",
    {
      schema: {
        tags: ["auth"],
        summary: "Register a new user",
        description: "email/password/display_name/timezone 으로 사용자를 생성한다. 비밀번호는 argon2id 로 해싱된다.",
        body: registerBodySchema,
        response: registerResponseSchema,
      },
    },
    async (req, reply) => {
      const { password, timezone } = req.body;
      const email = req.body.email.trim().toLowerCase();
      const display_name = req.body.display_name.trim();

      if (Array.from(email).length > 320 || !/^[^\s@.]+(?:\.[^\s@.]+)*@[^\s@.]+(?:\.[^\s@.]+)+$/u.test(email)) {
        return reply.code(400).send({ statusCode: 400, error: "Bad Request", message: "Invalid email" });
      }
      const passwordLength = Array.from(password).length;
      if (passwordLength < 12 || passwordLength > 128) {
        return reply.code(400).send({ statusCode: 400, error: "Bad Request", message: "Password must be 12 to 128 characters" });
      }
      const displayNameLength = Array.from(display_name).length;
      if (displayNameLength < 1 || displayNameLength > 100) {
        return reply.code(400).send({ statusCode: 400, error: "Bad Request", message: "Display name must be 1 to 100 characters" });
      }

      try {
        new Intl.DateTimeFormat("en", { timeZone: timezone });
      } catch (err) {
        if (!(err instanceof RangeError)) throw err;
        return reply.code(400).send({ statusCode: 400, error: "Bad Request", message: "Invalid timezone" });
      }

      if (registrationMode !== "demo" && !mailConfig) return reply.code(503).send({ error: "registration_unavailable" });
      if (registrationMode !== "demo" && await registrationRateLimited(redis, email, req.ip)) return reply.code(429).send({ error: "rate_limited" });

      const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
      const id = uuidv7obj();

      try {
        const conn = await pool.getConnection();
        try {
          await conn.beginTransaction();
          await conn.execute(
            "INSERT INTO users (id,email,password_hash,display_name,timezone,email_verified_at) VALUES (?,?,?,?,?,?)",
            [Buffer.from(id.bytes), email, passwordHash, display_name, timezone, registrationMode === "demo" ? new Date() : null],
          );
          if (registrationMode !== "demo" && mailConfig) {
            const token = randomBytes(32).toString("base64url");
            const encrypted = encryptMailPayload(JSON.stringify({ subject: "Verify your email", token, action: "verify" }), mailConfig.encryptionKey);
            await conn.execute("INSERT INTO account_action_tokens(user_id,purpose,token_hash,expires_at) VALUES(?,'verify_email',?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 30 MINUTE))", [Buffer.from(id.bytes), createHash("sha256").update(token).digest("hex")]);
            const mailId = uuidv7obj();
            await conn.execute("INSERT INTO auth_mail_outbox(id,user_id,purpose,recipient,encrypted_payload) VALUES(?,?,'verify_email',?,?)", [Buffer.from(mailId.bytes), Buffer.from(id.bytes), email, encrypted]);
          }
          await conn.commit();
        } catch (err) { await conn.rollback(); throw err; }
        finally { conn.release(); }
      } catch (err) {
        if (isDuplicateEmailError(err)) {
          return reply.code(409).send({ error: "email_already_registered" });
        }
        throw err;
      }

      return reply.code(201).send({
        id: id.toString(),
        email,
        display_name,
        timezone,
        verification_required: registrationMode !== "demo",
      });
    },
  );
}
