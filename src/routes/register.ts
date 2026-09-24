import argon2 from "argon2";
import type { FastifyInstance } from "fastify";
import type { Pool } from "mysql2/promise";
import { uuidv7obj } from "uuidv7";

export interface RegisterRouteOptions {
  pool: Pool;
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
    },
    required: ["id", "email", "display_name", "timezone"],
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

export async function registerRoutes(app: FastifyInstance, opts: RegisterRouteOptions): Promise<void> {
  const { pool } = opts;

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

      const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
      const id = uuidv7obj();

      try {
        await pool.execute(
          "INSERT INTO users (id, email, password_hash, display_name, timezone) VALUES (?, ?, ?, ?, ?)",
          [Buffer.from(id.bytes), email, passwordHash, display_name, timezone],
        );
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
      });
    },
  );
}
