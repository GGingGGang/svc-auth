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
    email: { type: "string", minLength: 3, maxLength: 320, pattern: "^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$" },
    password: { type: "string", minLength: 1, maxLength: 512 },
    display_name: { type: "string", minLength: 1, maxLength: 100 },
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
      const { email, password, display_name, timezone } = req.body;

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
