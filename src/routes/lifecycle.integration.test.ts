import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { MySqlContainer, type StartedMySqlContainer } from "@testcontainers/mysql";
import { RedisContainer, type StartedRedisContainer } from "@testcontainers/redis";
import argon2 from "argon2";
import { Redis } from "ioredis";
import { createConnection, createPool, type Pool, type RowDataPacket } from "mysql2/promise";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { acceptResult } from "../deletionWorker.js";
import { decryptMailPayload } from "../mailer.js";
import type { SigningKey } from "../keys.js";
import { buildApp } from "../router.js";
import { generateTestSigningKey } from "../test-support/signing-key.js";
import type { TokenEnv } from "../tokens.js";

const migrationSql = ["0001_init", "0002_login_lockout", "0003_credential_version", "0004_account_lifecycle"]
  .map((name) => readFileSync(fileURLToPath(new URL(`../../db/migrations/${name}.up.sql`, import.meta.url)), "utf8"))
  .join("\n");
const mailKey = Buffer.alloc(32, 0x5a);
const originalEnv = {
  smtp: process.env.SMTP_URL,
  from: process.env.SMTP_FROM,
  key: process.env.AUTH_MAIL_ENCRYPTION_KEY,
  web: process.env.WEB_APP_URL,
};
const tokenEnv: TokenEnv = { issuer: "auth.integration", accessTtlSeconds: 3600, refreshTtlSeconds: 1_209_600 };

describe("account lifecycle MySQL integration", () => {
  let mysqlContainer: StartedMySqlContainer;
  let redisContainer: StartedRedisContainer;
  let pool: Pool;
  let redis: Redis;
  let signingKey: SigningKey;
  let app: ReturnType<typeof buildApp>;

  beforeAll(async () => {
    process.env.SMTP_URL = "smtp://127.0.0.1:1025";
    process.env.SMTP_FROM = "no-reply@example.test";
    process.env.AUTH_MAIL_ENCRYPTION_KEY = mailKey.toString("base64");
    process.env.WEB_APP_URL = "https://example.test";
    [mysqlContainer, redisContainer] = await Promise.all([
      new MySqlContainer("mysql:8").withDatabase("auth").start(),
      new RedisContainer("redis:7").start(),
    ]);
    const setup = await createConnection({
      host: mysqlContainer.getHost(), port: mysqlContainer.getMappedPort(3306),
      user: mysqlContainer.getUsername(), password: mysqlContainer.getUserPassword(),
      database: mysqlContainer.getDatabase(), multipleStatements: true,
    });
    await setup.query(migrationSql);
    await setup.end();
    pool = createPool({
      host: mysqlContainer.getHost(), port: mysqlContainer.getMappedPort(3306),
      user: mysqlContainer.getUsername(), password: mysqlContainer.getUserPassword(),
      database: mysqlContainer.getDatabase(), waitForConnections: true, connectionLimit: 8,
    });
    redis = new Redis({ host: redisContainer.getHost(), port: redisContainer.getPort(), db: 0 });
    signingKey = await generateTestSigningKey();
    // The SMTP URL is deliberately unreachable; this suite reads encrypted
    // outbox payloads and never starts the mail worker or sends a message.
    app = buildApp({ pool, redis, signingKey, tokenEnv, registrationMode: "verified" });
    await app.ready();
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    await pool?.end();
    redis?.disconnect();
    await mysqlContainer?.stop();
    await redisContainer?.stop();
    restore("SMTP_URL", originalEnv.smtp);
    restore("SMTP_FROM", originalEnv.from);
    restore("AUTH_MAIL_ENCRYPTION_KEY", originalEnv.key);
    restore("WEB_APP_URL", originalEnv.web);
  });

  async function register(email: string, password = "correct horse battery staple") {
    const response = await app.inject({
      method: "POST", url: "/register",
      payload: { email, password, display_name: "Lifecycle", timezone: "Asia/Seoul" },
    });
    expect(response.statusCode).toBe(201);
    return { id: response.json().id as string, email, password };
  }

  async function actionToken(email: string, purpose: string): Promise<string> {
    const [rows] = await pool.query<Array<RowDataPacket & { encrypted_payload: Buffer }>>(
      "SELECT encrypted_payload FROM auth_mail_outbox WHERE recipient=? AND purpose=? ORDER BY id DESC LIMIT 1",
      [email, purpose],
    );
    expect(rows[0]).toBeDefined();
    return (JSON.parse(decryptMailPayload(rows[0]!.encrypted_payload, mailKey)) as { token: string }).token;
  }

  it("consumes a verification token once under concurrent MySQL requests", async () => {
    const user = await register("verify-race@example.test");
    const token = await actionToken(user.email, "verify_email");
    const results = await Promise.all([
      app.inject({ method: "POST", url: "/email/verification/confirm", payload: { token } }),
      app.inject({ method: "POST", url: "/email/verification/confirm", payload: { token } }),
    ]);
    expect(results.map((result) => result.statusCode).sort()).toEqual([200, 400]);
    const [users] = await pool.query<Array<RowDataPacket & { email_verified_at: Date | null }>>(
      "SELECT email_verified_at FROM users WHERE id=UUID_TO_BIN(?)", [user.id],
    );
    expect(users[0]?.email_verified_at).not.toBeNull();
    const [tokens] = await pool.query<Array<RowDataPacket & { consumed_at: Date | null }>>(
      "SELECT consumed_at FROM account_action_tokens WHERE user_id=UUID_TO_BIN(?) AND purpose='verify_email'", [user.id],
    );
    expect(tokens).toHaveLength(1);
    expect(tokens[0]?.consumed_at).not.toBeNull();
  }, 30_000);

  it("persists a reset token once and rejects reuse against the real action-token table", async () => {
    const user = await register("reset-once@example.test");
    const verify = await actionToken(user.email, "verify_email");
    expect((await app.inject({ method: "POST", url: "/email/verification/confirm", payload: { token: verify } })).statusCode).toBe(200);
    expect((await app.inject({ method: "POST", url: "/password/reset/request", payload: { email: user.email } })).statusCode).toBe(202);
    const token = await actionToken(user.email, "reset_password");
    const reset = { token, new_password: "a changed and safer password" };
    expect((await app.inject({ method: "POST", url: "/password/reset", payload: reset })).statusCode).toBe(204);
    await redis.flushdb(); // clear request throttling so reuse reaches MySQL token validation
    expect((await app.inject({ method: "POST", url: "/password/reset", payload: reset })).statusCode).toBe(400);
    const [rows] = await pool.query<Array<RowDataPacket & { credential_version: number; password_hash: string }>>(
      "SELECT credential_version,password_hash FROM users WHERE id=UUID_TO_BIN(?)", [user.id],
    );
    expect(Number(rows[0]?.credential_version)).toBe(1);
    expect(await argon2.verify(rows[0]!.password_hash, "a changed and safer password")).toBe(true);
    expect(await argon2.verify(rows[0]!.password_hash, user.password)).toBe(false);
    const [tokens] = await pool.query<Array<RowDataPacket & { token_hash: string }>>(
      "SELECT token_hash FROM account_action_tokens WHERE user_id=UUID_TO_BIN(?) AND purpose='reset_password'", [user.id],
    );
    expect(tokens).toHaveLength(0);
  }, 30_000);

  it("keeps deletion pending until all service ACKs, then hard-deletes and completes the receipt", async () => {
    const user = await register("delete-flow@example.test");
    const verify = await actionToken(user.email, "verify_email");
    expect((await app.inject({ method: "POST", url: "/email/verification/confirm", payload: { token: verify } })).statusCode).toBe(200);
    const login = await app.inject({ method: "POST", url: "/login", payload: { email: user.email, password: user.password } });
    expect(login.statusCode).toBe(200);
    const deleted = await app.inject({
      method: "DELETE", url: "/account", headers: { authorization: `Bearer ${login.json().access_token}` },
      payload: { current_password: user.password, confirm: true },
    });
    expect(deleted.statusCode).toBe(202);
    const receipt = deleted.json().deletion_receipt as string;
    const [outboxRows] = await pool.query<Array<RowDataPacket & { event_id: string; request_id: string }>>(
      "SELECT event_id,request_id FROM account_deletion_outbox WHERE user_id=UUID_TO_BIN(?)", [user.id],
    );
    const event = outboxRows[0]!;
    const status = (await app.inject({ method: "GET", url: "/account/deletion", headers: { "x-deletion-receipt": receipt } }));
    expect(status.json()).toEqual({ status: "deleting" });
    expect((await pool.query("SELECT id FROM users WHERE id=UUID_TO_BIN(?)", [user.id]))[0]).toHaveLength(1);

    for (const service of ["core", "batch"] as const) {
      await acceptResult(pool, redis, { ...event, service, status: "completed", occurred_at: new Date().toISOString() });
      expect((await pool.query("SELECT id FROM users WHERE id=UUID_TO_BIN(?)", [user.id]))[0]).toHaveLength(1);
    }
    await Promise.all([
      acceptResult(pool, redis, { ...event, service: "notify", status: "completed", occurred_at: new Date().toISOString() }),
      acceptResult(pool, redis, { ...event, service: "notify", status: "completed", occurred_at: new Date().toISOString() }),
    ]);
    const [users] = await pool.query("SELECT id FROM users WHERE id=UUID_TO_BIN(?)", [user.id]);
    expect(users).toHaveLength(0);
    const [mail] = await pool.query("SELECT id FROM auth_mail_outbox WHERE recipient=?", [user.email]);
    expect(mail).toHaveLength(0);
    const completed = await app.inject({ method: "GET", url: "/account/deletion", headers: { "x-deletion-receipt": receipt } });
    expect(completed.statusCode).toBe(200);
    expect(completed.json()).toEqual({ status: "completed" });
    expect((await app.inject({ method: "GET", url: "/account/deletion", headers: { "x-deletion-receipt": "wrong-receipt" } })).statusCode).toBe(404);

    await acceptResult(pool, redis, { ...event, service: "notify", status: "completed", occurred_at: new Date().toISOString() });
  }, 30_000);
});

function restore(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
