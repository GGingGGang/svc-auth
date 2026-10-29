import { afterEach, describe, expect, it, vi } from "vitest";
import type { Pool } from "mysql2/promise";
import type { Redis } from "ioredis";
import argon2 from "argon2";
import { uuidv7obj } from "uuidv7";
import { buildApp } from "../router.js";
import { generateTestSigningKey } from "../test-support/signing-key.js";

const tokenEnv = { issuer: "auth.test", accessTtlSeconds: 3600, refreshTtlSeconds: 1209600 };
const stubRedis = { eval: vi.fn().mockResolvedValue(0) } as unknown as Redis;
const original = { internal: process.env.INTERNAL_SERVICE_TOKEN, operators: process.env.OPERATOR_TOKENS_JSON, smtp: process.env.SMTP_URL, from: process.env.SMTP_FROM, key: process.env.AUTH_MAIL_ENCRYPTION_KEY, web: process.env.WEB_APP_URL };

afterEach(() => {
  if (original.internal === undefined) delete process.env.INTERNAL_SERVICE_TOKEN; else process.env.INTERNAL_SERVICE_TOKEN = original.internal;
  if (original.operators === undefined) delete process.env.OPERATOR_TOKENS_JSON; else process.env.OPERATOR_TOKENS_JSON = original.operators;
  if (original.smtp === undefined) delete process.env.SMTP_URL; else process.env.SMTP_URL = original.smtp;
  if (original.from === undefined) delete process.env.SMTP_FROM; else process.env.SMTP_FROM = original.from;
  if (original.key === undefined) delete process.env.AUTH_MAIL_ENCRYPTION_KEY; else process.env.AUTH_MAIL_ENCRYPTION_KEY = original.key;
  if (original.web === undefined) delete process.env.WEB_APP_URL; else process.env.WEB_APP_URL = original.web;
});

describe("account lifecycle security boundaries", () => {
  it("does not accept registration in public mode without a configured SMTP transport", async () => {
    delete process.env.SMTP_URL; delete process.env.SMTP_FROM; delete process.env.AUTH_MAIL_ENCRYPTION_KEY; delete process.env.WEB_APP_URL;
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: {} as Pool, redis: stubRedis, signingKey, registrationMode: "verified" });
    await app.ready();
    const response = await app.inject({ method: "POST", url: "/register", payload: { email: "test@example.com", password: "a strong and safe passphrase", display_name: "Test", timezone: "UTC" } });
    expect(response.statusCode).toBe(503);
    await app.close();
  });

  it("requires the internal service bearer and returns verified active state only", async () => {
    process.env.INTERNAL_SERVICE_TOKEN = "internal-secret";
    const query = vi.fn().mockResolvedValue([[{ status: "active", timezone: "Asia/Seoul", email_verified_at: new Date() }], []]);
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: { query } as unknown as Pool, redis: stubRedis, signingKey });
    await app.ready();
    const userId = "123e4567-e89b-42d3-a456-426614174000";
    const denied = await app.inject({ method: "GET", url: `/internal/accounts/${userId}/status` });
    expect(denied.statusCode).toBe(401);
    const allowed = await app.inject({ method: "GET", url: `/internal/accounts/${userId}/status`, headers: { authorization: "Bearer internal-secret" } });
    expect(allowed.json()).toEqual({ active: true, timezone: "Asia/Seoul" });
    await app.close();
  });

  it("binds suspend audit actor to configured operator credential and bumps credential version", async () => {
    const operatorToken = "01234567890123456789012345678901";
    process.env.OPERATOR_TOKENS_JSON = JSON.stringify({ "security-operator": operatorToken });
    const execute = vi.fn().mockResolvedValue([{}, []]);
    const query = vi.fn().mockResolvedValue([[{ id: Buffer.alloc(16), status: "active", email_verified_at: new Date() }], []]);
    const conn = { beginTransaction: vi.fn(), commit: vi.fn(), rollback: vi.fn(), release: vi.fn(), execute, query };
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: { getConnection: vi.fn().mockResolvedValue(conn) } as unknown as Pool, redis: stubRedis, signingKey });
    await app.ready();
    const response = await app.inject({ method: "POST", url: "/internal/accounts/123e4567-e89b-42d3-a456-426614174000/suspend", headers: { authorization: `Bearer ${operatorToken}` }, payload: { reason: "verified policy violation" } });
    expect(response.statusCode).toBe(200);
    expect(execute.mock.calls[0]?.[0]).toContain("credential_version=credential_version+1");
    const audit = execute.mock.calls.find(([sql]) => String(sql).includes("account_operator_audit"));
    expect(audit?.[1]).toContain("security-operator");
    await app.close();
  });

  it("deletes an unverified account only after password confirmation and persists cleanup request", async () => {
    const userId = uuidv7obj();
    const passwordHash = await argon2.hash("unverified user's safe password");
    const execute = vi.fn().mockResolvedValue([{}, []]);
    const query = vi.fn().mockResolvedValue([[{ id: Buffer.from(userId.bytes), password_hash: passwordHash, status: "active", credential_version: 0, email_verified_at: null }], []]);
    const conn = { beginTransaction: vi.fn(), commit: vi.fn(), rollback: vi.fn(), release: vi.fn(), execute, query };
    const poolQuery = vi.fn().mockResolvedValue([[{ id: Buffer.from(userId.bytes) }], []]);
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: { query: poolQuery, getConnection: vi.fn().mockResolvedValue(conn) } as unknown as Pool, redis: stubRedis, signingKey });
    await app.ready();
    const response = await app.inject({ method: "POST", url: "/account/deletion/unverified", payload: { email: "pending@example.com", password: "unverified user's safe password", confirm: true } });
    expect(response.statusCode).toBe(202);
    expect(response.json()).toMatchObject({ accepted: true, deletion_receipt: expect.any(String) });
    expect(execute.mock.calls.some(([sql]) => String(sql).includes("account_deletion_outbox"))).toBe(true);
    expect(execute.mock.calls.some(([sql]) => String(sql).includes("status='deleting'"))).toBe(true);
    await app.close();
  }, 20_000);

  it("validates reset token before hashing and consumes it with a version bump", async () => {
    const userId = uuidv7obj();
    const execute = vi.fn().mockResolvedValue([{}, []]);
    const query = vi.fn().mockResolvedValue([[{ id: Buffer.from(userId.bytes), email: "verified@example.com", status: "active", credential_version: 4, purpose: "reset_password", pending_email: null }], []]);
    const conn = { beginTransaction: vi.fn(), commit: vi.fn(), rollback: vi.fn(), release: vi.fn(), execute, query };
    const poolQuery = vi.fn().mockResolvedValueOnce([[{ ok: 1 }], []]).mockResolvedValueOnce([[], []]);
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: { query: poolQuery, getConnection: vi.fn().mockResolvedValue(conn) } as unknown as Pool, redis: stubRedis, signingKey });
    await app.ready();
    const payload = { token: "a-real-looking-token", new_password: "a new secure password" };
    const success = await app.inject({ method: "POST", url: "/password/reset", payload });
    expect(success.statusCode).toBe(204);
    expect(execute.mock.calls.some(([sql]) => String(sql).includes("credential_version=credential_version+1"))).toBe(true);
    const repeat = await app.inject({ method: "POST", url: "/password/reset", payload });
    expect(repeat.statusCode).toBe(400);
    expect(poolQuery).toHaveBeenCalledTimes(2);
    await app.close();
  }, 20_000);
});
