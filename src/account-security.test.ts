import argon2 from "argon2";
import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";
import { describe, expect, it, vi } from "vitest";

import { buildApp } from "./router.js";
import { generateTestSigningKey } from "./test-support/signing-key.js";
import { signAccessToken } from "./tokens.js";

const tokenEnv = { issuer: "auth.test", accessTtlSeconds: 3600, refreshTtlSeconds: 1209600 };
const userId = "01993d8e-e9d1-7068-9123-000000000004";

function mockPool(hash: string) {
  let version = 0;
  let savedHash = hash;
  const query = vi.fn(async (sql: string) => {
    if (sql.includes("credential_version")) return [[{ credential_version: version }], []];
    if (sql.includes("BIN_TO_UUID")) return [[{
      id: userId, email: "alice@example.com", display_name: "Alice", timezone: "UTC",
    }], []];
    return [[], []];
  });
  const conn = {
    beginTransaction: vi.fn(async () => undefined),
    query: vi.fn(async () => [[{
      password_hash: savedHash, status: "active", credential_version: version,
    }], []]),
    execute: vi.fn(async (sql: string, values: unknown[]) => {
      if (sql.includes("UPDATE users SET password_hash")) {
        savedHash = String(values[0]);
        version++;
      }
      return [{ affectedRows: 1 }, []];
    }),
    commit: vi.fn(async () => undefined),
    rollback: vi.fn(async () => undefined),
    release: vi.fn(),
  };
  return {
    pool: { query, getConnection: vi.fn(async () => conn) } as unknown as Pool,
    conn,
    currentVersion: () => version,
  };
}

describe("account and password security", () => {
  it("changes password atomically and rejects old credentials even when Redis cleanup fails", async () => {
    const hash = await argon2.hash("correct current password");
    const db = mockPool(hash);
    const signingKey = await generateTestSigningKey();
    const pair = await signAccessToken(userId, signingKey, tokenEnv);
    const evalCommand = vi.fn()
      .mockResolvedValueOnce([1, 60]).mockResolvedValueOnce([1, 60])
      .mockRejectedValueOnce(new Error("redis unavailable")).mockResolvedValueOnce([1]);
    const get = vi.fn().mockResolvedValue(JSON.stringify({
      user_id: userId, family_id: "old-family", credential_version: 0, consumed: false,
    }));
    const redis = { eval: evalCommand, get } as unknown as Redis;
    const app = buildApp({ pool: db.pool, redis, signingKey, tokenEnv });
    await app.ready();
    const headers = { authorization: `Bearer ${pair.token}` };

    const changed = await app.inject({ method: "POST", url: "/password/change", headers,
      payload: { current_password: "correct current password", new_password: "a new secure password" } });
    expect(changed.statusCode).toBe(204);
    expect(db.currentVersion()).toBe(1);
    expect(db.conn.commit).toHaveBeenCalledOnce();

    expect((await app.inject({ method: "GET", url: "/introspect", headers })).statusCode).toBe(401);
    // A login that read version 0 before commit may mint its response afterward;
    // that response remains version 0 and is rejected immediately.
    const racedToken = (await signAccessToken(userId, signingKey, tokenEnv, 0)).token;
    expect((await app.inject({ method: "GET", url: "/introspect",
      headers: { authorization: `Bearer ${racedToken}` } })).statusCode).toBe(401);
    const refresh = await app.inject({ method: "POST", url: "/refresh", payload: { refresh_token: "old-refresh" } });
    expect(refresh.statusCode).toBe(401);
    expect(evalCommand).toHaveBeenCalledTimes(4); // rate limit, deferred cleanup, then stale family cleanup
    await app.close();
  }, 20_000);

  it("does not change credentials when current password is wrong or new password is too short", async () => {
    const hash = await argon2.hash("correct current password");
    const db = mockPool(hash);
    const signingKey = await generateTestSigningKey();
    const evalCommand = vi.fn().mockResolvedValue([1, 60]);
    const redis = { eval: evalCommand } as unknown as Redis;
    const app = buildApp({ pool: db.pool, redis, signingKey, tokenEnv });
    await app.ready();
    const token = (await signAccessToken(userId, signingKey, tokenEnv)).token;
    const headers = { authorization: `Bearer ${token}` };

    expect((await app.inject({ method: "POST", url: "/password/change", headers,
      payload: { current_password: "correct current password", new_password: "a new secure password", extra: true } })).statusCode).toBe(400);
    expect((await app.inject({ method: "POST", url: "/password/change", headers,
      payload: { current_password: "wrong current password", new_password: "a new secure password" } })).statusCode).toBe(401);
    expect((await app.inject({ method: "POST", url: "/password/change", headers,
      payload: { current_password: "correct current password", new_password: "short" } })).statusCode).toBe(400);
    expect(db.currentVersion()).toBe(0);
    expect(db.conn.commit).not.toHaveBeenCalled();
    expect(evalCommand).toHaveBeenCalledTimes(2); // dedicated IP and account rate limits
    await app.close();
  });

  it("rate limits password-change attempts in a separate scope", async () => {
    const db = mockPool(await argon2.hash("correct current password"));
    const signingKey = await generateTestSigningKey();
    const evalCommand = vi.fn().mockResolvedValue([21, 37]);
    const app = buildApp({ pool: db.pool, redis: { eval: evalCommand } as unknown as Redis, signingKey, tokenEnv });
    await app.ready();
    const token = (await signAccessToken(userId, signingKey, tokenEnv)).token;
    const response = await app.inject({ method: "POST", url: "/password/change",
      headers: { authorization: `Bearer ${token}` },
      payload: { current_password: "correct current password", new_password: "a new secure password" } });
    expect(response.statusCode).toBe(429);
    expect(response.headers["retry-after"]).toBe("37");
    expect(evalCommand).toHaveBeenCalledOnce();
    expect(db.pool.getConnection).not.toHaveBeenCalled();
    await app.close();
  });

  it("updates only the caller's profile and validates timezone and display name", async () => {
    const hash = await argon2.hash("correct current password");
    const db = mockPool(hash);
    const signingKey = await generateTestSigningKey();
    const execute = vi.fn(async () => [{ affectedRows: 1 }, []]);
    (db.pool as unknown as { execute: typeof execute }).execute = execute;
    const app = buildApp({ pool: db.pool, redis: {} as Redis, signingKey, tokenEnv });
    await app.ready();
    const token = (await signAccessToken(userId, signingKey, tokenEnv)).token;
    const headers = { authorization: `Bearer ${token}` };

    const updated = await app.inject({ method: "PATCH", url: "/account", headers,
      payload: { display_name: "  Alice A.  ", timezone: "Asia/Seoul" } });
    expect(updated.statusCode).toBe(200);
    expect(execute).toHaveBeenCalledWith(expect.stringContaining("display_name = ?, timezone = ?"), ["Alice A.", "Asia/Seoul", userId]);
    const invalid = await app.inject({ method: "PATCH", url: "/account", headers, payload: { timezone: "Mars/Olympus_Mons" } });
    expect(invalid.statusCode).toBe(400);
    const empty = await app.inject({ method: "PATCH", url: "/account", headers, payload: { display_name: "   " } });
    expect(empty.statusCode).toBe(400);
    const extra = await app.inject({ method: "PATCH", url: "/account", headers,
      payload: { display_name: "Alice", is_admin: true } });
    expect(extra.statusCode).toBe(400);
    await app.close();
  });
});
