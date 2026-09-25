import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { MySqlContainer, type StartedMySqlContainer } from "@testcontainers/mysql";
import { RedisContainer, type StartedRedisContainer } from "@testcontainers/redis";
import { Redis } from "ioredis";
import { createConnection, createPool, type Pool, type RowDataPacket } from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import type { LoginSecurityEnv } from "../loginSecurity.js";
import type { SigningKey } from "../keys.js";
import { buildApp } from "../router.js";
import { generateTestSigningKey } from "../test-support/signing-key.js";
import type { TokenEnv } from "../tokens.js";

const migrationSql = readFileSync(
  fileURLToPath(new URL("../../db/migrations/0001_init.up.sql", import.meta.url)),
  "utf8",
) + readFileSync(fileURLToPath(new URL("../../db/migrations/0002_login_lockout.up.sql", import.meta.url)), "utf8");

const tokenEnv: TokenEnv = { issuer: "auth.test", accessTtlSeconds: 3600, refreshTtlSeconds: 1_209_600 };

// small, fast thresholds — beforeEach flushes Redis so every test starts each
// counter at zero regardless of execution order or what earlier tests sent.
const loginSecurityEnv: LoginSecurityEnv = {
  rateLimitIpMax: 10,
  rateLimitIpWindowSeconds: 60,
  rateLimitEmailMax: 5,
  rateLimitEmailWindowSeconds: 60,
  lockoutThreshold: 3,
  lockoutWindowSeconds: 900,
  lockoutDurationSeconds: 900,
};

describe("login rate limiting + account lockout", () => {
  let mysqlContainer: StartedMySqlContainer;
  let redisContainer: StartedRedisContainer;
  let pool: Pool;
  let redis: Redis;
  let signingKey: SigningKey;
  let app: ReturnType<typeof buildApp>;

  beforeAll(async () => {
    [mysqlContainer, redisContainer] = await Promise.all([
      new MySqlContainer("mysql:8").withDatabase("auth").start(),
      new RedisContainer("redis:7").start(),
    ]);

    const setupConn = await createConnection({
      host: mysqlContainer.getHost(),
      port: mysqlContainer.getMappedPort(3306),
      user: mysqlContainer.getUsername(),
      password: mysqlContainer.getUserPassword(),
      database: mysqlContainer.getDatabase(),
      multipleStatements: true,
    });
    await setupConn.query(migrationSql);
    await setupConn.end();

    pool = createPool({
      host: mysqlContainer.getHost(),
      port: mysqlContainer.getMappedPort(3306),
      user: mysqlContainer.getUsername(),
      password: mysqlContainer.getUserPassword(),
      database: mysqlContainer.getDatabase(),
      waitForConnections: true,
      connectionLimit: 5,
    });

    redis = new Redis({ host: redisContainer.getHost(), port: redisContainer.getPort(), db: 0 });
    signingKey = await generateTestSigningKey();

    app = buildApp({ pool, redis, signingKey, tokenEnv, loginSecurityEnv });
    await app.ready();
  }, 180_000);

  afterAll(async () => {
    await app.close();
    await pool.end();
    redis.disconnect();
    await mysqlContainer.stop();
    await redisContainer.stop();
  });

  beforeEach(async () => {
    await redis.flushdb();
  });

  async function register(email: string, password = "correct horse battery staple") {
    const response = await app.inject({
      method: "POST",
      url: "/register",
      payload: { email, password, display_name: "Test User", timezone: "Asia/Seoul" },
    });
    expect(response.statusCode).toBe(201);
  }

  async function login(email: string, password: string) {
    return app.inject({ method: "POST", url: "/login", payload: { email, password } });
  }

  async function userStatus(email: string): Promise<string> {
    const [rows] = await pool.query<RowDataPacket[]>("SELECT status FROM users WHERE email = ?", [email]);
    return rows[0]?.status as string;
  }

  it("locks the account after the failed-login threshold and rejects even the correct password afterwards", async () => {
    const email = "lockout@example.com";
    const password = "correct horse battery staple";
    await register(email, password);

    // threshold - 1 failures stay plain invalid_credentials
    for (let i = 0; i < loginSecurityEnv.lockoutThreshold - 1; i++) {
      const response = await login(email, "wrong password");
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({ error: "invalid_credentials" });
    }

    // the failure that crosses the threshold sets a temporary lock, not operational status
    const lockingAttempt = await login(email, "wrong password");
    expect(lockingAttempt.statusCode).toBe(401);
    expect(lockingAttempt.json()).toEqual({ error: "account_locked" });
    expect(await userStatus(email)).toBe("active");

    // correct password no longer works once locked
    const afterLock = await login(email, password);
    expect(afterLock.statusCode).toBe(401);
    expect(afterLock.json()).toEqual({ error: "account_locked" });
  });

  it("resets the failed-login counter on a successful login", async () => {
    const email = "reset-counter@example.com";
    const password = "correct horse battery staple";
    await register(email, password);

    for (let i = 0; i < loginSecurityEnv.lockoutThreshold - 1; i++) {
      const response = await login(email, "wrong password");
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({ error: "invalid_credentials" });
    }

    const success = await login(email, password);
    expect(success.statusCode).toBe(200);

    // if the counter hadn't reset, this single failure would be the 3rd
    // cumulative one and would lock the account — it doesn't.
    const afterReset = await login(email, "wrong password");
    expect(afterReset.statusCode).toBe(401);
    expect(afterReset.json()).toEqual({ error: "invalid_credentials" });
    expect(await userStatus(email)).toBe("active");
  });

  it("automatically unlocks at the deadline and starts a fresh failure window", async () => {
    const email = "expires@example.com";
    await register(email);
    for (let i = 0; i < loginSecurityEnv.lockoutThreshold; i++) {
      await login(email, "wrong password");
    }
    await pool.execute(
      "UPDATE users SET login_locked_until = UTC_TIMESTAMP(3) WHERE email = ?",
      [email],
    );
    const firstAfterExpiry = await login(email, "wrong password");
    expect(firstAfterExpiry.json()).toEqual({ error: "invalid_credentials" });
    const success = await login(email, "correct horse battery staple");
    expect(success.statusCode).toBe(200);
  });

  it("counts simultaneous failures without losing increments", async () => {
    const email = "parallel@example.com";
    await register(email);
    const attempts = await Promise.all(Array.from({ length: loginSecurityEnv.lockoutThreshold }, () => login(email, "wrong password")));
    expect(attempts.filter((response) => response.json().error === "account_locked")).toHaveLength(1);
    const afterLock = await login(email, "correct horse battery staple");
    expect(afterLock.json()).toEqual({ error: "account_locked" });
  });

  it("returns 429 with Retry-After once the per-email login rate limit is exceeded", async () => {
    const email = "rate-limited-email@example.com";

    for (let i = 0; i < loginSecurityEnv.rateLimitEmailMax; i++) {
      const response = await login(email, "wrong password");
      expect(response.statusCode).toBe(401);
    }

    const limited = await login(email, "wrong password");
    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toEqual({ error: "rate_limited" });
    expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
  });

  it("returns 429 once the per-IP login rate limit is exceeded across different emails", async () => {
    for (let i = 0; i < loginSecurityEnv.rateLimitIpMax; i++) {
      const response = await login(`ip-rate-limit-${i}@example.com`, "wrong password");
      expect(response.statusCode).toBe(401);
    }

    const limited = await login("ip-rate-limit-overflow@example.com", "wrong password");
    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toEqual({ error: "rate_limited" });
  });

  it("ignores forwarded IP headers from an untrusted peer", async () => {
    for (let i = 0; i < loginSecurityEnv.rateLimitIpMax; i++) {
      const response = await app.inject({
        method: "POST", url: "/login", remoteAddress: "192.0.2.10",
        headers: { "x-forwarded-for": `198.51.100.${i + 1}` },
        payload: { email: `spoof-${i}@example.com`, password: "wrong password" },
      });
      expect(response.statusCode).toBe(401);
    }
    const limited = await app.inject({
      method: "POST", url: "/login", remoteAddress: "192.0.2.10",
      headers: { "x-forwarded-for": "198.51.100.200" },
      payload: { email: "spoof-overflow@example.com", password: "wrong password" },
    });
    expect(limited.statusCode).toBe(429);
    expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
  });

  it("repairs a legacy rate-limit key without an expiry", async () => {
    const ip = "192.0.2.50";
    const key = `auth:loginrl:ip:${ip}`;
    await redis.set(key, String(loginSecurityEnv.rateLimitIpMax));
    expect(await redis.ttl(key)).toBe(-1);

    const response = await app.inject({
      method: "POST", url: "/login", remoteAddress: ip,
      payload: { email: "expired-key@example.com", password: "wrong password" },
    });
    expect(response.statusCode).toBe(429);
    expect(Number(response.headers["retry-after"])).toBeGreaterThan(0);
    expect(await redis.ttl(key)).toBeGreaterThan(0);
  });

  it("keeps an established session usable during a temporary login lock", async () => {
    const email = "existing-session@example.com";
    await register(email);
    const existing = (await login(email, "correct horse battery staple")).json() as { access_token: string; refresh_token: string };
    for (let i = 0; i < loginSecurityEnv.lockoutThreshold; i++) await login(email, "wrong password");

    const introspect = await app.inject({ method: "GET", url: "/introspect", headers: { authorization: `Bearer ${existing.access_token}` } });
    expect(introspect.statusCode).toBe(200);
    expect(introspect.json()).toEqual({ active: true });
    const refresh = await app.inject({ method: "POST", url: "/refresh", payload: { refresh_token: existing.refresh_token } });
    expect(refresh.statusCode).toBe(200);
  });

  it("checks current account status when an old access token is retried", async () => {
    const email = "status-changed@example.com";
    await register(email);
    const existing = (await login(email, "correct horse battery staple")).json() as { access_token: string; refresh_token: string };
    await pool.execute("UPDATE users SET status = 'deleted' WHERE email = ?", [email]);

    const introspect = await app.inject({ method: "GET", url: "/introspect", headers: { authorization: `Bearer ${existing.access_token}` } });
    expect(introspect.statusCode).toBe(401);
    expect(introspect.json()).toEqual({ error: "unauthorized" });
    const refresh = await app.inject({ method: "POST", url: "/refresh", payload: { refresh_token: existing.refresh_token } });
    expect(refresh.statusCode).toBe(401);
  });
});
