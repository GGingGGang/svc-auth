import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { MySqlContainer, type StartedMySqlContainer } from "@testcontainers/mysql";
import { RedisContainer, type StartedRedisContainer } from "@testcontainers/redis";
import { Redis } from "ioredis";
import { importJWK, jwtVerify } from "jose";
import { createConnection, createPool, type Pool } from "mysql2/promise";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { SigningKey } from "../keys.js";
import { buildApp } from "../router.js";
import { generateTestSigningKey } from "../test-support/signing-key.js";
import type { TokenEnv } from "../tokens.js";

const migrationSql = readFileSync(
  fileURLToPath(new URL("../../db/migrations/0001_init.up.sql", import.meta.url)),
  "utf8",
);

const tokenEnv: TokenEnv = { issuer: "auth.test", accessTtlSeconds: 3600, refreshTtlSeconds: 1_209_600 };

describe("login -> refresh (rotation) -> reuse detection -> logout", () => {
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

    app = buildApp({ pool, redis, signingKey, tokenEnv });
    await app.ready();
  }, 180_000);

  afterAll(async () => {
    await app.close();
    await pool.end();
    redis.disconnect();
    await mysqlContainer.stop();
    await redisContainer.stop();
  });

  const credentials = {
    email: "carol@example.com",
    password: "correct horse battery staple",
    display_name: "Carol",
    timezone: "Asia/Seoul",
  };

  async function login() {
    const response = await app.inject({ method: "POST", url: "/login", payload: credentials });
    expect(response.statusCode).toBe(200);
    return response.json() as { access_token: string; refresh_token: string; token_type: string; expires_in: number };
  }

  it("registers the user used across this flow", async () => {
    const response = await app.inject({ method: "POST", url: "/register", payload: credentials });
    expect(response.statusCode).toBe(201);
  });

  it("rejects login with a wrong password", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/login",
      payload: { email: credentials.email, password: "wrong password" },
    });
    expect(response.statusCode).toBe(401);
  });

  it("logs in and returns an access+refresh token pair", async () => {
    const body = await login();
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(tokenEnv.accessTtlSeconds);
    expect(typeof body.access_token).toBe("string");
    expect(typeof body.refresh_token).toBe("string");
  });

  it("exposes JWKS with Cache-Control and a key whose kid matches the signing key", async () => {
    const response = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("max-age=3600");

    const jwks = response.json() as { keys: Array<Record<string, unknown>> };
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]?.kid).toBe(signingKey.kid);
    expect(jwks.keys[0]?.d).toBeUndefined(); // public key only, no private exponent
  });

  it("issues an access token that verifies against the JWKS public key (core's verification path)", async () => {
    const { access_token: accessToken } = await login();

    const jwksResponse = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    const jwks = jwksResponse.json() as { keys: Array<Record<string, unknown>> };
    const publicKey = await importJWK(jwks.keys[0] as Parameters<typeof importJWK>[0], "ES256");

    const { payload, protectedHeader } = await jwtVerify(accessToken, publicKey, {
      issuer: tokenEnv.issuer,
      audience: "core",
    });

    expect(protectedHeader.kid).toBe(signingKey.kid);
    expect(payload.scope).toBe("read:schedules write:schedules");
    expect(typeof payload.sub).toBe("string");
    expect(typeof payload.jti).toBe("string");
  });

  it("rotates the refresh token on use and revokes the whole family on reuse", async () => {
    const { refresh_token: firstRefresh } = await login();

    const rotated = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refresh_token: firstRefresh },
    });
    expect(rotated.statusCode).toBe(200);
    const rotatedBody = rotated.json() as { access_token: string; refresh_token: string };
    expect(rotatedBody.refresh_token).not.toBe(firstRefresh);

    // reuse of the already-consumed token must be detected and revoke the family
    const reuse = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refresh_token: firstRefresh },
    });
    expect(reuse.statusCode).toBe(401);
    expect(reuse.json()).toEqual({ error: "refresh_reuse_detected" });

    // the descendant token from the legitimate rotation is now revoked too (family-wide)
    const descendantAfterRevocation = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refresh_token: rotatedBody.refresh_token },
    });
    expect(descendantAfterRevocation.statusCode).toBe(401);
    expect(descendantAfterRevocation.json()).toEqual({ error: "invalid_refresh_token" });
  });

  it("rejects an unknown refresh token", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refresh_token: "not-a-real-token" },
    });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "invalid_refresh_token" });
  });

  it("logout revokes the family so the refresh token can no longer be used", async () => {
    const { refresh_token: refreshToken } = await login();

    const logoutResponse = await app.inject({
      method: "POST",
      url: "/logout",
      payload: { refresh_token: refreshToken },
    });
    expect(logoutResponse.statusCode).toBe(204);

    const afterLogout = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refresh_token: refreshToken },
    });
    expect(afterLogout.statusCode).toBe(401);
  });

  it("logout is idempotent for an unknown refresh token", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/logout",
      payload: { refresh_token: "never-issued" },
    });
    expect(response.statusCode).toBe(204);
  });
});
