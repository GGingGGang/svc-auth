import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";
import { describe, expect, it, vi } from "vitest";

import { buildApp } from "./router.js";
import { generateTestSigningKey } from "./test-support/signing-key.js";
import { signAccessToken } from "./tokens.js";

// buildApp() never touches the pool/redis unless a route handler actually
// queries them — none of the routes exercised below do, so stubs are enough
// here. signingKey still has to be a real ES256 key since fastify/swagger
// reads it while building the schema-derived OpenAPI spec.
const stubPool = {} as Pool;
const stubRedis = {} as Redis;

describe("OpenAPI spec", () => {
  it("checks current account status on every introspection and revokes refresh after deletion", async () => {
    const signingKey = await generateTestSigningKey();
    const tokenEnv = { issuer: "auth.test", accessTtlSeconds: 3600, refreshTtlSeconds: 1209600 };
    const userId = "01993d8e-e9d1-7068-9123-000000000001";
    let status = "active";
    const query = vi.fn(async () => [[{ status }], []]);
    const evalCommand = vi.fn().mockResolvedValue(1);
    const get = vi.fn().mockResolvedValue(JSON.stringify({ user_id: userId, family_id: "family-1", consumed: false }));
    const app = buildApp({
      pool: { query } as unknown as Pool,
      redis: { eval: evalCommand, get } as unknown as Redis,
      signingKey, tokenEnv,
    });
    await app.ready();
    const token = (await signAccessToken(userId, signingKey, tokenEnv)).token;
    const headers = { authorization: `Bearer ${token}` };

    expect((await app.inject({ method: "GET", url: "/introspect", headers })).json()).toEqual({ active: true });
    status = "deleted";
    const inactive = await app.inject({ method: "GET", url: "/introspect", headers });
    expect(inactive.statusCode).toBe(401);
    expect(inactive.headers["cache-control"]).toBe("no-store");
    expect(query).toHaveBeenCalledTimes(2);

    const sessions = await app.inject({ method: "GET", url: "/sessions", headers });
    expect(sessions.statusCode).toBe(401);
    query.mockRejectedValueOnce(new Error("database unavailable"));
    const unavailable = await app.inject({ method: "GET", url: "/introspect", headers });
    expect(unavailable.statusCode).toBe(503);

    const refresh = await app.inject({ method: "POST", url: "/refresh", payload: { refresh_token: "old-token" } });
    expect(refresh.statusCode).toBe(401);
    expect(evalCommand).toHaveBeenCalledTimes(1);
    await app.close();
  });

  it("keeps the old refresh token usable when the account-status query fails", async () => {
    const signingKey = await generateTestSigningKey();
    const userId = "01993d8e-e9d1-7068-9123-000000000002";
    const tokenEnv = { issuer: "auth.test", accessTtlSeconds: 3600, refreshTtlSeconds: 1209600 };
    const query = vi.fn().mockRejectedValueOnce(new Error("temporary database outage"))
      .mockResolvedValue([[{ status: "active" }], []]);
    const get = vi.fn().mockResolvedValue(JSON.stringify({ user_id: userId, family_id: "family-2", consumed: false }));
    const evalCommand = vi.fn().mockResolvedValue([1, userId]);
    const app = buildApp({ pool: { query } as unknown as Pool,
      redis: { get, eval: evalCommand } as unknown as Redis, signingKey, tokenEnv });
    await app.ready();

    const payload = { refresh_token: "same-old-token" };
    expect((await app.inject({ method: "POST", url: "/refresh", payload })).statusCode).toBe(500);
    expect(evalCommand).not.toHaveBeenCalled();
    expect((await app.inject({ method: "POST", url: "/refresh", payload })).statusCode).toBe(200);
    expect(evalCommand).toHaveBeenCalledTimes(1);
    await app.close();
  });

  it("trusts forwarded IPs only from configured proxies and returns a safe error ID", async () => {
    vi.stubEnv("TRUSTED_PROXY_CIDRS", "10.244.0.0/16");
    try {
      const signingKey = await generateTestSigningKey();
      const app = buildApp({ pool: stubPool, redis: stubRedis, signingKey });
      const ips: string[] = [];
      app.get("/test-error", async (req) => {
        ips.push(req.ip);
        throw new Error("private@example.com password=secret");
      });
      await app.ready();

      for (const remoteAddress of ["10.244.0.92", "203.0.113.7"]) {
        const response = await app.inject({
          method: "GET", url: "/test-error", remoteAddress,
          headers: { "x-forwarded-for": "198.51.100.8" },
        });
        expect(response.statusCode).toBe(500);
        expect(response.json()).toEqual({ error: "internal_error" });
        expect(response.headers["x-error-id"]).toMatch(/^[0-9a-f]{32}$/);
      }
      expect(ips).toEqual(["198.51.100.8", "203.0.113.7"]);
      await app.close();
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("rejects overlong normalized login email before Redis or DB access", async () => {
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: stubPool, redis: stubRedis, signingKey });
    await app.ready();

    const response = await app.inject({
      method: "POST", url: "/login",
      payload: { email: ` ${"a".repeat(317)}@x.io `, password: "correct horse battery staple" },
    });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "invalid_credentials" });
    await app.close();
  });

  it("rejects invalid registration fields before writing a user", async () => {
    const execute = vi.fn();
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: { execute } as unknown as Pool, redis: stubRedis, signingKey });
    await app.ready();

    const valid = { email: "alice@example.com", password: "123456789012", display_name: "Alice", timezone: "UTC" };
    for (const payload of [
      { ...valid, email: ` ${"a".repeat(317)}@x.io ` },
      { ...valid, email: "alice at example.com" },
      { ...valid, email: "alice@example..com" },
      { ...valid, password: "😀".repeat(11) },
      { ...valid, password: "😀".repeat(129) },
      { ...valid, display_name: "  " },
      { ...valid, display_name: ` ${"😀".repeat(101)} ` },
    ]) {
      const response = await app.inject({ method: "POST", url: "/register", payload });
      expect(response.statusCode).toBe(400);
    }
    expect(execute).not.toHaveBeenCalled();
    await app.close();
  });

  it("rejects an invalid registration timezone before writing a user", async () => {
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: stubPool, redis: stubRedis, signingKey });
    await app.ready();

    const response = await app.inject({
      method: "POST",
      url: "/register",
      payload: {
        email: "alice@example.com",
        password: "correct horse battery staple",
        display_name: "Alice",
        timezone: "Mars/Olympus_Mons",
      },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json().message).toBe("Invalid timezone");
    await app.close();
  });

  it("lists exactly the implemented endpoints, no more, no less", async () => {
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: stubPool, redis: stubRedis, signingKey });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/openapi.json" });
    expect(response.statusCode).toBe(200);

    const spec = response.json();
    expect(spec.openapi).toBe("3.0.0");
    expect(Object.keys(spec.paths).sort()).toEqual([
      "/.well-known/jwks.json",
      "/healthz",
      "/introspect",
      "/login",
      "/logout",
      "/metrics",
      "/readyz",
      "/refresh",
      "/register",
      "/sessions",
      "/sessions/{familyId}",
    ]);

    await app.close();
  });

  it("serves the swagger UI at /documentation", async () => {
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: stubPool, redis: stubRedis, signingKey });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/documentation" });
    expect(response.statusCode).toBe(200);

    await app.close();
  });
});
