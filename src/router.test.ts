import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";
import { describe, expect, it } from "vitest";

import { buildApp } from "./router.js";
import { generateTestSigningKey } from "./test-support/signing-key.js";

// buildApp() never touches the pool/redis unless a route handler actually
// queries them — none of the routes exercised below do, so stubs are enough
// here. signingKey still has to be a real ES256 key since fastify/swagger
// reads it while building the schema-derived OpenAPI spec.
const stubPool = {} as Pool;
const stubRedis = {} as Redis;

describe("OpenAPI spec", () => {
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
      "/login",
      "/logout",
      "/metrics",
      "/readyz",
      "/refresh",
      "/register",
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
