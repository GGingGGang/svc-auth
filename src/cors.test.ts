import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";
import { expect, it } from "vitest";

import { buildApp } from "./router.js";
import { generateTestSigningKey } from "./test-support/signing-key.js";

it("allows the configured browser origin and handles its preflight", async () => {
  const app = buildApp({ pool: {} as Pool, redis: {} as Redis, signingKey: await generateTestSigningKey() });
  await app.ready();
  const response = await app.inject({ method: "OPTIONS", url: "/login", headers: { origin: "https://www.ggang.cloud" } });
  expect(response.statusCode).toBe(204);
  expect(response.headers["access-control-allow-origin"]).toBe("https://www.ggang.cloud");
  await app.close();
});
