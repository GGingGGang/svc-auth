import { describe, expect, it } from "vitest";
import type { Pool } from "mysql2/promise";
import type { Redis } from "ioredis";
import { buildApp } from "./router.js";
import { generateTestSigningKey } from "./test-support/signing-key.js";
import { authHttpMetrics, resetHttpMetricsForTest } from "./httpMetrics.js";

it("records bounded method, route-template, and status labels", async () => {
  resetHttpMetricsForTest();
  const app = buildApp({ pool: {} as Pool, redis: {} as Redis, signingKey: await generateTestSigningKey() });
  await app.ready();
  await app.inject({ method: "GET", url: "/healthz" });
  const values = await authHttpMetrics().requests.get();
  expect(values.values).toContainEqual(expect.objectContaining({ labels: { method: "GET", route: "/healthz", status_code: "200" }, value: 1 }));
  await app.close();
});
