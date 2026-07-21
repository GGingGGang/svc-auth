import type { Pool } from "mysql2/promise";
import { describe, expect, it } from "vitest";

import { buildApp } from "./router.js";

// buildApp() never touches the pool unless a route handler actually queries
// the DB — none of the routes exercised below do, so a stub is enough here.
const stubPool = {} as Pool;

describe("OpenAPI spec", () => {
  it("lists exactly the implemented endpoints, no more, no less", async () => {
    const app = buildApp({ pool: stubPool });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/openapi.json" });
    expect(response.statusCode).toBe(200);

    const spec = response.json();
    expect(spec.openapi).toBe("3.0.0");
    expect(Object.keys(spec.paths).sort()).toEqual(["/healthz", "/metrics", "/readyz", "/register"]);

    await app.close();
  });

  it("serves the swagger UI at /documentation", async () => {
    const app = buildApp({ pool: stubPool });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/documentation" });
    expect(response.statusCode).toBe(200);

    await app.close();
  });
});
