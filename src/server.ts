import { createDbPool } from "./db.js";
import { loadSigningKey } from "./keys.js";
import { migrateUp } from "./migrate.js";
import { shutdownTracing } from "./observability/tracing.js";
import { createRedisClient } from "./redis.js";
import { buildApp } from "./router.js";

const port = Number(process.env.HTTP_PORT ?? 3000);
const version = process.env.APP_VERSION ?? "dev"; // Dockerfile 이 GIT_SHA 로 주입

async function main() {
  const pem = process.env.JWT_PRIVATE_KEY_PEM;
  if (!pem) {
    throw new Error("JWT_PRIVATE_KEY_PEM env is required");
  }

  await migrateUp();

  const pool = createDbPool();
  const redis = createRedisClient();
  const signingKey = await loadSigningKey(pem);

  // JWT_SECONDARY_KEY_PEM is optional and only ever published in JWKS, never
  // signed with — it's the "kid 2개 공존" rotation slot (../PLAN.md §6):
  // holds the next key ahead of a cutover, then the retiring key until its
  // already-issued tokens expire. Absent outside a rotation window.
  const secondaryPem = process.env.JWT_SECONDARY_KEY_PEM;
  const secondaryKey = secondaryPem ? await loadSigningKey(secondaryPem) : undefined;

  const app = buildApp({ pool, redis, signingKey, secondaryKey });

  // graceful shutdown (go-app 의 15s 미러)
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.on(signal, async () => {
      app.log.info(`received ${signal}, shutting down`);
      const timer = setTimeout(() => process.exit(1), 15_000);
      timer.unref();
      try {
        await app.close();
        await pool.end();
        redis.disconnect();
        await shutdownTracing();
        process.exit(0);
      } catch {
        process.exit(1);
      }
    });
  }

  try {
    await app.listen({ port, host: "0.0.0.0" });
    app.log.info(`svc-auth ${version} listening on :${port}`);
  } catch {
    app.log.error({ error_code: "startup_failed" }, "startup failed");
    process.exit(1);
  }
}

void main().catch(() => {
  console.error("startup_failed");
  process.exit(1);
});
