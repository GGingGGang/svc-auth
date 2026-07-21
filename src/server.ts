import { createDbPool } from "./db.js";
import { loadSigningKey } from "./keys.js";
import { createRedisClient } from "./redis.js";
import { buildApp } from "./router.js";

const port = Number(process.env.HTTP_PORT ?? 3000);
const version = process.env.APP_VERSION ?? "dev"; // Dockerfile 이 GIT_SHA 로 주입

async function main() {
  const pem = process.env.JWT_PRIVATE_KEY_PEM;
  if (!pem) {
    throw new Error("JWT_PRIVATE_KEY_PEM env is required");
  }

  const pool = createDbPool();
  const redis = createRedisClient();
  const signingKey = await loadSigningKey(pem);

  const app = buildApp({ pool, redis, signingKey });

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
        process.exit(0);
      } catch {
        process.exit(1);
      }
    });
  }

  try {
    await app.listen({ port, host: "0.0.0.0" });
    app.log.info(`svc-auth ${version} listening on :${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

void main();
