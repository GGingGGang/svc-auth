import { buildApp } from "./router.js";

const port = Number(process.env.HTTP_PORT ?? 3000);
const version = process.env.APP_VERSION ?? "dev"; // Dockerfile 이 GIT_SHA 로 주입

const app = buildApp();

async function main() {
  try {
    await app.listen({ port, host: "0.0.0.0" });
    app.log.info(`svc-auth ${version} listening on :${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

// graceful shutdown (go-app 의 15s 미러)
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, async () => {
    app.log.info(`received ${signal}, shutting down`);
    const timer = setTimeout(() => process.exit(1), 15_000);
    timer.unref();
    try {
      await app.close();
      process.exit(0);
    } catch {
      process.exit(1);
    }
  });
}

void main();
