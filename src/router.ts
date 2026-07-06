import Fastify, { type FastifyInstance } from "fastify";
import type { Pool } from "mysql2/promise";
import { collectDefaultMetrics, register } from "prom-client";

import { createDbPool } from "./db.js";
import { healthz, readyz } from "./health.js";
import { registerRoutes } from "./routes/register.js";

// Node/프로세스 런타임 기본 메트릭 등록 (go-app promhttp 대응)
collectDefaultMetrics();

export interface BuildAppOptions {
  pool?: Pool;
}

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? "info",
      base: { service: "auth" },
      messageKey: "msg",
      formatters: {
        level(label) {
          return { level: label.toUpperCase() };
        },
      },
      timestamp: () => `,"ts":"${new Date().toISOString()}"`,
    },
  });

  const pool = options.pool ?? createDbPool();

  app.get("/healthz", healthz);
  app.get("/readyz", readyz);
  app.get("/metrics", async (_req, reply) => {
    reply.header("Content-Type", register.contentType);
    return register.metrics();
  });

  app.register(registerRoutes, { pool });

  return app;
}
