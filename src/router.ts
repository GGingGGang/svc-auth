import Fastify, { type FastifyInstance } from "fastify";
import { collectDefaultMetrics, register } from "prom-client";

import { healthz, readyz } from "./health.js";

// Node/프로세스 런타임 기본 메트릭 등록 (go-app promhttp 대응)
collectDefaultMetrics();

export function buildApp(): FastifyInstance {
  const app = Fastify({ logger: true });

  app.get("/healthz", healthz);
  app.get("/readyz", readyz);
  app.get("/metrics", async (_req, reply) => {
    reply.header("Content-Type", register.contentType);
    return register.metrics();
  });

  return app;
}
