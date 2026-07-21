import fastifySwagger from "@fastify/swagger";
import fastifySwaggerUi from "@fastify/swagger-ui";
import Fastify, { type FastifyInstance } from "fastify";
import type { Pool } from "mysql2/promise";
import { collectDefaultMetrics, register } from "prom-client";

import { createDbPool } from "./db.js";
import { healthz, readyz } from "./health.js";
import { registerRoutes } from "./routes/register.js";

const okResponseSchema = {
  type: "object",
  properties: { status: { type: "string" } },
  required: ["status"],
} as const;

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
  const version = process.env.APP_VERSION ?? "dev";

  app.register(fastifySwagger, {
    openapi: {
      openapi: "3.0.0",
      info: {
        title: "svc-auth",
        description: "사용자 등록 / 인증 / 세션 / 토큰 발급 서비스.",
        version,
      },
      servers: [{ url: "http://auth.auth.svc.cluster.local:3000" }],
      tags: [
        { name: "auth", description: "사용자 등록 / 인증" },
        { name: "ops", description: "probe / metrics" },
      ],
    },
  });
  app.register(fastifySwaggerUi, { routePrefix: "/documentation" });

  // routes are added inside .after() so they register once the swagger plugins
  // above have finished loading and their onRoute hook is capturing schemas —
  // a plain app.get() called before that point would boot synchronously and
  // be invisible to the generated spec.
  app.after(() => {
    app.get("/openapi.json", { schema: { hide: true } }, async () => app.swagger());

    app.get(
      "/healthz",
      { schema: { tags: ["ops"], summary: "Liveness probe", response: { 200: okResponseSchema } } },
      healthz,
    );
    app.get(
      "/readyz",
      { schema: { tags: ["ops"], summary: "Readiness probe", response: { 200: okResponseSchema } } },
      readyz,
    );
    app.get(
      "/metrics",
      { schema: { tags: ["ops"], summary: "Prometheus metrics" } },
      async (_req, reply) => {
        reply.header("Content-Type", register.contentType);
        return register.metrics();
      },
    );

    app.register(registerRoutes, { pool });
  });

  return app;
}
