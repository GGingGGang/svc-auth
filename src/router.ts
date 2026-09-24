import fastifySwagger from "@fastify/swagger";
import fastifySwaggerUi from "@fastify/swagger-ui";
import Fastify, { LogController, type FastifyError, type FastifyInstance } from "fastify";
import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";
import { collectDefaultMetrics, register } from "prom-client";

import { createDbPool } from "./db.js";
import { registerCors } from "./cors.js";
import { healthz, readyz } from "./health.js";
import type { SigningKey } from "./keys.js";
import { loadLoginSecurityEnv, type LoginSecurityEnv } from "./loginSecurity.js";
import { registerHttpTracing } from "./observability/httpTracing.js";
import { jwksRoutes } from "./routes/jwks.js";
import { loginRoutes } from "./routes/login.js";
import { logoutRoutes } from "./routes/logout.js";
import { refreshRoutes } from "./routes/refresh.js";
import { registerRoutes } from "./routes/register.js";
import { sessionsRoutes } from "./routes/sessions.js";
import { loadTokenEnv, type TokenEnv } from "./tokens.js";

const okResponseSchema = {
  type: "object",
  properties: { status: { type: "string" }, database: { type: "string" }, sessions: { type: "string" } },
  required: ["status"],
} as const;

// Node/프로세스 런타임 기본 메트릭 등록 (go-app promhttp 대응)
collectDefaultMetrics();

export interface BuildAppOptions {
  pool?: Pool;
  redis: Redis;
  signingKey: SigningKey;
  // secondaryKey, if set, is published in JWKS alongside signingKey but
  // never used to sign — see JwksRouteOptions in routes/jwks.ts for the
  // rotation runbook this backs (../PLAN.md §6 "kid 2개 공존").
  secondaryKey?: SigningKey;
  tokenEnv?: TokenEnv;
  loginSecurityEnv?: LoginSecurityEnv;
}

export function buildApp(options: BuildAppOptions): FastifyInstance {
  const trustedProxies = process.env.TRUSTED_PROXY_CIDRS?.split(",").map((cidr) => cidr.trim()).filter(Boolean);
  const app = Fastify({
    trustProxy: trustedProxies?.length ? trustedProxies : false,
    logController: new LogController({ disableRequestLogging: true }),
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
  const { redis, signingKey, secondaryKey } = options;
  const tokenEnv = options.tokenEnv ?? loadTokenEnv();
  const loginSecurityEnv = options.loginSecurityEnv ?? loadLoginSecurityEnv();
  const version = process.env.APP_VERSION ?? "dev";

  registerCors(app);
  registerHttpTracing(app);

  app.setErrorHandler((error, req, reply) => {
    const failure = error as FastifyError;
    const status = failure.statusCode && failure.statusCode < 500 ? failure.statusCode : 500;
    req.log.error({ error_code: failure.code, status_code: status }, "request failed");
    return reply.code(status).send({ error: status === 500 ? "internal_error" : "invalid_request" });
  });

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
      readyz(pool, redis),
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
    app.register(loginRoutes, { pool, redis, signingKey, tokenEnv, loginSecurityEnv });
    app.register(refreshRoutes, { redis, signingKey, tokenEnv });
    app.register(logoutRoutes, { redis });
    app.register(jwksRoutes, { signingKey, secondaryKey });
    app.register(sessionsRoutes, { redis, signingKey, secondaryKey, tokenEnv });
  });

  return app;
}
