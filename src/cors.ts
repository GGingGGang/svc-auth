import type { FastifyInstance } from "fastify";

const defaultOrigins = "https://www.ggang.cloud";

export function registerCors(app: FastifyInstance, value = process.env.CORS_ALLOWED_ORIGINS ?? defaultOrigins): void {
  const origins = new Set(value.split(",").map((origin) => origin.trim()).filter(Boolean));

  app.addHook("onRequest", async (request, reply) => {
    const origin = request.headers.origin;
    if (!origin || !origins.has(origin)) return;

    reply.header("Access-Control-Allow-Origin", origin);
    reply.header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
    reply.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
    reply.header("Access-Control-Expose-Headers", "X-Request-ID, X-Error-ID, Retry-After");
    reply.header("Vary", "Origin");
    if (request.method === "OPTIONS") return reply.code(204).send();
  });
}
