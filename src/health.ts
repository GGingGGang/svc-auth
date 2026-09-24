import type { FastifyReply } from "fastify";
import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";

export async function healthz() {
  return { status: "ok" };
}

export function readyz(pool: Pool, redis: Redis) {
  return async (_request: unknown, reply: FastifyReply) => {
    const [db, cache] = await Promise.allSettled([pool.query("SELECT 1"), redis.ping()]);
    if (db.status === "rejected") return reply.code(503).send({ status: "not_ready", database: "unavailable", sessions: cache.status === "fulfilled" ? "ready" : "unavailable" });
    if (cache.status === "rejected") return { status: "partial", database: "ready", sessions: "unavailable" };
    return { status: "ready", database: "ready", sessions: "ready" };
  };
}
