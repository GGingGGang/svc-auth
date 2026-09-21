import type { FastifyReply } from "fastify";
import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";

export async function healthz() {
  return { status: "ok" };
}

export function readyz(pool: Pool, redis: Redis) {
  return async (_request: unknown, reply: FastifyReply) => {
    try {
      await Promise.all([pool.query("SELECT 1"), redis.ping()]);
      return { status: "ready" };
    } catch {
      return reply.code(503).send({ status: "not_ready" });
    }
  };
}
