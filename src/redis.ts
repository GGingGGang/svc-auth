import { Redis } from "ioredis";

export interface RedisConfig {
  host: string;
  port: number;
  db: number;
}

// REDIS_ADDR is host:port (matches svc-auth/PLAN.md §8 env naming), split here
// rather than accepting a redis:// URL so it lines up 1:1 with the k8s Service DNS.
export function loadRedisConfig(env: NodeJS.ProcessEnv = process.env): RedisConfig {
  const addr = env.REDIS_ADDR ?? "127.0.0.1:6379";
  const [host, portStr] = addr.split(":");

  return {
    host: host || "127.0.0.1",
    port: Number(portStr ?? 6379),
    db: Number(env.REDIS_DB ?? 0),
  };
}

export function createRedisClient(config: RedisConfig = loadRedisConfig()): Redis {
  return new Redis({
    host: config.host,
    port: config.port,
    db: config.db,
  });
}
