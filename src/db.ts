import { createPool, type Pool, type PoolOptions } from "mysql2/promise";

export interface DbConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  ssl: boolean;
  sslRejectUnauthorized: boolean;
  connectionLimit: number;
}

function parseBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return value.toLowerCase() !== "false";
}

// DB_PORT/DB_SSL/DB_SSL_REJECT_UNAUTHORIZED let the same pool code target a non-default
// port/host (local MySQL, testcontainers) without touching the HeatWave defaults below.
// sslRejectUnauthorized defaults to false because HeatWave's server cert has no IP SAN —
// full verification fails; encryption in transit still holds without it.
export function loadDbConfig(env: NodeJS.ProcessEnv = process.env): DbConfig {
  return {
    host: env.DB_HOST ?? "127.0.0.1",
    port: Number(env.DB_PORT ?? 3306),
    user: env.DB_USER ?? "root",
    password: env.DB_PASSWORD ?? "",
    database: env.DB_NAME ?? "auth",
    ssl: parseBool(env.DB_SSL, true),
    sslRejectUnauthorized: parseBool(env.DB_SSL_REJECT_UNAUTHORIZED, false),
    connectionLimit: Number(env.DB_POOL_SIZE ?? 10),
  };
}

export function createDbPool(config: DbConfig = loadDbConfig()): Pool {
  const options: PoolOptions = {
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password,
    database: config.database,
    ssl: config.ssl ? { rejectUnauthorized: config.sslRejectUnauthorized } : undefined,
    waitForConnections: true,
    connectionLimit: config.connectionLimit,
  };

  return createPool(options);
}
