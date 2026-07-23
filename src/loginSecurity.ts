import { createHash } from "node:crypto";

import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";

// Login-specific brute-force defenses (../PLAN.md 3M turn): a short-window
// rate limit backed by Redis DB0 counters, plus a longer-window failed-login
// counter that escalates into a persisted users.status = 'locked' lock.
export interface LoginSecurityEnv {
  rateLimitIpMax: number;
  rateLimitIpWindowSeconds: number;
  rateLimitEmailMax: number;
  rateLimitEmailWindowSeconds: number;
  lockoutThreshold: number;
  lockoutWindowSeconds: number;
}

export function loadLoginSecurityEnv(env: NodeJS.ProcessEnv = process.env): LoginSecurityEnv {
  return {
    rateLimitIpMax: Number(env.LOGIN_RATE_LIMIT_IP_MAX ?? 20),
    rateLimitIpWindowSeconds: Number(env.LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS ?? 60),
    rateLimitEmailMax: Number(env.LOGIN_RATE_LIMIT_EMAIL_MAX ?? 10),
    rateLimitEmailWindowSeconds: Number(env.LOGIN_RATE_LIMIT_EMAIL_WINDOW_SECONDS ?? 60),
    lockoutThreshold: Number(env.LOGIN_LOCKOUT_THRESHOLD ?? 5),
    lockoutWindowSeconds: Number(env.LOGIN_LOCKOUT_WINDOW_SECONDS ?? 900),
  };
}

// email is hashed before it ever touches a Redis key — same treatment as
// refresh tokens in tokens.ts, and keeps raw email out of Redis (§8.1 PII rule
// is about logs/metrics/spans, but there is no reason to widen the footprint).
function hashEmail(email: string): string {
  return createHash("sha256").update(email.toLowerCase()).digest("hex");
}

export type RateLimitResult = { limited: false } | { limited: true; retryAfterSeconds: number };

// Fixed-window counter: INCR both creates and bumps the key atomically: only
// the request that takes it from 0 to 1 arms the window's TTL, so later hits
// in the same window don't keep pushing the expiry out.
async function hitWindow(redis: Redis, key: string, max: number, windowSeconds: number): Promise<RateLimitResult> {
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, windowSeconds);
  }
  if (count <= max) {
    return { limited: false };
  }

  const ttl = await redis.ttl(key);
  return { limited: true, retryAfterSeconds: ttl > 0 ? ttl : windowSeconds };
}

// Checked in this order (IP first) so a single attacker spraying many emails
// from one address is capped even though each individual email stays under
// its own limit.
export async function checkLoginRateLimit(
  redis: Redis,
  env: LoginSecurityEnv,
  ip: string,
  email: string,
): Promise<RateLimitResult> {
  const byIp = await hitWindow(redis, `auth:loginrl:ip:${ip}`, env.rateLimitIpMax, env.rateLimitIpWindowSeconds);
  if (byIp.limited) {
    return byIp;
  }

  return hitWindow(
    redis,
    `auth:loginrl:email:${hashEmail(email)}`,
    env.rateLimitEmailMax,
    env.rateLimitEmailWindowSeconds,
  );
}

function lockoutKey(userId: string): string {
  return `auth:loginfail:${userId}`;
}

export async function resetFailedLogins(redis: Redis, userId: string): Promise<void> {
  await redis.del(lockoutKey(userId));
}

// Failed attempts accumulate in a short-lived Redis counter; once the
// threshold is crossed the lock is written to users.status so it survives the
// counter's TTL and is immediately visible to every auth replica (no
// cross-instance Redis-only state for something this security-sensitive).
export async function recordFailedLogin(
  pool: Pool,
  redis: Redis,
  env: LoginSecurityEnv,
  userId: Buffer,
  userIdStr: string,
): Promise<{ locked: boolean }> {
  const key = lockoutKey(userIdStr);
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, env.lockoutWindowSeconds);
  }
  if (count < env.lockoutThreshold) {
    return { locked: false };
  }

  await pool.execute("UPDATE users SET status = 'locked' WHERE id = ? AND status = 'active'", [userId]);
  await redis.del(key);
  return { locked: true };
}
