import { createHash, randomBytes, randomUUID } from "node:crypto";

import type { Redis } from "ioredis";
import { SignJWT } from "jose";

import type { SigningKey } from "./keys.js";

export interface TokenEnv {
  issuer: string;
  accessTtlSeconds: number;
  refreshTtlSeconds: number;
}

export function loadTokenEnv(env: NodeJS.ProcessEnv = process.env): TokenEnv {
  return {
    issuer: env.JWT_ISSUER ?? "auth.local",
    accessTtlSeconds: Number(env.ACCESS_TTL ?? 3600),
    refreshTtlSeconds: Number(env.REFRESH_TTL ?? 1209600),
  };
}

const ACCESS_SCOPE = "read:schedules write:schedules";

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

interface RefreshRecord {
  user_id: string;
  family_id: string;
  issued_at: string;
  consumed: boolean;
}

function refreshKey(hash: string): string {
  return `auth:refresh:${hash}`;
}

function familyKey(familyId: string): string {
  return `auth:rtfam:${familyId}`;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export async function signAccessToken(
  userId: string,
  signingKey: SigningKey,
  tokenEnv: TokenEnv,
): Promise<{ token: string; expiresIn: number }> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + tokenEnv.accessTtlSeconds;

  const token = await new SignJWT({ scope: ACCESS_SCOPE })
    .setProtectedHeader({ alg: "ES256", kid: signingKey.kid })
    .setIssuer(tokenEnv.issuer)
    .setSubject(userId)
    .setAudience(["core"])
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .setJti(randomUUID())
    .sign(signingKey.privateKey);

  return { token, expiresIn: tokenEnv.accessTtlSeconds };
}

async function storeRefreshToken(
  redis: Redis,
  record: RefreshRecord,
  hash: string,
  ttlSeconds: number,
): Promise<void> {
  await redis.set(refreshKey(hash), JSON.stringify(record), "EX", ttlSeconds);
  await redis.sadd(familyKey(record.family_id), hash);
  await redis.expire(familyKey(record.family_id), ttlSeconds);
}

export interface IssueTokenPairParams {
  redis: Redis;
  signingKey: SigningKey;
  tokenEnv: TokenEnv;
  userId: string;
  familyId?: string;
}

// Fresh login starts a new family; rotation (rotateRefreshToken below) reuses
// the caller's familyId so every descendant token stays revocable as a unit.
export async function issueTokenPair(params: IssueTokenPairParams): Promise<TokenPair> {
  const { redis, signingKey, tokenEnv, userId } = params;
  const familyId = params.familyId ?? randomUUID();
  const refreshToken = randomBytes(32).toString("base64url");
  const hash = hashToken(refreshToken);

  const record: RefreshRecord = {
    user_id: userId,
    family_id: familyId,
    issued_at: new Date().toISOString(),
    consumed: false,
  };
  await storeRefreshToken(redis, record, hash, tokenEnv.refreshTtlSeconds);

  const access = await signAccessToken(userId, signingKey, tokenEnv);
  return { accessToken: access.token, refreshToken, expiresIn: access.expiresIn };
}

export type RefreshResult =
  | { ok: true; pair: TokenPair }
  | { ok: false; reason: "invalid" | "reuse_detected" };

export interface RotateRefreshTokenParams {
  redis: Redis;
  signingKey: SigningKey;
  tokenEnv: TokenEnv;
  refreshToken: string;
}

// One-time use: the record is marked consumed (not deleted outright) so a
// second attempt with the same token is recognizable as reuse rather than
// looking identical to an unknown/expired token — that recognition is what
// lets reuse trigger a full family revocation instead of a plain 401.
export async function rotateRefreshToken(params: RotateRefreshTokenParams): Promise<RefreshResult> {
  const { redis, signingKey, tokenEnv, refreshToken } = params;
  const hash = hashToken(refreshToken);
  const raw = await redis.get(refreshKey(hash));
  if (!raw) {
    return { ok: false, reason: "invalid" };
  }

  const record = JSON.parse(raw) as RefreshRecord;
  if (record.consumed) {
    await revokeFamily(redis, record.family_id);
    return { ok: false, reason: "reuse_detected" };
  }

  record.consumed = true;
  await redis.set(refreshKey(hash), JSON.stringify(record), "KEEPTTL");

  const pair = await issueTokenPair({
    redis,
    signingKey,
    tokenEnv,
    userId: record.user_id,
    familyId: record.family_id,
  });
  return { ok: true, pair };
}

export async function revokeFamily(redis: Redis, familyId: string): Promise<void> {
  const members = await redis.smembers(familyKey(familyId));
  if (members.length > 0) {
    await redis.del(...members.map(refreshKey));
  }
  await redis.del(familyKey(familyId));
}

export async function logoutByRefreshToken(redis: Redis, refreshToken: string): Promise<void> {
  const hash = hashToken(refreshToken);
  const raw = await redis.get(refreshKey(hash));
  if (!raw) return;

  const record = JSON.parse(raw) as RefreshRecord;
  await revokeFamily(redis, record.family_id);
}
