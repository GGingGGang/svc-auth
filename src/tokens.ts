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
  credential_version: number;
}

// SessionRecord is the 5M session-management addition (../PLAN.md §7 "세션
// 관리 API") — one row per refresh family, i.e. per login ("device"). It's
// metadata alongside the family, not a replacement for it: RefreshRecord
// stays the source of truth for whether a specific refresh token is valid.
interface SessionRecord {
  user_id: string;
  created_at: string; // first login that started this family — never changes across rotations
  last_active_at: string; // bumped on every rotation
  credential_version: number;
}

export interface SessionSummary {
  family_id: string;
  created_at: string;
  last_active_at: string;
}

function refreshKey(hash: string): string {
  return `auth:refresh:${hash}`;
}

function familyKey(familyId: string): string {
  return `auth:rtfam:${familyId}`;
}

function sessionKey(familyId: string): string {
  return `auth:session:${familyId}`;
}

// userFamKey is the reverse index (user -> its families) GET/DELETE
// /sessions need — nothing else in this file required looking up "all of a
// user's families" before 5M.
function userFamKey(userId: string): string {
  return `auth:userfam:${userId}`;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export async function signAccessToken(
  userId: string,
  signingKey: SigningKey,
  tokenEnv: TokenEnv,
  credentialVersion = 0,
): Promise<{ token: string; expiresIn: number }> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + tokenEnv.accessTtlSeconds;

  const token = await new SignJWT({ scope: ACCESS_SCOPE, credential_version: credentialVersion })
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

// touchSession keeps auth:session:<family> and the auth:userfam:<user>
// reverse index in step with the family's sliding TTL — called on every
// issueTokenPair (fresh login AND rotation) so a session's last_active_at
// reflects actual use and its entry never expires out from under an
// otherwise-still-valid family.
async function touchSession(
  redis: Redis,
  familyId: string,
  userId: string,
  now: string,
  isNewFamily: boolean,
  ttlSeconds: number,
  credentialVersion: number,
): Promise<void> {
  let createdAt = now;
  if (!isNewFamily) {
    const raw = await redis.get(sessionKey(familyId));
    if (raw) {
      createdAt = (JSON.parse(raw) as SessionRecord).created_at;
    }
  }
  const session: SessionRecord = { user_id: userId, created_at: createdAt, last_active_at: now, credential_version: credentialVersion };
  await redis.set(sessionKey(familyId), JSON.stringify(session), "EX", ttlSeconds);
  await redis.sadd(userFamKey(userId), familyId);
  await redis.expire(userFamKey(userId), ttlSeconds);
}

export interface IssueTokenPairParams {
  redis: Redis;
  signingKey: SigningKey;
  tokenEnv: TokenEnv;
  userId: string;
  familyId?: string;
  credentialVersion?: number;
}

// Fresh login starts a new family; rotation (rotateRefreshToken below) reuses
// the caller's familyId so every descendant token stays revocable as a unit.
export async function issueTokenPair(params: IssueTokenPairParams): Promise<TokenPair> {
  const { redis, signingKey, tokenEnv, userId } = params;
  const credentialVersion = params.credentialVersion ?? 0;
  const isNewFamily = params.familyId === undefined;
  const familyId = params.familyId ?? randomUUID();
  const refreshToken = randomBytes(32).toString("base64url");
  const hash = hashToken(refreshToken);
  const now = new Date().toISOString();

  const record: RefreshRecord = { user_id: userId, family_id: familyId, issued_at: now, consumed: false, credential_version: credentialVersion };
  await storeRefreshToken(redis, record, hash, tokenEnv.refreshTtlSeconds);
  await touchSession(redis, familyId, userId, now, isNewFamily, tokenEnv.refreshTtlSeconds, credentialVersion);

  const access = await signAccessToken(userId, signingKey, tokenEnv, credentialVersion);
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

export async function refreshTokenOwner(redis: Redis, refreshToken: string): Promise<{ userId: string; familyId: string; credentialVersion: number } | null> {
  const raw = await redis.get(refreshKey(hashToken(refreshToken)));
  if (!raw) return null;
  const record = JSON.parse(raw) as RefreshRecord;
  const credentialVersion = record.credential_version ?? 0;
  if (!Number.isSafeInteger(credentialVersion) || credentialVersion < 0) return null;
  return { userId: record.user_id, familyId: record.family_id, credentialVersion };
}

// Consume and issue in one Redis turn: a concurrent reuse cannot revoke the
// family between those writes and leave a newly issued token alive.
const ROTATE_LUA = `
local raw = redis.call('GET', KEYS[1])
if not raw then return {0} end
local record = cjson.decode(raw)
local credentialVersion = record.credential_version
if credentialVersion == nil then credentialVersion = 0 end
if type(credentialVersion) ~= 'number' or credentialVersion < 0 or credentialVersion % 1 ~= 0 or credentialVersion > 9007199254740991 then return {0} end
local family = 'auth:rtfam:' .. record.family_id
local session = 'auth:session:' .. record.family_id
local index = 'auth:userfam:' .. record.user_id
if redis.call('SISMEMBER', family, ARGV[1]) == 0 then return {0} end
if record.consumed then
  for _, member in ipairs(redis.call('SMEMBERS', family)) do
    redis.call('DEL', 'auth:refresh:' .. member)
  end
  redis.call('DEL', family, session)
  redis.call('SREM', index, record.family_id)
  return {2}
end
record.consumed = true
redis.call('SET', KEYS[1], cjson.encode(record), 'KEEPTTL')
redis.call('SET', KEYS[2], cjson.encode({user_id=record.user_id, family_id=record.family_id, issued_at=ARGV[3], consumed=false, credential_version=credentialVersion}), 'EX', ARGV[2])
redis.call('SADD', family, ARGV[4])
redis.call('EXPIRE', family, ARGV[2])
local sessionRaw = redis.call('GET', session)
local createdAt = sessionRaw and cjson.decode(sessionRaw).created_at or ARGV[3]
redis.call('SET', session, cjson.encode({user_id=record.user_id, created_at=createdAt, last_active_at=ARGV[3], credential_version=credentialVersion}), 'EX', ARGV[2])
redis.call('SADD', index, record.family_id)
redis.call('EXPIRE', index, ARGV[2])
return {1, record.user_id, credentialVersion}
`;

// One-time use: the record is marked consumed (not deleted outright) so a
// second attempt with the same token is recognizable as reuse rather than
// looking identical to an unknown/expired token — that recognition is what
// lets reuse trigger a full family revocation instead of a plain 401.
export async function rotateRefreshToken(params: RotateRefreshTokenParams): Promise<RefreshResult> {
  const { redis, signingKey, tokenEnv, refreshToken } = params;
  const hash = hashToken(refreshToken);
  const nextToken = randomBytes(32).toString("base64url");
  const nextHash = hashToken(nextToken);
  const result = await redis.eval(
    ROTATE_LUA, 2, refreshKey(hash), refreshKey(nextHash),
    hash, tokenEnv.refreshTtlSeconds, new Date().toISOString(), nextHash,
  ) as [number, string?, number?];
  if (result[0] !== 1) {
    return { ok: false, reason: result[0] === 2 ? "reuse_detected" : "invalid" };
  }
  const credentialVersion = result[2] ?? 0;
  const access = await signAccessToken(result[1]!, signingKey, tokenEnv, credentialVersion);
  return { ok: true, pair: { accessToken: access.token, refreshToken: nextToken, expiresIn: access.expiresIn } };
}

// revokeFamily looks the session up by familyId (rather than requiring
// callers to already know the owning user_id) so /logout and /refresh's
// reuse-detection path — neither of which touched the session index before
// 5M — didn't need to change.
export async function revokeFamily(redis: Redis, familyId: string): Promise<void> {
  await redis.eval(`
    local session = redis.call('GET', KEYS[2])
    for _, member in ipairs(redis.call('SMEMBERS', KEYS[1])) do
      redis.call('DEL', 'auth:refresh:' .. member)
    end
    redis.call('DEL', KEYS[1], KEYS[2])
    if session then redis.call('SREM', 'auth:userfam:' .. cjson.decode(session).user_id, ARGV[1]) end
  `, 2, familyKey(familyId), sessionKey(familyId), familyId);
}

export async function logoutByRefreshToken(redis: Redis, refreshToken: string): Promise<void> {
  const hash = hashToken(refreshToken);
  const raw = await redis.get(refreshKey(hash));
  if (!raw) return;

  const record = JSON.parse(raw) as RefreshRecord;
  await revokeFamily(redis, record.family_id);
}

// listSessions backs GET /sessions (../PLAN.md §7 "세션 관리 API — family
// 목록") — one entry per active login ("device"). A family_id present in
// the reverse index whose session key already expired (TTL raced ahead of
// an unused login) is dropped and the stale index entry self-heals away.
export async function listSessions(redis: Redis, userId: string, credentialVersion = 0): Promise<SessionSummary[]> {
  const familyIds = await redis.smembers(userFamKey(userId));
  const sessions: SessionSummary[] = [];
  for (const familyId of familyIds) {
    const raw = await redis.get(sessionKey(familyId));
    if (!raw) {
      await redis.srem(userFamKey(userId), familyId);
      continue;
    }
    const session = JSON.parse(raw) as SessionRecord;
    const sessionVersion = session.credential_version ?? 0;
    if (!Number.isSafeInteger(sessionVersion) || sessionVersion < credentialVersion) {
      await revokeFamily(redis, familyId);
      continue;
    }
    if (sessionVersion > credentialVersion) continue;
    sessions.push({ family_id: familyId, created_at: session.created_at, last_active_at: session.last_active_at });
  }
  return sessions.sort((a, b) => b.last_active_at.localeCompare(a.last_active_at));
}

export async function revokeSessionsBeforeVersion(redis: Redis, userId: string, credentialVersion: number): Promise<number> {
  return Number(await redis.eval(`
    local families = redis.call('SMEMBERS', KEYS[1])
    local revoked = 0
    for _, familyId in ipairs(families) do
      local sessionKey = 'auth:session:' .. familyId
      local rawSession = redis.call('GET', sessionKey)
      local sessionVersion = 0
      if rawSession then
        local session = cjson.decode(rawSession)
        sessionVersion = session.credential_version or 0
      end
      if not rawSession or type(sessionVersion) ~= 'number' or sessionVersion < tonumber(ARGV[1]) then
      local family = 'auth:rtfam:' .. familyId
      for _, member in ipairs(redis.call('SMEMBERS', family)) do
        redis.call('DEL', 'auth:refresh:' .. member)
      end
      redis.call('DEL', family, sessionKey)
      redis.call('SREM', KEYS[1], familyId)
      revoked = revoked + 1
      end
    end
    return revoked
  `, 1, userFamKey(userId), credentialVersion));
}

// revokeSessionForUser backs DELETE /sessions/:familyId ("개별 폐기" /
// force logout). Ownership is checked via the reverse index before
// revoking — a familyId that exists but belongs to someone else returns
// false so the route can 404 without leaking whether the id exists at all.
export async function revokeSessionForUser(
  redis: Redis,
  userId: string,
  familyId: string,
  credentialVersion = 0,
): Promise<boolean> {
  const revoked = await redis.eval(`
    local rawSession = redis.call('GET', KEYS[2])
    if not rawSession then return 0 end
    local session = cjson.decode(rawSession)
    local version = session.credential_version or 0
    if session.user_id ~= ARGV[1] or type(version) ~= 'number' or version ~= tonumber(ARGV[3]) then return 0 end
    for _, member in ipairs(redis.call('SMEMBERS', KEYS[1])) do
      redis.call('DEL', 'auth:refresh:' .. member)
    end
    redis.call('DEL', KEYS[1], KEYS[2])
    redis.call('SREM', KEYS[3], ARGV[2])
    return 1
  `, 3, familyKey(familyId), sessionKey(familyId), userFamKey(userId), userId, familyId, credentialVersion);
  return Number(revoked) === 1;
}
