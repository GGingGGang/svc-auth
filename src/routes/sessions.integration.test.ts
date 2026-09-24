import { RedisContainer, type StartedRedisContainer } from "@testcontainers/redis";
import { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import type { SigningKey } from "../keys.js";
import { buildApp } from "../router.js";
import { generateTestSigningKey } from "../test-support/signing-key.js";
import { issueTokenPair, rotateRefreshToken, signAccessToken, type TokenEnv } from "../tokens.js";

// Sessions routes never touch the DB — pool.() is never called by anything
// this test exercises, matching router.test.ts's stub pattern. Real logins
// are simulated with issueTokenPair() directly rather than going through
// /login, which would need a real users row (MySQL) this test has no
// reason to stand up.
const stubPool = { query: async () => [[{ status: "active" }], []] } as unknown as Pool;
const tokenEnv: TokenEnv = { issuer: "auth.test", accessTtlSeconds: 3600, refreshTtlSeconds: 1_209_600 };

describe("session management (GET/DELETE /sessions)", () => {
  let redisContainer: StartedRedisContainer;
  let redis: Redis;
  let signingKey: SigningKey;
  let app: ReturnType<typeof buildApp>;

  beforeAll(async () => {
    redisContainer = await new RedisContainer("redis:7").start();
    redis = new Redis({ host: redisContainer.getHost(), port: redisContainer.getPort(), db: 0 });
    signingKey = await generateTestSigningKey();

    app = buildApp({ pool: stubPool, redis, signingKey, tokenEnv });
    await app.ready();
  }, 120_000);

  beforeEach(async () => {
    await redis.flushdb();
  });

  afterAll(async () => {
    await app.close();
    redis.disconnect();
    await redisContainer.stop();
  });

  function bearer(userId: string): Promise<string> {
    return signAccessToken(userId, signingKey, tokenEnv).then((r) => r.token);
  }

  it("requires a bearer token", async () => {
    const response = await app.inject({ method: "GET", url: "/sessions" });
    expect(response.statusCode).toBe(401);
  });

  it("lists only the caller's own sessions, one per login", async () => {
    const userId = "user-a";
    await issueTokenPair({ redis, signingKey, tokenEnv, userId }); // login 1
    await issueTokenPair({ redis, signingKey, tokenEnv, userId }); // login 2
    await issueTokenPair({ redis, signingKey, tokenEnv, userId: "user-b" }); // someone else's login

    const response = await app.inject({
      method: "GET",
      url: "/sessions",
      headers: { authorization: `Bearer ${await bearer(userId)}` },
    });
    expect(response.statusCode).toBe(200);

    const body = response.json() as { sessions: Array<{ family_id: string; created_at: string; last_active_at: string }> };
    expect(body.sessions).toHaveLength(2);
    expect(body.sessions.every((s) => typeof s.family_id === "string" && s.family_id.length > 0)).toBe(true);
  });

  it("a refresh rotation does not create a second session for the same login", async () => {
    const userId = "user-c";
    const pair = await issueTokenPair({ redis, signingKey, tokenEnv, userId });

    const rotated = await rotateRefreshToken({ redis, signingKey, tokenEnv, refreshToken: pair.refreshToken });
    expect(rotated.ok).toBe(true);

    const response = await app.inject({
      method: "GET",
      url: "/sessions",
      headers: { authorization: `Bearer ${await bearer(userId)}` },
    });
    const body = response.json() as { sessions: unknown[] };
    expect(body.sessions).toHaveLength(1);
  });

  it("force logout revokes the target session and its refresh token stops working", async () => {
    const userId = "user-d";
    const pair = await issueTokenPair({ redis, signingKey, tokenEnv, userId });

    const listResponse = await app.inject({
      method: "GET",
      url: "/sessions",
      headers: { authorization: `Bearer ${await bearer(userId)}` },
    });
    const { sessions } = listResponse.json() as { sessions: Array<{ family_id: string }> };
    expect(sessions).toHaveLength(1);
    const familyId = sessions[0]?.family_id;

    const deleteResponse = await app.inject({
      method: "DELETE",
      url: `/sessions/${familyId}`,
      headers: { authorization: `Bearer ${await bearer(userId)}` },
    });
    expect(deleteResponse.statusCode).toBe(204);

    const afterListResponse = await app.inject({
      method: "GET",
      url: "/sessions",
      headers: { authorization: `Bearer ${await bearer(userId)}` },
    });
    expect((afterListResponse.json() as { sessions: unknown[] }).sessions).toHaveLength(0);

    const rotateAfterRevoke = await rotateRefreshToken({
      redis,
      signingKey,
      tokenEnv,
      refreshToken: pair.refreshToken,
    });
    expect(rotateAfterRevoke.ok).toBe(false);
  });

  it("cannot force-logout another user's session (404, no existence leak)", async () => {
    const owner = "user-e";
    const attacker = "user-f";
    const pair = await issueTokenPair({ redis, signingKey, tokenEnv, userId: owner });

    const listResponse = await app.inject({
      method: "GET",
      url: "/sessions",
      headers: { authorization: `Bearer ${await bearer(owner)}` },
    });
    const { sessions } = listResponse.json() as { sessions: Array<{ family_id: string }> };
    const familyId = sessions[0]?.family_id;

    const deleteResponse = await app.inject({
      method: "DELETE",
      url: `/sessions/${familyId}`,
      headers: { authorization: `Bearer ${await bearer(attacker)}` },
    });
    expect(deleteResponse.statusCode).toBe(404);

    // still usable — the attacker's failed attempt must not have revoked it.
    const stillValid = await rotateRefreshToken({ redis, signingKey, tokenEnv, refreshToken: pair.refreshToken });
    expect(stillValid.ok).toBe(true);
  });
});
