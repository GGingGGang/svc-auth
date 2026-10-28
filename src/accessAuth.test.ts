import { describe, expect, it } from "vitest";

import { verifyOwnAccessToken, verifyOwnAccessTokenClaims } from "./accessAuth.js";
import { generateTestSigningKey } from "./test-support/signing-key.js";
import { signAccessToken } from "./tokens.js";
import type { TokenEnv } from "./tokens.js";

const tokenEnv: TokenEnv = { issuer: "auth.test", accessTtlSeconds: 3600, refreshTtlSeconds: 1_209_600 };

describe("verifyOwnAccessToken", () => {
  it("accepts a token signed with the primary key and returns its subject", async () => {
    const signingKey = await generateTestSigningKey();
    const { token } = await signAccessToken("user-1", signingKey, tokenEnv);

    await expect(verifyOwnAccessToken(token, signingKey, undefined, tokenEnv)).resolves.toBe("user-1");
  });

  it("treats pre-version tokens as version zero and preserves an explicit version", async () => {
    const signingKey = await generateTestSigningKey();
    const legacy = (await signAccessToken("user-legacy", signingKey, tokenEnv)).token;
    const updated = (await signAccessToken("user-updated", signingKey, tokenEnv, 7)).token;

    await expect(verifyOwnAccessTokenClaims(legacy, signingKey, undefined, tokenEnv))
      .resolves.toEqual({ userId: "user-legacy", credentialVersion: 0 });
    await expect(verifyOwnAccessTokenClaims(updated, signingKey, undefined, tokenEnv))
      .resolves.toEqual({ userId: "user-updated", credentialVersion: 7 });
  });

  it("also accepts a token signed with the secondary key (rotation window)", async () => {
    const active = await generateTestSigningKey();
    const secondary = await generateTestSigningKey();
    const { token } = await signAccessToken("user-2", secondary, tokenEnv);

    await expect(verifyOwnAccessToken(token, active, secondary, tokenEnv)).resolves.toBe("user-2");
  });

  it("rejects a token signed by neither key", async () => {
    const signingKey = await generateTestSigningKey();
    const stranger = await generateTestSigningKey();
    const { token } = await signAccessToken("user-3", stranger, tokenEnv);

    await expect(verifyOwnAccessToken(token, signingKey, undefined, tokenEnv)).resolves.toBeNull();
  });

  it("rejects garbage input without throwing", async () => {
    const signingKey = await generateTestSigningKey();
    await expect(verifyOwnAccessToken("not-a-jwt", signingKey, undefined, tokenEnv)).resolves.toBeNull();
  });
});
