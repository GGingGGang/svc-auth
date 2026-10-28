import { importJWK, jwtVerify, type JWK } from "jose";

import type { SigningKey } from "./keys.js";
import type { TokenEnv } from "./tokens.js";

// verifyOwnAccessToken lets auth authenticate its own access tokens for the
// self-service session-management API (../PLAN.md §7 5M). This is the
// service verifying tokens it minted itself — a local public-key check
// against signingKey (and secondaryKey during a rotation window, so a
// still-valid pre-cutover token doesn't lock its owner out of session
// management — see keyRotation.test.ts), not a call to /.well-known/jwks.json
// the way core does it. The audience check is intentionally skipped: `aud`
// exists to stop a token from being replayed against a *different* relying
// party than it was minted for, but the issuer inspecting its own token is
// not that scenario.
export async function verifyOwnAccessToken(
  token: string,
  signingKey: SigningKey,
  secondaryKey: SigningKey | undefined,
  tokenEnv: TokenEnv,
): Promise<string | null> {
  return (await verifyOwnAccessTokenClaims(token, signingKey, secondaryKey, tokenEnv))?.userId ?? null;
}

export interface OwnAccessClaims {
  userId: string;
  credentialVersion: number;
}

export async function verifyOwnAccessTokenClaims(
  token: string,
  signingKey: SigningKey,
  secondaryKey: SigningKey | undefined,
  tokenEnv: TokenEnv,
): Promise<OwnAccessClaims | null> {
  const candidates = secondaryKey ? [signingKey, secondaryKey] : [signingKey];

  for (const key of candidates) {
    try {
      const publicKey = await importJWK(key.publicJwk as JWK, "ES256");
      const { payload } = await jwtVerify(token, publicKey, { issuer: tokenEnv.issuer });
      if (typeof payload.sub === "string" && payload.sub.length > 0) {
        const version = payload.credential_version ?? 0;
        if (Number.isSafeInteger(version) && typeof version === "number" && version >= 0) {
          return { userId: payload.sub, credentialVersion: version };
        }
      }
    } catch {
      // try the next candidate key; if none verify, fall through to null below.
    }
  }
  return null;
}
