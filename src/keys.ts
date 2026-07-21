import { calculateJwkThumbprint, exportJWK, importPKCS8, type CryptoKey, type JWK } from "jose";

// ES256 signing key derived from a PEM private key. kid is always computed
// from the key itself (RFC 7638 JWK thumbprint) — never hardcoded, so a key
// rotation only requires swapping the PEM and the kid follows automatically.
export interface SigningKey {
  privateKey: CryptoKey;
  publicJwk: JWK;
  kid: string;
}

export async function loadSigningKey(pem: string): Promise<SigningKey> {
  const privateKey = await importPKCS8(pem, "ES256", { extractable: true });
  const fullJwk = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(fullJwk);

  const { d: _d, ...publicJwk } = fullJwk;
  publicJwk.kid = kid;
  publicJwk.alg = "ES256";
  publicJwk.use = "sig";

  return { privateKey, publicJwk, kid };
}
