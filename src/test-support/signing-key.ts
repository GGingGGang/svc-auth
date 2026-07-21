import { exportPKCS8, generateKeyPair } from "jose";

import { loadSigningKey, type SigningKey } from "../keys.js";

// Test-only: real ES256 keypair generated in-process so JWKS/JWT tests never
// touch the k8s Secret — kid is still derived the normal way (loadSigningKey).
export async function generateTestSigningKey(): Promise<SigningKey> {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const pem = await exportPKCS8(privateKey);
  return loadSigningKey(pem);
}
