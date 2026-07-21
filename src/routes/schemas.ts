// Shared response schemas for the token-issuing routes (login/refresh).

export const tokenResponseSchema = {
  type: "object",
  description: "access(JWT ES256) + refresh(opaque) 토큰 발급",
  properties: {
    access_token: { type: "string" },
    refresh_token: { type: "string" },
    token_type: { type: "string" },
    expires_in: { type: "integer", description: "access token TTL(초)" },
  },
  required: ["access_token", "refresh_token", "token_type", "expires_in"],
} as const;

export const errorResponseSchema = {
  type: "object",
  properties: {
    error: { type: "string" },
  },
  required: ["error"],
} as const;
