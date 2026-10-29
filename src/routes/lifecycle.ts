import argon2 from "argon2";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { Redis } from "ioredis";
import type { Pool, RowDataPacket } from "mysql2/promise";
import { UUID, uuidv7obj } from "uuidv7";
import { verifyOwnAccessTokenClaims } from "../accessAuth.js";
import { activeCredentialVersion } from "../accountStatus.js";
import type { SigningKey } from "../keys.js";
import { encryptMailPayload, type MailConfig, type MailMessage } from "../mailer.js";
import { revokeSessionsBeforeVersion, type TokenEnv } from "../tokens.js";

const hash = (v: string) => createHash("sha256").update(v).digest("hex");
const makeToken = () => randomBytes(32).toString("base64url");
const validEmail = (v: string) => v.length <= 320 && /^[^\s@.]+(?:\.[^\s@.]+)*@[^\s@.]+(?:\.[^\s@.]+)+$/u.test(v);
const error = (error: string) => ({ error });
const bodySchema = (required: string[], properties: Record<string, unknown>) => ({ type: "object", required, additionalProperties: false, properties });

async function rateLimited(redis: Redis, kind: string, email: string, ip: string): Promise<boolean> {
  const emailKey = `auth:lifecycle:email:${kind}:${hash(email)}`;
  const ipKey = `auth:lifecycle:ip:${kind}:${hash(ip)}`;
  const minuteKey = `${emailKey}:minute`;
  const script = `local m=redis.call('INCR',KEYS[1]); if m==1 then redis.call('EXPIRE',KEYS[1],60) end; local a=redis.call('INCR',KEYS[2]); if a==1 then redis.call('EXPIRE',KEYS[2],3600) end; local b=redis.call('INCR',KEYS[3]); if b==1 then redis.call('EXPIRE',KEYS[3],3600) end; return (m>1 or a>5 or b>20) and 1 or 0`;
  return Number(await redis.eval(script, 3, minuteKey, emailKey, ipKey)) === 1;
}

async function queueMail(conn: { execute: Pool["execute"] }, config: MailConfig, userId: Buffer | null, recipient: string, purpose: "verify_email" | "reset_password" | "change_email", message: MailMessage): Promise<void> {
  const id = uuidv7obj();
  const encrypted = encryptMailPayload(JSON.stringify(message), config.encryptionKey);
  await conn.execute(
    "INSERT INTO auth_mail_outbox (id,user_id,purpose,recipient,encrypted_payload) VALUES (?,?,?,?,?)",
    [Buffer.from(id.bytes), userId, purpose, recipient, encrypted],
  );
}

interface TokenRow extends RowDataPacket { id: Buffer; email: string; password_hash: string | null; status: string; credential_version: number | string }

export interface LifecycleOptions {
  pool: Pool; redis: Redis; signingKey: SigningKey; secondaryKey?: SigningKey; tokenEnv: TokenEnv;
  mailConfig: MailConfig | null; registrationMode: "verified" | "demo";
}

export async function lifecycleRoutes(app: FastifyInstance, opts: LifecycleOptions): Promise<void> {
  const { pool, redis, mailConfig } = opts;

  app.post<{ Body: { email: string } }>("/email/verification/request", { schema: { body: bodySchema(["email"], { email: { type: "string", maxLength: 320 } }) } }, async (req, reply) => {
    const email = req.body?.email?.trim().toLowerCase();
    if (!email || !validEmail(email)) return reply.code(400).send(error("invalid_request"));
    if (await rateLimited(redis, "verify", email, req.ip)) return reply.code(429).send(error("rate_limited"));
    if (!mailConfig) return reply.code(503).send(error("email_unavailable"));
    const [rows] = await pool.query<TokenRow[]>("SELECT id,email,status FROM users WHERE email=? AND email_verified_at IS NULL AND status='active'", [email]);
    if (rows[0]) await issueActionForUser(pool, mailConfig, rows[0].id, email, "verify_email", null, "Verify your email");
    return reply.code(202).send({ accepted: true });
  });

  app.post<{ Body: { token: string } }>("/email/verification/confirm", { schema: { body: bodySchema(["token"], { token: { type: "string", minLength: 1, maxLength: 256 } }) } }, async (req, reply) => {
    const token = req.body?.token;
    if (!token || token.length > 256) return reply.code(400).send(error("invalid_or_expired_token"));
    const result = await consumeAction(pool, token, ["verify_email", "change_email"]);
    if (!result) return reply.code(400).send(error("invalid_or_expired_token"));
    if (result.purpose === "change_email") await revokeSessionsBeforeVersion(redis, result.userId, result.credentialVersion).catch(() => req.log.warn({ error_code: "session_cleanup_deferred" }, "email changed; session cleanup deferred"));
    return result.purpose === "verify_email"
      ? reply.code(200).send({ verified: true })
      : reply.code(200).send({ email_changed: true });
  });

  app.post<{ Body: { email: string } }>("/password/reset/request", { schema: { body: bodySchema(["email"], { email: { type: "string", maxLength: 320 } }) } }, async (req, reply) => {
    const email = req.body?.email?.trim().toLowerCase();
    if (!email || !validEmail(email)) return reply.code(400).send(error("invalid_request"));
    if (await rateLimited(redis, "reset", email, req.ip)) return reply.code(429).send(error("rate_limited"));
    if (!mailConfig) return reply.code(503).send(error("email_unavailable"));
    const [rows] = await pool.query<TokenRow[]>("SELECT id,email FROM users WHERE email=? AND email_verified_at IS NOT NULL AND status='active'", [email]);
    if (rows[0]) await issueActionForUser(pool, mailConfig, rows[0].id, email, "reset_password", null, "Reset your password");
    return reply.code(202).send({ accepted: true });
  });

  app.post<{ Body: { token: string; new_password: string } }>("/password/reset", { schema: { body: bodySchema(["token", "new_password"], { token: { type: "string", minLength: 1, maxLength: 256 }, new_password: { type: "string", minLength: 12, maxLength: 128 } }) } }, async (req, reply) => {
    const { token, new_password } = req.body ?? {};
    const length = typeof new_password === "string" ? Array.from(new_password).length : 0;
    if (!token || token.length > 256 || length < 12 || length > 128) return reply.code(400).send(error("invalid_request"));
    if (await rateLimited(redis, "reset_consume", hash(token), req.ip)) return reply.code(429).send(error("rate_limited"));
    const [validRows] = await pool.query<RowDataPacket[]>(
      "SELECT 1 FROM account_action_tokens t JOIN users u ON u.id=t.user_id AND u.credential_version=t.credential_version WHERE t.token_hash=? AND t.purpose='reset_password' AND t.consumed_at IS NULL AND t.expires_at>UTC_TIMESTAMP(3) AND u.status='active'",
      [hash(token)],
    );
    if (!validRows.length) return reply.code(400).send(error("invalid_or_expired_token"));
    const passwordHash = await argon2.hash(new_password, { type: argon2.argon2id });
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [rows] = await conn.query<(TokenRow & { purpose: string; pending_email: string | null })[]>(
        "SELECT u.id,u.email,u.status,u.credential_version,t.purpose,t.pending_email FROM account_action_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.purpose='reset_password' AND t.credential_version=u.credential_version AND t.consumed_at IS NULL AND t.expires_at>UTC_TIMESTAMP(3) FOR UPDATE",
        [hash(token)],
      );
      const row = rows[0];
      if (!row || row.status !== "active") { await conn.rollback(); return reply.code(400).send(error("invalid_or_expired_token")); }
      await conn.execute("UPDATE account_action_tokens SET consumed_at=UTC_TIMESTAMP(3) WHERE user_id=? AND purpose='reset_password' AND consumed_at IS NULL", [row.id]);
      await conn.execute("UPDATE users SET password_hash=?,credential_version=credential_version+1,login_failures=0,login_failure_window_started_at=NULL,login_locked_until=NULL WHERE id=? AND status='active'", [passwordHash,row.id]);
      await conn.execute("DELETE FROM account_action_tokens WHERE user_id=? AND purpose IN ('reset_password','change_email')", [row.id]);
      await conn.commit();
      await revokeSessionsBeforeVersion(redis, UUID.ofInner(row.id).toString(), Number(row.credential_version) + 1).catch(() => req.log.warn({ error_code: "session_cleanup_deferred" }, "password reset; session cleanup deferred"));
      return reply.code(204).send();
    } catch (err) { await conn.rollback(); if (isDuplicate(err)) return reply.code(400).send(error("invalid_or_expired_token")); throw err; }
    finally { conn.release(); }
  });

  app.post<{ Body: { current_password: string; new_email: string } }>("/account/email-change", { schema: { body: bodySchema(["current_password", "new_email"], { current_password: { type: "string", minLength: 1, maxLength: 512 }, new_email: { type: "string", maxLength: 320 } }) } }, async (req, reply) => {
    const userId = await authenticate(opts, req.headers.authorization);
    if (!userId) return reply.code(401).send(error("unauthorized"));
    const email = req.body?.new_email?.trim().toLowerCase();
    if (!req.body?.current_password || !email || !validEmail(email)) return reply.code(400).send(error("invalid_request"));
    if (await rateLimited(redis, "email_change", email, req.ip)) return reply.code(429).send(error("rate_limited"));
    if (!mailConfig) return reply.code(503).send(error("email_unavailable"));
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [rows] = await conn.query<TokenRow[]>("SELECT id,email,password_hash,status,credential_version FROM users WHERE id=UUID_TO_BIN(?) FOR UPDATE", [userId]);
      const user = rows[0];
      if (!user || user.status !== "active" || !user.password_hash || !await argon2.verify(user.password_hash, req.body.current_password)) {
        await conn.rollback(); return reply.code(401).send(error("reauthentication_failed"));
      }
      if (user.email === email) { await conn.rollback(); return reply.code(400).send(error("email_unchanged")); }
      const [existing] = await conn.query<RowDataPacket[]>("SELECT id FROM users WHERE email=?", [email]);
      if (existing.length) { await conn.rollback(); return reply.code(409).send(error("email_unavailable")); }
      await issueAction(conn as never, mailConfig, user.id, email, "change_email", email, "Confirm your new email", Number(user.credential_version));
      await conn.commit();
      return reply.code(202).send({ accepted: true });
    } catch (err) { await conn.rollback(); if (isDuplicate(err)) return reply.code(409).send(error("email_unavailable")); throw err; }
    finally { conn.release(); }
  });

  app.delete<{ Body: { current_password: string; confirm: true } }>("/account", { schema: { body: bodySchema(["current_password", "confirm"], { current_password: { type: "string", minLength: 1, maxLength: 512 }, confirm: { const: true } }) } }, async (req, reply) => {
    const userId = await authenticate(opts, req.headers.authorization);
    if (!userId) return reply.code(401).send(error("unauthorized"));
    if (!req.body?.confirm || !req.body.current_password) return reply.code(400).send(error("confirmation_required"));
    if (await rateLimited(redis, "delete", userId, req.ip)) return reply.code(429).send(error("rate_limited"));
    const receipt = await requestDeletion(pool, redis, userId, req.body.current_password, false);
    if (!receipt) return reply.code(401).send(error("reauthentication_failed"));
    return reply.code(202).send({ deletion_receipt: receipt });
  });

  app.post<{ Body: { email: string; password: string; confirm: true } }>("/account/deletion/unverified", {
    schema: { body: bodySchema(["email", "password", "confirm"], { email: { type: "string", maxLength: 320 }, password: { type: "string", minLength: 1, maxLength: 512 }, confirm: { const: true } }) },
  }, async (req, reply) => {
    const email = req.body.email.trim().toLowerCase();
    if (!validEmail(email)) return reply.code(400).send(error("invalid_request"));
    if (await rateLimited(redis, "delete_unverified", email, req.ip)) return reply.code(429).send(error("rate_limited"));
    const [rows] = await pool.query<(RowDataPacket & { id: Buffer })[]>("SELECT id FROM users WHERE email=? AND status='active' AND email_verified_at IS NULL", [email]);
    const receipt = rows[0] ? await requestDeletion(pool, redis, UUID.ofInner(rows[0].id).toString(), req.body.password, true) : null;
    return reply.code(202).send({ accepted: true, ...(receipt ? { deletion_receipt: receipt } : {}) });
  });

  app.get("/account/deletion", async (req, reply) => {
    const header = req.headers["x-deletion-receipt"];
    const receipt = Array.isArray(header) ? header[0] : header;
    if (!receipt || receipt.length > 256) return reply.code(404).send(error("not_found"));
    const [rows] = await pool.query<(RowDataPacket & { status: string })[]>("SELECT status FROM account_deletion_receipts WHERE receipt_hash=?", [hash(receipt)]);
    if (!rows[0]) return reply.code(404).send(error("not_found"));
    return reply.code(200).send({ status: rows[0].status });
  });

  app.get<{ Params: { userId: string } }>("/internal/accounts/:userId/status", { schema: { hide: true } }, async (req, reply) => {
    const internalToken = process.env.INTERNAL_SERVICE_TOKEN;
    if (!constantTimeBearer(req.headers.authorization, internalToken)) return reply.code(internalToken ? 401 : 503).send(error(internalToken ? "unauthorized" : "unavailable"));
    if (!/^[0-9a-f-]{36}$/iu.test(req.params.userId)) return reply.code(200).send({ active: false });
    const [rows] = await pool.query<(RowDataPacket & { status: string; timezone: string; email_verified_at: Date | null })[]>("SELECT status,timezone,email_verified_at FROM users WHERE id=UUID_TO_BIN(?)", [req.params.userId]);
    const user = rows[0];
    return reply.code(200).send(user?.status === "active" && user.email_verified_at ? { active: true, timezone: user.timezone } : { active: false });
  });

  for (const action of ["suspend", "unsuspend"] as const) {
    app.post<{ Params: { userId: string }; Body: { reason: string } }>(`/internal/accounts/:userId/${action}`, {
      schema: {
        hide: true,
        body: bodySchema(["reason"], { reason: { type: "string", minLength: 3, maxLength: 500 } }),
      },
    }, async (req, reply) => {
      const credentials = loadOperatorCredentials();
      if (!credentials) return reply.code(503).send(error("unavailable"));
      const actor = operatorActor(req.headers.authorization, credentials);
      if (!actor) return reply.code(401).send(error("unauthorized"));
      if (!/^[0-9a-f-]{36}$/iu.test(req.params.userId)) return reply.code(404).send(error("not_found"));
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        const [rows] = await conn.query<(RowDataPacket & { id: Buffer; status: string; email_verified_at: Date | null })[]>("SELECT id,status,email_verified_at FROM users WHERE id=UUID_TO_BIN(?) FOR UPDATE", [req.params.userId]);
        const user = rows[0];
        const canChange = action === "suspend"
          ? user?.status === "active"
          : user?.status === "locked" && user.email_verified_at !== null;
        if (!user || !canChange) { await conn.rollback(); return reply.code(409).send(error("account_state_conflict")); }
        const auditId = uuidv7obj();
        if (action === "suspend") {
          await conn.execute("UPDATE users SET status='locked',credential_version=credential_version+1 WHERE id=?", [user.id]);
        } else {
          await conn.execute("UPDATE users SET status='active' WHERE id=? AND status='locked' AND email_verified_at IS NOT NULL", [user.id]);
        }
        await conn.execute("INSERT INTO account_operator_audit(id,target_user_id,actor,action,reason) VALUES(?,?,?,?,?)", [Buffer.from(auditId.bytes),user.id,actor,action,req.body.reason.trim()]);
        await conn.commit();
        return reply.code(200).send({ status: action === "suspend" ? "locked" : "active" });
      } catch (err) { await conn.rollback(); throw err; }
      finally { conn.release(); }
    });
  }
}

function constantTimeBearer(header: string | string[] | undefined, expected: string | undefined): boolean {
  if (!expected) return false;
  const raw = Array.isArray(header) ? header[0] : header;
  const supplied = raw?.startsWith("Bearer ") ? raw.slice(7) : "";
  const a = Buffer.from(supplied); const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function loadOperatorCredentials(): Map<string, string> | null {
  try {
    const parsed: unknown = JSON.parse(process.env.OPERATOR_TOKENS_JSON ?? "");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const entries = Object.entries(parsed as Record<string, unknown>);
    if (!entries.length || entries.some(([actor, token]) => !actor.trim() || typeof token !== "string" || token.length < 32)) return null;
    const tokens = entries.map(([, token]) => token as string);
    if (new Set(tokens).size !== tokens.length) return null;
    return new Map(entries.map(([actor, token]) => [token as string, actor.trim()]));
  } catch { return null; }
}

function operatorActor(header: string | string[] | undefined, credentials: Map<string, string>): string | null {
  const raw = Array.isArray(header) ? header[0] : header;
  const supplied = raw?.startsWith("Bearer ") ? raw.slice(7) : "";
  let actor: string | null = null;
  for (const [token, name] of credentials) if (constantTimeBearer(`Bearer ${supplied}`, token)) actor = name;
  return actor;
}

async function authenticate(opts: LifecycleOptions, authorization?: string): Promise<string | null> {
  const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined;
  const claims = token ? await verifyOwnAccessTokenClaims(token, opts.signingKey, opts.secondaryKey, opts.tokenEnv) : null;
  if (!claims || await activeCredentialVersion(opts.pool, claims.userId) !== claims.credentialVersion) return null;
  return claims.userId;
}

async function requestDeletion(pool: Pool, redis: Redis, userId: string, password: string, requireUnverified: boolean): Promise<string | null> {
  const receipt = makeToken();
  const requestId = randomUUID();
  const eventId = randomUUID();
  const conn = await pool.getConnection();
  let version = 0;
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query<(TokenRow & { email_verified_at: Date | null })[]>("SELECT id,password_hash,status,credential_version,email_verified_at FROM users WHERE id=UUID_TO_BIN(?) FOR UPDATE", [userId]);
    const user = rows[0];
    if (!user || user.status !== "active" || !user.password_hash || (requireUnverified && user.email_verified_at !== null) || !await argon2.verify(user.password_hash, password)) {
      await conn.rollback(); return null;
    }
    version = Number(user.credential_version) + 1;
    await conn.execute("UPDATE users SET status='deleting',credential_version=? WHERE id=?", [version,user.id]);
    await conn.execute("INSERT INTO account_deletion_outbox(event_id,request_id,user_id,credential_version) VALUES(?,?,?,?)", [eventId,requestId,user.id,version]);
    for (const service of ["core","batch","notify"]) await conn.execute("INSERT INTO account_deletion_services(request_id,service) VALUES(?,?)", [requestId,service]);
    await conn.execute("INSERT INTO account_deletion_receipts(receipt_hash,request_id) VALUES(?,?)", [hash(receipt),requestId]);
    await conn.commit();
  } catch (err) { await conn.rollback(); throw err; }
  finally { conn.release(); }
  await revokeSessionsBeforeVersion(redis, userId, version).catch(() => undefined);
  return receipt;
}

async function issueActionForUser(pool: Pool, config: MailConfig, userId: Buffer, recipient: string, purpose: "verify_email" | "reset_password", pendingEmail: null, subject: string): Promise<void> {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query<(RowDataPacket & { status: string; credential_version: number | string; email_verified_at: Date | null })[]>("SELECT status,credential_version,email_verified_at FROM users WHERE id=? FOR UPDATE", [userId]);
    const user = rows[0];
    if (!user || user.status !== "active" || (purpose === "verify_email" ? user.email_verified_at !== null : user.email_verified_at === null)) {
      await conn.rollback(); return;
    }
    await issueAction(conn, config, userId, recipient, purpose, pendingEmail, subject, Number(user.credential_version));
    await conn.commit();
  } catch (err) { await conn.rollback(); throw err; }
  finally { conn.release(); }
}

async function issueAction(conn: { execute: Pool["execute"] }, config: MailConfig, userId: Buffer, recipient: string, purpose: "verify_email" | "reset_password" | "change_email", pendingEmail: string | null, subject: string, credentialVersion: number) {
  const token = makeToken();
  const action = purpose === "verify_email" ? "verify" : purpose === "reset_password" ? "reset" : "email-change";
  await conn.execute("DELETE FROM auth_mail_outbox WHERE user_id=? AND purpose=?", [userId,purpose]);
  await conn.execute(
    "INSERT INTO account_action_tokens(user_id,purpose,token_hash,pending_email,credential_version,expires_at,consumed_at) VALUES(?,?,?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL ? MINUTE),NULL) ON DUPLICATE KEY UPDATE token_hash=VALUES(token_hash),pending_email=VALUES(pending_email),credential_version=VALUES(credential_version),expires_at=VALUES(expires_at),consumed_at=NULL",
    [userId,purpose,hash(token),pendingEmail,credentialVersion,purpose === "reset_password" ? 15 : 30],
  );
  await queueMail(conn, config, userId, recipient, purpose, { subject, token, action });
}

async function consumeAction(pool: Pool, token: string, purposes: string[]): Promise<{ purpose: string; userId: string; credentialVersion: number } | null> {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query<(TokenRow & { purpose: string; pending_email: string | null })[]>(
      "SELECT u.id,u.status,u.credential_version,t.credential_version AS action_credential_version,t.purpose,t.pending_email FROM account_action_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.purpose IN (?,?) AND t.credential_version=u.credential_version AND t.consumed_at IS NULL AND t.expires_at>UTC_TIMESTAMP(3) FOR UPDATE",
      [hash(token), purposes[0], purposes[1]],
    );
    const row = rows[0];
    if (!row || row.status !== "active") { await conn.rollback(); return null; }
    if (row.purpose === "change_email") {
      const [used] = await conn.query<RowDataPacket[]>("SELECT id FROM users WHERE email=? AND id<>?", [row.pending_email, row.id]);
      if (used.length || !row.pending_email) { await conn.rollback(); return null; }
      await conn.execute("UPDATE users SET email=?,email_verified_at=UTC_TIMESTAMP(3),credential_version=credential_version+1 WHERE id=? AND status='active'", [row.pending_email,row.id]);
      await conn.execute("DELETE FROM account_action_tokens WHERE user_id=? AND purpose IN ('reset_password','change_email')", [row.id]);
    } else {
      await conn.execute("UPDATE users SET email_verified_at=UTC_TIMESTAMP(3) WHERE id=? AND status='active'", [row.id]);
    }
    await conn.execute("UPDATE account_action_tokens SET consumed_at=UTC_TIMESTAMP(3) WHERE user_id=? AND purpose=? AND consumed_at IS NULL", [row.id,row.purpose]);
    const credentialVersion = Number(row.credential_version) + (row.purpose === "change_email" ? 1 : 0);
    await conn.commit();
    return { purpose: row.purpose, userId: UUID.ofInner(row.id).toString(), credentialVersion };
  } catch (err) { await conn.rollback(); if (isDuplicate(err)) return null; throw err; }
  finally { conn.release(); }
}

function isDuplicate(err: unknown): boolean {
  return typeof err === "object" && err !== null && "code" in err && (err as { code?: unknown }).code === "ER_DUP_ENTRY";
}
