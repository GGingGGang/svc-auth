import { jetstream } from "@nats-io/jetstream";
import { connect } from "@nats-io/transport-node";
import { UUID } from "uuidv7";
import type { Pool, RowDataPacket } from "mysql2/promise";
import type { Redis } from "ioredis";
import { revokeAllUserSessions } from "./tokens.js";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface PendingDeletion extends RowDataPacket { event_id: string; request_id: string; user_id: Buffer; credential_version: number | string }
export interface DeletionResult { event_id: string; request_id: string; service: "core" | "batch" | "notify"; status: "completed" | "retry"; occurred_at: string }

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export function parseDeletionResult(value: unknown): DeletionResult {
  if (typeof value !== "object" || value === null) throw new Error("invalid_deletion_ack");
  const result = value as Partial<DeletionResult>;
  if (typeof result.request_id !== "string" || !uuidPattern.test(result.request_id) ||
      typeof result.event_id !== "string" || !uuidPattern.test(result.event_id) ||
      !["core", "batch", "notify"].includes(result.service ?? "") ||
      !["completed", "retry"].includes(result.status ?? "") ||
      typeof result.occurred_at !== "string" || !Number.isFinite(Date.parse(result.occurred_at))) {
    throw new Error("invalid_deletion_ack");
  }
  return result as DeletionResult;
}

export async function superviseDeletionResults<T>(
  getMessages: () => Promise<AsyncIterable<T>>,
  handle: (message: T) => Promise<void>,
  isStopped: () => boolean,
  wait: () => Promise<void>,
  onUnavailable: () => void,
): Promise<void> {
  while (!isStopped()) {
    try {
      for await (const message of await getMessages()) {
        await handle(message);
        if (isStopped()) break;
      }
    } catch {
      if (!isStopped()) onUnavailable();
    }
    if (!isStopped()) await wait();
  }
}

async function publishPending(pool: Pool, js: ReturnType<typeof jetstream>): Promise<void> {
  const conn = await pool.getConnection();
  let row: PendingDeletion | undefined;
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query<PendingDeletion[]>(
      "SELECT o.event_id,o.request_id,o.user_id,o.credential_version FROM account_deletion_outbox o WHERE (o.published_at IS NULL OR o.published_at<DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE)) AND (o.lease_until IS NULL OR o.lease_until<UTC_TIMESTAMP(3)) ORDER BY o.requested_at LIMIT 1 FOR UPDATE SKIP LOCKED",
    );
    row = rows[0];
    if (!row) { await conn.commit(); return; }
    await conn.execute("UPDATE account_deletion_outbox SET lease_until=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE) WHERE event_id=?", [row.event_id]);
    await conn.commit();
  } catch (err) { await conn.rollback(); throw err; }
  finally { conn.release(); }
  try {
    const userId = UUID.ofInner(row.user_id).toString();
    const event = { event_id: row.event_id, request_id: row.request_id, user_id: userId, credential_version: Number(row.credential_version), occurred_at: new Date().toISOString() };
    await js.publish("app.account.deletion_requested.v1", encoder.encode(JSON.stringify(event)), { msgID: row.event_id });
    await pool.execute("UPDATE account_deletion_outbox SET published_at=UTC_TIMESTAMP(3),lease_until=NULL WHERE event_id=?", [row.event_id]);
  } catch {
    await pool.execute("UPDATE account_deletion_outbox SET lease_until=NULL WHERE event_id=?", [row.event_id]);
  }
}

export async function acceptResult(pool: Pool, redis: Redis, result: DeletionResult): Promise<void> {
  const conn = await pool.getConnection();
  let completedUser: { userId: string; userIdBytes: Buffer } | null = null;
  try {
    await conn.beginTransaction();
    const [events] = await conn.query<RowDataPacket[]>("SELECT user_id,credential_version FROM account_deletion_outbox WHERE event_id=? AND request_id=? FOR UPDATE", [result.event_id,result.request_id]);
    if (result.status === "retry") {
      if (events.length) await conn.execute("UPDATE account_deletion_outbox SET published_at=NULL WHERE event_id=?", [result.event_id]);
      await conn.commit(); return;
    }
    if (!events.length) { await conn.commit(); return; }
    await conn.execute("UPDATE account_deletion_services SET status='completed' WHERE request_id=? AND service=?", [result.request_id,result.service]);
    const [pending] = await conn.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM account_deletion_services WHERE request_id=? AND status<>'completed'", [result.request_id]);
    if (Number(pending[0]?.count) === 0) {
      const row = events[0]!;
      const userId = UUID.ofInner(row.user_id as Buffer).toString();
      completedUser = { userId, userIdBytes: row.user_id as Buffer };
    }
    await conn.commit();
  } catch (err) { await conn.rollback(); throw err; }
  finally { conn.release(); }
  if (completedUser) {
    await revokeAllUserSessions(redis, completedUser.userId);
    const finish = await pool.getConnection();
    try {
      await finish.beginTransaction();
      const [pending] = await finish.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM account_deletion_services WHERE request_id=? AND status<>'completed' FOR UPDATE", [result.request_id]);
      if (Number(pending[0]?.count) === 0) {
        await finish.execute("DELETE FROM users WHERE id=? AND status='deleting'", [completedUser.userIdBytes]);
        await finish.execute("UPDATE account_deletion_receipts SET status='completed' WHERE request_id=?", [result.request_id]);
        await finish.execute("DELETE FROM account_deletion_outbox WHERE event_id=?", [result.event_id]);
      }
      await finish.commit();
    } catch (err) { await finish.rollback(); throw err; }
    finally { finish.release(); }
  }
}

export async function startDeletionWorker(pool: Pool, redis: Redis, natsUrl = process.env.NATS_URL): Promise<() => Promise<void>> {
  if (!natsUrl) return async () => undefined;
  let stopped = false;
  let js: ReturnType<typeof jetstream> | undefined;
  let nc: Awaited<ReturnType<typeof connect>> | undefined;
  let activeMessages: { stop: (err?: Error) => void } | undefined;
  let lastPublishWarning = 0;
  const timer = setInterval(() => {
    if (!stopped && js) void publishPending(pool, js).catch(() => {
      const now = Date.now();
      if (now - lastPublishWarning >= 60_000) {
        lastPublishWarning = now;
        console.warn("auth_deletion_outbox_publish_failed");
      }
    });
  }, 1000);
  timer.unref();
  const stream = process.env.ACCOUNT_LIFECYCLE_STREAM ?? "ACCOUNT_LIFECYCLE";
  const durable = process.env.AUTH_DELETION_RESULT_DURABLE ?? "auth-deletion-results";
  const waitBeforeRetry = () => new Promise<void>((resolve) => { const retryTimer = setTimeout(resolve, 5000); retryTimer.unref(); });
  let lastUnavailableWarning = 0;
  const task = superviseDeletionResults(
    async () => {
      if (nc?.isClosed()) { nc = undefined; js = undefined; }
      nc ??= await connect({ servers: natsUrl, name: "svc-auth-account-lifecycle" });
      js = jetstream(nc);
      const messages = await (await js.consumers.get(stream, durable)).consume({ max_messages: 10 });
      activeMessages = messages;
      return messages;
    },
    async (message) => {
      const resultMessage = message as { data: Uint8Array; ack: () => void; nak: (delay: number) => void };
      try { await acceptResult(pool, redis, parseDeletionResult(JSON.parse(decoder.decode(resultMessage.data)))); resultMessage.ack(); }
      catch { resultMessage.nak(5000); }
    },
    () => stopped,
    waitBeforeRetry,
    () => {
      const now = Date.now();
      if (now - lastUnavailableWarning >= 60_000) {
        lastUnavailableWarning = now;
        console.warn("auth_deletion_result_consumer_unavailable");
      }
    },
  );
  return async () => {
    stopped = true;
    clearInterval(timer);
    activeMessages?.stop();
    await nc?.drain();
    await task;
  };
}
