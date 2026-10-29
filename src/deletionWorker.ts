import { jetstream } from "@nats-io/jetstream";
import { connect } from "@nats-io/transport-node";
import { UUID } from "uuidv7";
import type { Pool, RowDataPacket } from "mysql2/promise";
import type { Redis } from "ioredis";
import { revokeAllUserSessions } from "./tokens.js";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface PendingDeletion extends RowDataPacket { event_id: string; request_id: string; user_id: Buffer; credential_version: number | string }
interface DeletionResult { event_id: string; request_id: string; service: "core" | "batch" | "notify"; status: "completed" | "retry" }

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

async function acceptResult(pool: Pool, redis: Redis, result: DeletionResult): Promise<void> {
  if (!result || !/^[0-9a-f-]{36}$/iu.test(result.request_id) || !/^[0-9a-f-]{36}$/iu.test(result.event_id) ||
      !["core", "batch", "notify"].includes(result.service) || !["completed", "retry"].includes(result.status)) throw new Error("invalid_deletion_ack");
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
  const nc = await connect({ servers: natsUrl, name: "svc-auth-account-lifecycle" });
  const js = jetstream(nc);
  let stopped = false;
  const timer = setInterval(() => { if (!stopped) void publishPending(pool, js).catch(() => undefined); }, 1000);
  timer.unref();
  const stream = process.env.ACCOUNT_LIFECYCLE_STREAM ?? "ACCOUNT_LIFECYCLE";
  const durable = process.env.AUTH_DELETION_RESULT_DURABLE ?? "auth-deletion-results";
  void (async () => {
    try {
      const consumer = await js.consumers.get(stream, durable);
      const messages = await consumer.consume({ max_messages: 10 });
      for await (const message of messages) {
        try { await acceptResult(pool, redis, JSON.parse(decoder.decode(message.data)) as DeletionResult); message.ack(); }
        catch { message.nak(5000); }
        if (stopped) break;
      }
    } catch { /* durable consumer is provisioned with the ACCOUNT_LIFECYCLE stream */ }
  })();
  return async () => { stopped = true; clearInterval(timer); await nc.drain(); };
}
