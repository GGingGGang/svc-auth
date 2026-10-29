import type { Pool, RowDataPacket } from "mysql2/promise";
import { decryptMailPayload, createSmtpSender, type MailConfig, type MailMessage } from "./mailer.js";

interface OutboxRow extends RowDataPacket { id: Buffer; recipient: string; encrypted_payload: Buffer; attempts: number }

export async function deliverOneMail(pool: Pool, config: MailConfig, send = createSmtpSender(config)): Promise<boolean> {
  const conn = await pool.getConnection();
  let row: OutboxRow | undefined;
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query<OutboxRow[]>(
      "SELECT id,recipient,encrypted_payload,attempts FROM auth_mail_outbox WHERE sent_at IS NULL AND next_attempt_at<=UTC_TIMESTAMP(3) AND (lease_until IS NULL OR lease_until<UTC_TIMESTAMP(3)) ORDER BY next_attempt_at LIMIT 1 FOR UPDATE SKIP LOCKED",
    );
    row = rows[0];
    if (!row) { await conn.commit(); return false; }
    await conn.execute("UPDATE auth_mail_outbox SET lease_until=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 2 MINUTE),attempts=attempts+1 WHERE id=?", [row.id]);
    await conn.commit();
  } catch (err) { await conn.rollback(); throw err; }
  finally { conn.release(); }

  try {
    const message = JSON.parse(decryptMailPayload(row.encrypted_payload, config.encryptionKey)) as MailMessage;
    await send(row.recipient, message);
    await pool.execute("DELETE FROM auth_mail_outbox WHERE id=?", [row.id]);
  } catch {
    const seconds = Math.min(3600, 2 ** Math.min(row.attempts + 1, 10));
    await pool.execute("UPDATE auth_mail_outbox SET lease_until=NULL,next_attempt_at=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL ? SECOND) WHERE id=?", [seconds, row.id]);
  }
  return true;
}

export function startMailWorker(pool: Pool, config: MailConfig | null): () => void {
  if (!config) return () => undefined;
  let stopped = false;
  let running = false;
  const send = createSmtpSender(config);
  const timer = setInterval(() => {
    if (stopped || running) return;
    running = true;
    void deliverOneMail(pool, config, send).catch(() => undefined).finally(() => { running = false; });
  }, 1000);
  timer.unref();
  return () => { stopped = true; clearInterval(timer); };
}
