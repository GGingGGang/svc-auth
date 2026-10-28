import type { Pool, RowDataPacket } from "mysql2/promise";

export async function isActiveUser(pool: Pool, userId: string): Promise<boolean> {
  const [rows] = await pool.query<RowDataPacket[]>(
    "SELECT status FROM users WHERE id = UUID_TO_BIN(?)",
    [userId],
  );
  return rows[0]?.status === "active";
}

export async function activeCredentialVersion(pool: Pool, userId: string): Promise<number | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    "SELECT credential_version FROM users WHERE id = UUID_TO_BIN(?) AND status = 'active'",
    [userId],
  );
  const version = rows[0]?.credential_version;
  if (version === undefined) return null;
  const parsed = Number(version);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}
