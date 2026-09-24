import type { Pool, RowDataPacket } from "mysql2/promise";

export async function isActiveUser(pool: Pool, userId: string): Promise<boolean> {
  const [rows] = await pool.query<RowDataPacket[]>(
    "SELECT status FROM users WHERE id = UUID_TO_BIN(?)",
    [userId],
  );
  return rows[0]?.status === "active";
}
