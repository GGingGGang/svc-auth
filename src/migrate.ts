import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { RowDataPacket } from "mysql2/promise";

import { createMigrationConnection } from "./db.js";

const migrationsUrl = new URL("../db/migrations/", import.meta.url);
const migrationsDir = fileURLToPath(migrationsUrl);

export async function migrateUp(): Promise<void> {
  const conn = await createMigrationConnection();
  try {
    const [lockRows] = await conn.query<RowDataPacket[]>("SELECT GET_LOCK('svc_auth_schema_migrations', 30) AS acquired");
    if (lockRows[0]?.acquired !== 1) throw new Error("could not acquire auth migration lock");

    try {
      await conn.query("CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT NOT NULL PRIMARY KEY, dirty BOOLEAN NOT NULL)");
      const [rows] = await conn.query<RowDataPacket[]>("SELECT version, dirty FROM schema_migrations");
      if (rows.length > 1 || rows[0]?.dirty) throw new Error("auth migration history is dirty or invalid");

      let version = Number(rows[0]?.version ?? 0);
      const files = (await readdir(migrationsDir)).filter((name) => /^\d+_.*\.up\.sql$/.test(name)).sort();
      for (const file of files) {
        const next = Number(file.slice(0, file.indexOf("_")));
        if (next <= version) continue;
        if (next !== version + 1) throw new Error(`missing auth migration after version ${version}`);

        const sql = await readFile(new URL(file, migrationsUrl), "utf8");
        await conn.query("INSERT INTO schema_migrations (version, dirty) VALUES (?, TRUE)", [next]);
        await conn.query(sql);
        await conn.query("DELETE FROM schema_migrations WHERE version = ?", [version]);
        await conn.query("UPDATE schema_migrations SET dirty = FALSE WHERE version = ?", [next]);
        version = next;
      }
    } finally {
      await conn.query("SELECT RELEASE_LOCK('svc_auth_schema_migrations')");
    }
  } finally {
    await conn.end();
  }
}
