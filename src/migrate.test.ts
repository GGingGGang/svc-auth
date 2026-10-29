import { beforeEach, expect, it, vi } from "vitest";

vi.mock("./db.js", () => ({ createMigrationConnection: vi.fn() }));

import { createMigrationConnection } from "./db.js";
import { migrateUp } from "./migrate.js";

const connect = vi.mocked(createMigrationConnection);

beforeEach(() => vi.resetAllMocks());

it("applies the pending account lifecycle and operator audit migrations", async () => {
  const statements: string[] = [];
  const conn = {
    query: vi.fn(async (sql: string) => {
      statements.push(sql);
      if (sql.includes("GET_LOCK")) return [[{ acquired: 1 }]];
      if (sql.includes("SELECT version, dirty")) return [[{ version: 3, dirty: 0 }]];
      return [[]];
    }),
    end: vi.fn(),
  };
  connect.mockResolvedValue(conn as never);

  await migrateUp();

  expect(statements.some((sql) => sql.includes("CREATE TABLE account_action_tokens"))).toBe(true);
  expect(statements.some((sql) => sql.includes("CREATE TABLE account_operator_audit"))).toBe(true);
  expect(conn.query).toHaveBeenCalledWith("INSERT INTO schema_migrations (version, dirty) VALUES (?, TRUE)", [4]);
  expect(conn.query).toHaveBeenCalledWith("INSERT INTO schema_migrations (version, dirty) VALUES (?, TRUE)", [5]);
  expect(conn.query).toHaveBeenCalledWith("DELETE FROM schema_migrations WHERE version = ?", [3]);
  expect(conn.query).toHaveBeenCalledWith("UPDATE schema_migrations SET dirty = FALSE WHERE version = ?", [4]);
  expect(conn.query).toHaveBeenCalledWith("DELETE FROM schema_migrations WHERE version = ?", [4]);
  expect(conn.query).toHaveBeenCalledWith("UPDATE schema_migrations SET dirty = FALSE WHERE version = ?", [5]);
  expect(conn.end).toHaveBeenCalledOnce();
});

it("stops before serving when migration history is dirty", async () => {
  const conn = {
    query: vi.fn(async (sql: string) => {
      if (sql.includes("GET_LOCK")) return [[{ acquired: 1 }]];
      if (sql.includes("SELECT version, dirty")) return [[{ version: 3, dirty: 1 }]];
      return [[]];
    }),
    end: vi.fn(),
  };
  connect.mockResolvedValue(conn as never);

  await expect(migrateUp()).rejects.toThrow("dirty or invalid");
  expect(conn.query.mock.calls.some(([sql]) => sql.includes("ADD COLUMN"))).toBe(false);
  expect(conn.end).toHaveBeenCalledOnce();
});
