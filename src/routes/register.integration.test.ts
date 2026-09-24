import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { MySqlContainer, type StartedMySqlContainer } from "@testcontainers/mysql";
import type { Redis } from "ioredis";
import { createConnection, createPool, type Pool } from "mysql2/promise";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildApp } from "../router.js";
import { generateTestSigningKey } from "../test-support/signing-key.js";

// this file only exercises /register, which never touches redis — a stub is enough.
const stubRedis = {} as Redis;

const migrationSql = readFileSync(
  fileURLToPath(new URL("../../db/migrations/0001_init.up.sql", import.meta.url)),
  "utf8",
) + readFileSync(fileURLToPath(new URL("../../db/migrations/0002_login_lockout.up.sql", import.meta.url)), "utf8");

describe("POST /register", () => {
  let container: StartedMySqlContainer;
  let pool: Pool;
  let app: ReturnType<typeof buildApp>;

  beforeAll(async () => {
    container = await new MySqlContainer("mysql:8").withDatabase("auth").start();

    // apply the same DDL golang-migrate would run — a plain connection with
    // multipleStatements lets the whole migration file execute in one call.
    const setupConn = await createConnection({
      host: container.getHost(),
      port: container.getMappedPort(3306),
      user: container.getUsername(),
      password: container.getUserPassword(),
      database: container.getDatabase(),
      multipleStatements: true,
    });
    await setupConn.query(migrationSql);
    await setupConn.end();

    pool = createPool({
      host: container.getHost(),
      port: container.getMappedPort(3306),
      user: container.getUsername(),
      password: container.getUserPassword(),
      database: container.getDatabase(),
      waitForConnections: true,
      connectionLimit: 5,
    });

    const signingKey = await generateTestSigningKey();
    app = buildApp({ pool, redis: stubRedis, signingKey });
    await app.ready();
  }, 120_000);

  afterAll(async () => {
    await app.close();
    await pool.end();
    await container.stop();
  });

  it("creates a user and returns 201 with argon2id hash stored", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/register",
      payload: {
        email: "alice@example.com",
        password: "correct horse battery staple",
        display_name: "Alice",
        timezone: "Asia/Seoul",
      },
    });

    expect(response.statusCode).toBe(201);
    const body = response.json();
    expect(body.email).toBe("alice@example.com");
    expect(body.display_name).toBe("Alice");
    expect(body.timezone).toBe("Asia/Seoul");
    expect(typeof body.id).toBe("string");

    const [rows] = await pool.query("SELECT password_hash, status FROM users WHERE email = ?", [
      "alice@example.com",
    ]);
    const [row] = rows as Array<{ password_hash: string; status: string }>;
    expect(row.password_hash.startsWith("$argon2id$")).toBe(true);
    expect(row.status).toBe("active");
  });

  it("normalizes email and prevents concurrent duplicate accounts", async () => {
    const payload = {
      email: " Bob@Example.COM ",
      password: "another strong passphrase",
      display_name: " Bob ",
      timezone: "UTC",
    };

    const responses = await Promise.all([
      app.inject({ method: "POST", url: "/register", payload }),
      app.inject({ method: "POST", url: "/register", payload: { ...payload, email: "bob@example.com" } }),
    ]);
    expect(responses.map((response) => response.statusCode).sort()).toEqual([201, 409]);
    expect(responses.find((response) => response.statusCode === 201)?.json()).toMatchObject({
      email: "bob@example.com", display_name: "Bob",
    });
    expect(responses.find((response) => response.statusCode === 409)?.json()).toEqual({ error: "email_already_registered" });
    const [rows] = await pool.query("SELECT email, display_name FROM users WHERE email = ?", ["bob@example.com"]);
    expect(rows).toEqual([{ email: "bob@example.com", display_name: "Bob" }]);
  });
});
