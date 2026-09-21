import type { Redis } from "ioredis";
import type { Pool } from "mysql2/promise";
import { describe, expect, it, vi } from "vitest";

import { readyz } from "./health.js";

function replyStub() {
  const reply = {
    code: vi.fn(),
    send: vi.fn(),
  };
  reply.code.mockReturnValue(reply);
  reply.send.mockReturnValue({ status: "not_ready" });
  return reply;
}

describe("readyz", () => {
  it("is ready only when MySQL and Redis are reachable", async () => {
    const pool = { query: vi.fn().mockResolvedValue([[{ 1: 1 }], []]) } as unknown as Pool;
    const redis = { ping: vi.fn().mockResolvedValue("PONG") } as unknown as Redis;
    const reply = replyStub();

    await expect(readyz(pool, redis)({}, reply as never)).resolves.toEqual({ status: "ready" });
    expect(reply.code).not.toHaveBeenCalled();
  });

  it("returns 503 without exposing dependency errors", async () => {
    const pool = { query: vi.fn().mockRejectedValue(new Error("database password leaked")) } as unknown as Pool;
    const redis = { ping: vi.fn() } as unknown as Redis;
    const reply = replyStub();

    await expect(readyz(pool, redis)({}, reply as never)).resolves.toEqual({ status: "not_ready" });
    expect(reply.code).toHaveBeenCalledWith(503);
    expect(reply.send).toHaveBeenCalledWith({ status: "not_ready" });
  });
});
