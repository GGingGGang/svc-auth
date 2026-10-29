import { describe, expect, it, vi } from "vitest";
import { parseDeletionResult, superviseDeletionResults } from "./deletionWorker.js";

const ack = {
  event_id: "0190f0a0-1234-7123-8123-123456789abc",
  request_id: "0190f0a0-5678-7123-8123-123456789abc",
  service: "notify",
  status: "completed",
  occurred_at: "2026-10-29T10:00:00.000Z",
};

describe("account deletion result delivery", () => {
  it("accepts the cross-service ACK contract and rejects malformed or incomplete ACKs", () => {
    expect(parseDeletionResult(ack)).toEqual(ack);
    expect(() => parseDeletionResult({ ...ack, service: "web" })).toThrow("invalid_deletion_ack");
    expect(() => parseDeletionResult({ ...ack, event_id: "x" })).toThrow("invalid_deletion_ack");
    const { occurred_at: _omitted, ...missingTimestamp } = ack;
    expect(() => parseDeletionResult(missingTimestamp)).toThrow("invalid_deletion_ack");
  });

  it("retries consumer acquisition after the stream or durable is temporarily unavailable", async () => {
    let stopped = false;
    let lookups = 0;
    let delivered = 0;
    const getMessages = vi.fn(async () => {
      lookups++;
      if (lookups === 1) throw new Error("not provisioned yet");
      return (async function* () {
        yield "ack";
        delivered++;
        stopped = true;
      })();
    });
    const wait = vi.fn(async () => undefined);

    await superviseDeletionResults(getMessages, async () => undefined, () => stopped, wait, () => undefined);

    expect(getMessages).toHaveBeenCalledTimes(2);
    expect(wait).toHaveBeenCalledTimes(1);
    expect(delivered).toBe(1);
  });
});
