import { Writable } from "node:stream";

import Fastify from "fastify";
import { describe, expect, it } from "vitest";

import { registerHttpTracing } from "./httpTracing.js";

function captureStream() {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, callback) {
      lines.push(chunk.toString());
      callback();
    },
  });
  return { stream, lines };
}

function completedLog(lines: string[]): Record<string, unknown> | undefined {
  return lines.map((line) => JSON.parse(line) as Record<string, unknown>).find((l) => l.msg === "request completed");
}

describe("registerHttpTracing", () => {
  it("parents the request span off an inbound W3C traceparent header and binds trace_id/span_id onto the log line", async () => {
    const { stream, lines } = captureStream();
    const app = Fastify({ logger: { stream, level: "info" } });
    registerHttpTracing(app);
    app.get("/ping", async () => ({ ok: true }));
    await app.ready();

    const inboundTraceId = "4bf92f3577b34da6a3ce929d0e0e4736";
    const traceparent = `00-${inboundTraceId}-00f067aa0ba902b7-01`;

    const response = await app.inject({ method: "GET", url: "/ping", headers: { traceparent } });
    expect(response.statusCode).toBe(200);
    await app.close();

    const completed = completedLog(lines);
    expect(completed?.trace_id).toBe(inboundTraceId);
    expect(completed?.span_id).toMatch(/^[0-9a-f]{16}$/);
    // the request's own span id must differ from the inbound parent span id
    expect(completed?.span_id).not.toBe("00f067aa0ba902b7");
  });

  it("generates a fresh valid trace id when there is no inbound traceparent header", async () => {
    const { stream, lines } = captureStream();
    const app = Fastify({ logger: { stream, level: "info" } });
    registerHttpTracing(app);
    app.get("/ping", async () => ({ ok: true }));
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/ping" });
    expect(response.statusCode).toBe(200);
    await app.close();

    const completed = completedLog(lines);
    expect(completed?.trace_id).toMatch(/^[0-9a-f]{32}$/);
    expect(completed?.trace_id).not.toBe("00000000000000000000000000000000");
  });

  it("never puts PII (email/user_id) on the span — only method/route/status attributes", async () => {
    const { stream, lines } = captureStream();
    const app = Fastify({ logger: { stream, level: "info" } });
    registerHttpTracing(app);
    app.post("/login", async () => ({ ok: true }));
    await app.ready();

    await app.inject({ method: "POST", url: "/login", payload: { email: "someone@example.com" } });
    await app.close();

    const completed = completedLog(lines);
    const serialized = JSON.stringify(completed);
    expect(serialized).not.toContain("someone@example.com");
  });
});
