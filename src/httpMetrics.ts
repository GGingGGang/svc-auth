import { Counter, Histogram } from "prom-client";
import type { FastifyInstance, FastifyRequest } from "fastify";

const requests = new Counter({
  name: "auth_http_requests_total",
  help: "HTTP requests handled by svc-auth",
  labelNames: ["method", "route", "status_code"] as const,
});
const duration = new Histogram({
  name: "auth_http_request_duration_seconds",
  help: "HTTP request duration in seconds for svc-auth",
  labelNames: ["method", "route", "status_code"] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5],
});
const starts = new WeakMap<FastifyRequest, bigint>();

// Route templates keep IDs, emails, tokens, and arbitrary URLs out of labels.
export function registerHttpMetrics(app: FastifyInstance): void {
  app.addHook("onRequest", async (request) => {
    starts.set(request, process.hrtime.bigint());
  });
  app.addHook("onResponse", async (request, reply) => {
    const method = request.method;
    const route = request.routeOptions.url ?? "unmatched";
    const status = String(reply.statusCode);
    const labels = { method, route, status_code: status };
    requests.inc(labels);
    const start = starts.get(request);
    if (start !== undefined) duration.observe(labels, Number(process.hrtime.bigint() - start) / 1e9);
  });
}

export function authHttpMetrics(): { requests: Counter; duration: Histogram } {
  return { requests, duration };
}

export function resetHttpMetricsForTest(): void {
  requests.reset(); duration.reset();
}
