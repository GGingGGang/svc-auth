import { propagation, ROOT_CONTEXT, SpanKind, SpanStatusCode, type Span } from "@opentelemetry/api";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { tracer } from "./tracing.js";

declare module "fastify" {
  interface FastifyRequest {
    otelSpan?: Span;
  }
}

// Minimal HTTP server instrumentation (../../PLAN.md §8.2): one span per
// request, parented off an incoming `traceparent` header when present, plus
// trace_id/span_id bound onto the request's logger so every subsequent log
// line for this request satisfies the §8.1 JSON log schema. Attributes are
// limited to method/route/status — no email/user_id/raw path (§8.1 PII ban).
export function registerHttpTracing(app: FastifyInstance): void {
  app.decorateRequest("otelSpan", undefined);

  app.addHook("onRequest", async (req: FastifyRequest, reply: FastifyReply) => {
    const parentContext = propagation.extract(ROOT_CONTEXT, req.headers);
    const method = req.method;
    const route = req.routeOptions.url ?? "not_found";

    const span = tracer.startSpan(
      `${method} ${route}`,
      {
        kind: SpanKind.SERVER,
        attributes: {
          "http.request.method": method,
          "http.route": route,
        },
      },
      parentContext,
    );

    req.otelSpan = span;
    const { traceId, spanId } = span.spanContext();
    const boundLogger = req.log.child({ trace_id: traceId, span_id: spanId });
    // reply.log starts out as a separate reference captured when the Reply
    // object was built, so it has to be rebound too — otherwise Fastify's
    // built-in "request completed" log (which logs through reply.log, not
    // request.log) keeps using the unbound logger.
    req.log = boundLogger;
    reply.log = boundLogger;
  });

  app.addHook("onResponse", async (req: FastifyRequest, reply: FastifyReply) => {
    const span = req.otelSpan;
    if (!span) return;

    span.setAttribute("http.response.status_code", reply.statusCode);
    if (reply.statusCode >= 500) {
      span.setStatus({ code: SpanStatusCode.ERROR });
    }
    span.end();
  });
}
