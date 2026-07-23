import { propagation, trace } from "@opentelemetry/api";
import { CompositePropagator, W3CBaggagePropagator, W3CTraceContextPropagator } from "@opentelemetry/core";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-grpc";
import { detectResources, envDetector, resourceFromAttributes } from "@opentelemetry/resources";
import { BasicTracerProvider, BatchSpanProcessor, type SpanProcessor } from "@opentelemetry/sdk-trace-base";

const SERVICE_NAME = "auth";

// W3C TraceContext + Baggage propagation is installed unconditionally — it only
// parses/writes the `traceparent`/`tracestate`/`baggage` headers and costs
// nothing when no exporter is configured.
propagation.setGlobalPropagator(
  new CompositePropagator({
    propagators: [new W3CTraceContextPropagator(), new W3CBaggagePropagator()],
  }),
);

const resource = resourceFromAttributes({ "service.name": SERVICE_NAME }).merge(
  detectResources({ detectors: [envDetector] }),
);

// Export only when a collector is actually configured (../../PLAN.md §8.2 —
// start with OTEL_TRACES_EXPORTER=none while no collector is deployed). The
// TracerProvider itself is always real, so every span still gets a valid
// trace/span id for log correlation even while export is off — only the
// span processor (and therefore the outbound OTLP dial) is conditional.
const spanProcessors: SpanProcessor[] =
  process.env.OTEL_TRACES_EXPORTER === "otlp" ? [new BatchSpanProcessor(new OTLPTraceExporter())] : [];

const tracerProvider = new BasicTracerProvider({ resource, spanProcessors });
trace.setGlobalTracerProvider(tracerProvider);

export const tracer = trace.getTracer(SERVICE_NAME);

export async function shutdownTracing(): Promise<void> {
  await tracerProvider.shutdown();
}
