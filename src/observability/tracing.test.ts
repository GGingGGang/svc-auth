import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createTracerProvider } from "./tracing.js";

const originalExporter = process.env.OTEL_TRACES_EXPORTER;

afterEach(() => {
  if (originalExporter === undefined) delete process.env.OTEL_TRACES_EXPORTER;
  else process.env.OTEL_TRACES_EXPORTER = originalExporter;
});

describe("tracing exporter configuration", () => {
  it("exports spans through the configured exporter when OTLP is enabled", async () => {
    process.env.OTEL_TRACES_EXPORTER = "otlp";
    const exporter = new InMemorySpanExporter();
    const factory = vi.fn(() => exporter);
    const provider = createTracerProvider(factory);

    provider.getTracer("test").startSpan("request").end();
    await provider.forceFlush();

    expect(factory).toHaveBeenCalledOnce();
    expect(exporter.getFinishedSpans().map((span) => span.name)).toEqual(["request"]);
    await provider.shutdown();
  });

  it("does not create an exporter or export spans when tracing is disabled", async () => {
    process.env.OTEL_TRACES_EXPORTER = "none";
    const factory = vi.fn(() => new InMemorySpanExporter());
    const provider = createTracerProvider(factory);

    provider.getTracer("test").startSpan("request").end();
    await provider.forceFlush();

    expect(factory).not.toHaveBeenCalled();
    await provider.shutdown();
  });
});
