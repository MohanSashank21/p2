from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from app.core.config import settings


def configure_tracing(app: FastAPI) -> TracerProvider | None:
  if not settings.OTEL_TRACING_ENABLED:
    return None

  provider = TracerProvider(
    resource=Resource.create({SERVICE_NAME: settings.APP_NAME}),
  )
  provider.add_span_processor(
    BatchSpanProcessor(
      OTLPSpanExporter(endpoint=settings.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT),
    ),
  )
  trace.set_tracer_provider(provider)
  FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
  return provider
