Observability
=============

The service supports optional OpenTelemetry tracing and metrics export over
OTLP/gRPC. Both signals are disabled by default.

Configuration
-------------

``APP_TELEMETRY_ENABLED`` enables trace export and
``APP_METRICS_ENABLED`` enables metrics export. At least one enabled signal
requires ``APP_TELEMETRY_OTLP_ENDPOINT``. Export operations are bounded by
``APP_TELEMETRY_EXPORT_TIMEOUT_SECONDS``.

Resource attributes
-------------------

Every exported signal identifies ``service.name``, ``service.version``, and
``deployment.environment.name``.

Correlation
-----------

Structured logs include ``request_id``, ``trace_id``, and ``span_id``. Trace
fields contain ``-`` when no span is active.

Data protection
---------------

Request and response header values, authorization tokens, cookies, request
bodies, and connection credentials are not exported. The OTLP endpoint must
not contain credentials, query parameters, fragments, or a path.

Shutdown
--------

Instrumentation is removed and providers are flushed during graceful shutdown.
Exporter failures and timeouts are logged with safe static messages and do not
prevent the API from stopping.