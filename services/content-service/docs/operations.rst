Operations
==========

Configuration
-------------

Settings are read from ``APP_`` environment variables and an optional ``.env``
file. Unknown ``APP_`` names fail startup. Production mode rejects enabled API
documentation.

Health probes
-------------

``/health/live`` proves that the process can answer HTTP requests.
``/health/ready`` indicates whether the instance should receive traffic. When
``APP_DATABASE_ENABLED=true``, startup pings the service-owned PostgreSQL
database, and readiness reports its availability with a bounded check. An
unavailable database returns HTTP 503 without exposing connection details.
Liveness never queries the database. OTLP collector availability does not affect
readiness.

Persistence
-----------

Database support is disabled by default. When enabled, provide an untracked
``APP_DATABASE_URL`` using ``postgresql+asyncpg`` and the service's own database
credentials. Pool limits and connection timeouts are validated. Sessions require
an explicit commit; exceptions trigger rollback. The engine is disposed during
shutdown and after failed startup.

Run ``uv run --frozen alembic upgrade head`` with the database configuration
before application startup. The initial revision has no domain tables. The
application does not automatically migrate on each replica's startup. Runtime
images include ``alembic.ini`` and ``migrations/`` for an explicit migration job.

Logging
-------

Logs are JSON on standard output. A validated incoming ``X-Request-ID`` is
preserved; an absent or unsafe value is replaced with a UUID. The same ID is
added to responses, access logs, error responses, and can be propagated to
outbound HTTP calls with ``outbound_correlation_headers``.
Active trace and span identifiers are included when available. Tracing and
metrics export are opt-in through ``APP_TELEMETRY_ENABLED`` and
``APP_METRICS_ENABLED``. Enabled export requires an OTLP gRPC endpoint without
credentials, query strings, fragments or a URL path. Export failures do not
make the application unready. Authorization and cookie headers are not captured.

Containers
----------

The container runs as an unprivileged user on port 8000. The supplied Compose
service uses a read-only root filesystem and a temporary ``/tmp`` mount.
