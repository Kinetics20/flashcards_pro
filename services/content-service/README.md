# Flashcards Content Service

Service identifier: `content-service`
Owning team: `backend-team`
Generated from: `templates/fastapi-microservice`

## Responsibilities

Will own deck, card, category, and difficulty metadata used by the Flashcards application.
The current foundation exposes status and health endpoints only; domain models,
CRUD endpoints and domain seeds have not been implemented yet.

The service must not access another service's database or import another service's internal modules.

## Local setup

```shell
cp .env.example .env
make install
make local-run
```

The application listens on <http://127.0.0.1:8000> by default.

## Endpoints

- API status: <http://127.0.0.1:8000/api/v1/status>
- Swagger UI: <http://127.0.0.1:8000/docs>
- OpenAPI: <http://127.0.0.1:8000/openapi.json>
- Liveness: <http://127.0.0.1:8000/health/live>
- Readiness: <http://127.0.0.1:8000/health/ready>

## Quality gate

The versioned API snapshot and generated transport types live in the
[contract registry](../../contracts/README.md). Follow the
[contract maintainer guide](../../docs/contract-registry.md) when changing an
endpoint or response schema. Generated DTOs are transport artifacts, not shared domain models.

```shell
make lint
make format-check
make typecheck
make test
make docs
make image-build
```

## Runtime image

The container runs as a non-root user, listens on port `8000`, writes structured
logs to standard output, and exposes a liveness health check.

## Configuration

Configuration uses validated `APP_` environment variables. Copy `.env.example`
for local development. Never commit `.env` files or production secrets.

PostgreSQL, trace export and metric export are disabled by default. Enabling
`APP_DATABASE_ENABLED` requires a `postgresql+asyncpg` URL for the database owned
by this service. Startup checks that database; readiness returns 503 when it is
unavailable, while liveness remains independent of it. Database sessions do not
commit implicitly. The engine is disposed on shutdown, including startup failure.

Run migrations as an explicit deployment step before starting the application:

```shell
uv run --frozen alembic upgrade head
```

This command requires the generated database environment or a local untracked
`.env`. The initial migration establishes the Alembic revision only; there are
no domain tables. Migration files are included in the runtime image. Do not run
automatic migrations from every application replica's lifespan.

For local OTLP gRPC export, configure `APP_TELEMETRY_OTLP_ENDPOINT` and enable
`APP_TELEMETRY_ENABLED` and/or `APP_METRICS_ENABLED`. The exporter is not a
readiness dependency. Request logs include request/trace/span identifiers;
telemetry does not capture authorization or cookie headers.

## Ownership

Repository automation and service catalogs should read ownership metadata from
`OWNERS.yaml`. Template provenance is recorded in `TEMPLATE_METADATA.yaml`.
