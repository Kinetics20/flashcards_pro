# FastAPI Microservice Template

A clean, production-oriented Python 3.14 and FastAPI starter extracted from the
same conventions used by the FrameML API. It contains infrastructure and
quality foundations without carrying any FrameML business logic.

## Included

- `uv` dependency management with a committed lockfile
- `src/` package layout and a FastAPI application factory
- component-oriented, validated environment configuration
- versioned routes under `/api/v1`
- liveness and readiness probes outside the public API version
- structured JSON logs and `X-Request-ID` correlation
- safe, consistent error responses and sanitized validation errors
- configurable CORS and request-body limits
- non-root, read-only-friendly Docker image and Docker Compose
- Kubernetes Deployment and Service example
- Ruff, strict Pyright, pytest coverage, tox, pip-audit, and Sphinx
- GitHub Actions CI and Dependabot configuration

The template tracks the latest stable Python feature release and pins current
stable library/tool versions in `pyproject.toml` and `uv.lock`. Dependabot
checks Python, Docker, and GitHub Actions updates weekly.

The baseline intentionally has no database, broker, authentication provider,
or domain example. Add only the infrastructure required by the service you are
building.

## Create a service from this template

When using GitHub's template flow:

```shell
gh repo create my-service \
  --template pawelkonior/fastapi-microservice-template \
  --private \
  --clone
cd my-service
```

For a plain clone:

```shell
git clone https://github.com/pawelkonior/fastapi-microservice-template.git my-service
cd my-service
rm -rf .git
git init
```

Then update the project metadata in `pyproject.toml` and the defaults in
`.env.example`.

## Local setup

Install `uv`, then run:

```shell
cp .env.example .env
uv sync --all-groups
uv run uvicorn app.main:app --app-dir src --reload
```

Open:

- API status: <http://127.0.0.1:8000/api/v1/status>
- Swagger UI: <http://127.0.0.1:8000/docs>
- OpenAPI: <http://127.0.0.1:8000/openapi.json>
- Liveness: <http://127.0.0.1:8000/health/live>
- Readiness: <http://127.0.0.1:8000/health/ready>

Configuration uses `APP_` variables. Unknown `APP_` names fail fast so that a
misspelled production setting cannot be silently ignored. Documentation is
enabled by default for local development and must be disabled in production.

## Quality gate

Run the same checks as CI:

```shell
uv sync --all-groups --frozen
uv run pip-audit --skip-editable
uv run tox run-parallel
docker build --tag fastapi-microservice:local .
```

Individual checks:

```shell
uv run ruff check
uv run ruff format --check
uv run pyright
uv run pytest
uv run --group docs sphinx-build -E -a -W --keep-going -b html docs docs/_build/html
```

## Containers

Run the service locally:

```shell
docker compose up --build --wait
docker compose ps
```

Stop it with `docker compose down`.

The image runs as UID/GID `10001`, listens on port `8000`, writes logs to
standard output, and exposes a Docker health check. The Compose definition also
drops Linux capabilities and uses a read-only root filesystem.

## Project structure

```text
src/app/
├── core/                 # settings, application errors, context, logging
├── http/                 # router composition, DI, handlers, middleware
├── modules/              # feature-oriented vertical slices
│   ├── health/           # process probes
│   └── status/           # public service metadata
└── main.py               # application factory and lifespan only
deploy/kubernetes/        # deployment example
docs/                     # architecture and operations documentation
tests/                    # tests mirroring application boundaries
```

## Add a feature

Build business capabilities as vertical slices under
`src/app/modules/<feature>/`. Create a layer only when it has a real
responsibility. A database-backed feature will commonly use:

```text
src/app/modules/widgets/
├── __init__.py
├── model.py
├── schemas.py
├── repository.py
├── service.py
├── dependencies.py
├── exceptions.py
└── router.py
```

Keep the dependency direction one-way:

```text
router -> schema -> service -> repository -> persistence adapter
```

- Routers own HTTP input/output, status codes, and dependencies.
- Schemas own request validation and response serialization.
- Services own use cases and business rules; they do not import FastAPI.
- Repositories own persistence queries; they do not commit or return HTTP
  responses.
- Dependencies compose services and adapters at the HTTP edge.
- Application exceptions contain no HTTP response logic.

Register the new router in `src/app/http/router.py`. If the service gains a
startup-critical resource such as a database, initialize and close it in the
lifespan, and add its check to `/health/ready`.

## Error contract

Expected application errors and validation failures use one stable envelope:

```json
{
  "error": {
    "code": "not_found",
    "message": "The requested resource was not found",
    "request_id": "d81ee0d6-1d77-4477-a66f-f7afca8369f3"
  }
}
```

Unexpected exceptions are logged with their request ID and returned as a
generic `500` response. Validation responses never reflect submitted values or
validator context, which reduces accidental secret exposure.

## Production checklist

- Change the package metadata and application name/version.
- Set `APP_ENVIRONMENT=production` and `APP_DOCS_ENABLED=false`.
- Configure exact CORS origins only when browser access is required.
- Add authentication and authorization at the HTTP boundary.
- Add real readiness checks for startup-critical resources.
- Build and pin an immutable image tag in the Kubernetes manifest.
- Configure CPU/memory limits, replicas, autoscaling, and disruption policy for
  the workload.
- Keep secrets outside Git and inject them through the deployment platform.
