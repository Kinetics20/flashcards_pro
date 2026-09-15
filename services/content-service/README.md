# Flashcards Backend

Backend monorepo for the Flashcards application.

## Repository structure

- `services/` — independently buildable backend microservices.
- `templates/` — source templates used by the service generator.
- `contracts/` — OpenAPI specifications and event schemas.
- `infrastructure/` — infrastructure architecture and shared platform documentation.
- `deploy/helm/` — Kubernetes application Helm charts.
- `deploy/terraform/` — Terraform-managed infrastructure.
- `adr/` — architecture decision records.
- `docs/` — repository-level documentation.
- `scripts/` — repository automation.

## Services

| Service | Responsibility | Owner | Local port |
|---|---|---|---|
| `content-service` | Deck and card management | `backend-team` | `8002` |

## Local development

Prerequisites:

- Python 3.14
- uv
- Docker with Docker Compose
- rsync

Start the backend:

```bash
docker compose up --build --wait

```

Stop the backend:

```bash

docker compose down

```

## Creating a service

```bash

./scripts/create-service.sh \
  study-service \
  "Flashcards Study Service" \
  --owner backend-team

```

See `docs/service-lifecycle.md` for the complete process.

## Testing

Run the quality gate inside a service directory:

```bash

uv sync --all-groups --frozen
uv run pip-audit --skip-editable
uv run tox run-parallel
make docs
make image-build

```

## Architecture rules
- Services must not import internal modules from another service.
- Services must not access another service's database.
- Cross-service communication must use declared API or event contracts.
- Shared contracts must not contain service domain models.
- Every service must remain independently testable and buildable.

Run the boundary validation with:

```bash

python3 scripts/check-service-boundaries.py

```

## Service ownership
Every service must declare its owner in OWNERS.yaml.
Updating the template
Update `templates/fastapi-microservice`, increment the generator version when necessary, and verify the change by generating a temporary service.

Existing services must be upgraded through explicit pull requests.

## Removing a service
Follow the dependency, data-retention, deployment, contract, and documentation steps described in `docs/service-lifecycle.md`.