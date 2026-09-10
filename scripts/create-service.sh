#!/usr/bin/env bash

set -Eeuo pipefail

readonly GENERATOR_VERSION="1"

usage() {
    cat <<'EOF'
Create a new Flashcards microservice from the repository template.

Usage:
  ./scripts/create-service.sh SERVICE_NAME "Service Display Name" [options]

Arguments:
  SERVICE_NAME             Lowercase kebab-case name, for example content-service.
  Service Display Name     Human-readable application name.

Options:
  --owner OWNER            Owning team or person (default: backend-team).
  --output PATH            Destination directory. Relative paths use the repository root.
                           Default: services/SERVICE_NAME.
  --template PATH          Template directory. Relative paths use the repository root.
                           Default: templates/fastapi-microservice.
  -h, --help               Show this help message.

Examples:
  ./scripts/create-service.sh content-service "Flashcards Content Service"
  ./scripts/create-service.sh study-service "Flashcards Study Service" \
    --owner learning-team
  ./scripts/create-service.sh reference-service "Reference Service" \
    --output /tmp/reference-service
EOF
}

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

require_value() {
    local option_name="$1"
    local option_value="${2:-}"
    [[ -n "$option_value" ]] || fail "$option_name requires a value"
}

resolve_from_repo() {
    local path="$1"
    if [[ "$path" = /* ]]; then
        printf '%s\n' "$path"
    else
        printf '%s/%s\n' "$repository_root" "$path"
    fi
}

if [[ "${1:-}" = "-h" || "${1:-}" = "--help" ]]; then
    usage
    exit 0
fi

if (( $# < 2 )); then
    usage >&2
    exit 64
fi

service_name="$1"
display_name="$2"
shift 2

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_directory/.." && pwd -P)"

owner="backend-team"
output_path="services/$service_name"
template_path="templates/fastapi-microservice"

while (( $# > 0 )); do
    case "$1" in
        --owner)
            require_value "$1" "${2:-}"
            owner="$2"
            shift 2
            ;;
        --output)
            require_value "$1" "${2:-}"
            output_path="$2"
            shift 2
            ;;
        --template)
            require_value "$1" "${2:-}"
            template_path="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

[[ "$service_name" =~ ^[a-z][a-z0-9]*(-[a-z0-9]+)*$ ]] ||
    fail "SERVICE_NAME must use lowercase kebab-case"
(( ${#service_name} <= 63 )) || fail "SERVICE_NAME must contain at most 63 characters"

[[ -n "${display_name//[[:space:]]/}" ]] || fail "display name cannot be empty"
(( ${#display_name} <= 100 )) || fail "display name must contain at most 100 characters"
[[ "$display_name" != *$'\n'* && "$display_name" != *$'\r'* ]] ||
    fail "display name must be a single line"
[[ "$display_name" != *'"'* && "$display_name" != *'\'* ]] ||
    fail 'display name cannot contain a double quote or backslash'

[[ "$owner" =~ ^[A-Za-z0-9][A-Za-z0-9._@/-]*$ ]] ||
    fail "owner contains unsupported characters"
(( ${#owner} <= 100 )) || fail "owner must contain at most 100 characters"

template_directory="$(resolve_from_repo "$template_path")"
output_directory="$(resolve_from_repo "$output_path")"

[[ -d "$template_directory" ]] ||
    fail "template directory does not exist: $template_directory"
[[ ! -e "$output_directory" ]] ||
    fail "destination already exists; refusing to overwrite: $output_directory"

required_template_files=(
    "pyproject.toml"
    "uv.lock"
    "Dockerfile"
    "README.md"
    ".env.example"
    "src/app/main.py"
)

for required_file in "${required_template_files[@]}"; do
    [[ -f "$template_directory/$required_file" ]] ||
        fail "template is missing required file: $required_file"
done

for required_command in rsync python3; do
    command -v "$required_command" >/dev/null 2>&1 ||
        fail "required command is not installed: $required_command"
done

generator_tmp_directory="$(mktemp -d "${TMPDIR:-/tmp}/flashcards-service-generator.XXXXXX")"

cleanup() {
    if [[ -n "${generator_tmp_directory:-}" && -d "$generator_tmp_directory" ]]; then
        rm -rf -- "$generator_tmp_directory"
    fi
}

trap cleanup EXIT INT TERM HUP

staged_service="$generator_tmp_directory/service"
mkdir -p "$staged_service"

rsync -a \
    --exclude='.git/' \
    --exclude='.github/' \
    --exclude='.venv/' \
    --exclude='.env' \
    --exclude='.pytest_cache/' \
    --exclude='.ruff_cache/' \
    --exclude='.mypy_cache/' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='compose.yaml' \
    --exclude='deploy/' \
    --exclude='docs/_build/' \
    "$template_directory/" \
    "$staged_service/"

FCB_SERVICE_NAME="$service_name" \
FCB_SERVICE_DISPLAY_NAME="$display_name" \
FCB_SERVICE_OWNER="$owner" \
FCB_GENERATOR_VERSION="$GENERATOR_VERSION" \
python3 - "$staged_service" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


service_root = Path(sys.argv[1])
service_name = os.environ["FCB_SERVICE_NAME"]
display_name = os.environ["FCB_SERVICE_DISPLAY_NAME"]
owner = os.environ["FCB_SERVICE_OWNER"]
generator_version = os.environ["FCB_GENERATOR_VERSION"]
project_name = f"flashcards-{service_name}"


def update_text_files() -> None:
    replacements = (
        ("FastAPI Microservice", display_name),
        ("fastapi-microservice", project_name),
    )
    ignored_parts = {".git", ".venv", "__pycache__", "_build"}

    for path in service_root.rglob("*"):
        if not path.is_file() or any(part in ignored_parts for part in path.parts):
            continue
        if path.name == "README.md":
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        updated = content
        for old, new in replacements:
            updated = updated.replace(old, new)
        if updated != content:
            path.write_text(updated, encoding="utf-8")


def update_environment_example() -> None:
    path = service_root / ".env.example"
    lines = path.read_text(encoding="utf-8").splitlines()
    expected = f"APP_NAME={display_name}"
    replaced = False
    for index, line in enumerate(lines):
        if line.startswith("APP_NAME="):
            lines[index] = expected
            replaced = True
            break
    if not replaced:
        lines.insert(0, expected)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def update_readme() -> None:
    path = service_root / "README.md"
    readme = f"""# {display_name}

- Service identifier: `{service_name}`
- Owning team: `{owner}`
- Generated from: `templates/fastapi-microservice`

## Responsibilities

Document the business capabilities owned by this service before adding domain
implementation. This service must not read another service's database or import
another service's internal Python modules.

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

## Ownership

Repository automation and service catalogs should read ownership metadata from
`OWNERS.yaml`. Template provenance is recorded in `TEMPLATE_METADATA.yaml`.
"""
    path.write_text(readme, encoding="utf-8")


def write_metadata() -> None:
    owner_json = json.dumps(owner, ensure_ascii=False)
    display_json = json.dumps(display_name, ensure_ascii=False)
    service_json = json.dumps(service_name, ensure_ascii=False)

    owners = f"""schemaVersion: \"1\"
service:
  id: {service_json}
  displayName: {display_json}
  owner: {owner_json}
  type: microservice
  lifecycle: experimental
"""
    (service_root / "OWNERS.yaml").write_text(owners, encoding="utf-8")

    template_metadata = f"""schemaVersion: \"1\"
template:
  name: fastapi-microservice
  source: templates/fastapi-microservice
  generatorVersion: {json.dumps(generator_version)}
"""
    (service_root / "TEMPLATE_METADATA.yaml").write_text(
        template_metadata,
        encoding="utf-8",
    )


def write_makefile_if_missing() -> None:
    path = service_root / "Makefile"
    if path.exists():
        return

    makefile = f"""SHELL := /bin/sh
IMAGE ?= {project_name}:local

.PHONY: install lint format-check typecheck test unit-test integration-test contract-test container-test docs image-build local-run migrate migration-check

install:
\tuv sync --all-groups --frozen

lint:
\tuv run ruff check

format-check:
\tuv run ruff format --check

typecheck:
\tuv run pyright

test:
\tuv run pytest

unit-test:
\t@if [ -d tests/unit ]; then uv run pytest tests/unit; else uv run pytest; fi

integration-test:
\t@if [ -d tests/integration ]; then uv run pytest tests/integration; else printf '%s\\n' 'Integration tests are not configured yet.'; fi

contract-test:
\t@if [ -d tests/contract ]; then uv run pytest tests/contract; else printf '%s\\n' 'Contract tests are not configured yet.'; fi

container-test:
\t@if [ -d tests/container ]; then uv run pytest tests/container; else printf '%s\\n' 'Container tests are not configured yet.'; fi

docs:
\tuv run --group docs sphinx-build -E -a -W --keep-going -b html docs docs/_build/html

image-build:
\tdocker build --tag $(IMAGE) .

local-run:
\tuv run uvicorn app.main:app --app-dir src --host 127.0.0.1 --port 8000 --reload

migrate:
\t@if [ -f alembic.ini ]; then uv run alembic upgrade head; else printf '%s\\n' 'Alembic is not configured for this service.'; exit 2; fi

migration-check:
\t@if [ -f alembic.ini ]; then uv run alembic check; else printf '%s\\n' 'Alembic is not configured for this service.'; exit 2; fi
"""
    path.write_text(makefile, encoding="utf-8")


update_text_files()
update_environment_example()
update_readme()
write_metadata()
write_makefile_if_missing()
PY

mkdir -p "$(dirname -- "$output_directory")"

if [[ -e "$output_directory" ]]; then
    fail "destination appeared during generation; refusing to overwrite: $output_directory"
fi

mv -- "$staged_service" "$output_directory"

printf 'Created service: %s\n' "$service_name"
printf 'Location: %s\n' "$output_directory"
printf 'Owner: %s\n' "$owner"
printf '\nNext steps:\n'
printf '  cd %q\n' "$output_directory"
printf '  uv lock --check\n'
printf '  uv sync --all-groups --frozen\n'
printf '  make lint format-check typecheck test\n'
printf '  make image-build\n'