# syntax=docker/dockerfile:1.27.0

ARG PYTHON_IMAGE=python:3.14.8-alpine3.24

FROM ghcr.io/astral-sh/uv:0.12.23 AS uv

FROM ${PYTHON_IMAGE} AS base

RUN apk upgrade --no-cache \
    && apk add --no-cache libstdc++

FROM base AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

COPY --from=uv /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock README.md ./

RUN uv sync --locked \
    --no-default-groups \
    --no-dev \
    --no-editable \
    --no-install-project

COPY src ./src

RUN uv sync --locked \
    --no-default-groups \
    --no-dev \
    --no-editable

FROM base AS runner

RUN /usr/local/bin/python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.14/ensurepip \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app -h /app app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]