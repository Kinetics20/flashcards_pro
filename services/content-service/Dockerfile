# syntax=docker/dockerfile:1.27.0

ARG PYTHON_IMAGE=python:3.14.8-slim-trixie

FROM ghcr.io/astral-sh/uv:0.12.18 AS uv

FROM ${PYTHON_IMAGE} AS base

RUN apt-get update \
    && apt-get install --yes --only-upgrade --no-install-recommends \
        libpcre2-8-0 \
        libssl3t64 \
        openssl \
        openssl-provider-legacy \
        liblzma5 \
    && rm -rf /var/lib/apt/lists/*

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
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app \
        --home-dir /app --no-create-home app

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