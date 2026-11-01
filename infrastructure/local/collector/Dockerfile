# syntax=docker/dockerfile:1.27.0
# The upstream static collector is retained; Alpine adds a real HTTP health probe.
FROM otel/opentelemetry-collector-contrib:0.162.0@sha256:39923a8e431bd1f57be82411999d389fcfe40857492e4365456d97a4c1f74be6 AS collector
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=collector /otelcol-contrib /usr/local/bin/otelcol-contrib
USER 10001:10001
EXPOSE 4317 4318 13133
HEALTHCHECK --interval=3s --timeout=3s --retries=30 CMD wget -q -O /dev/null http://127.0.0.1:13133/ || exit 1
ENTRYPOINT ["/usr/local/bin/otelcol-contrib"]
