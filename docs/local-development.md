# Local backend environment

**Validation status (2026-10-14): functional candidate, security gate blocked.**
The complete local lifecycle integration passes, but the pinned infrastructure
images contain findings rejected by the repository policy. Do not treat this
configuration as merge-ready or production-approved. In particular, the scan
reports vulnerable Go runtime/network dependencies in SeaweedFS and the collector,
OS libraries in NGINX and Keycloak, and the unused-in-this-nonroot-setup `gosu`
binary in the PostgreSQL image. The NATS scan also flags `GO-2026-5932`: that advisory concerns
the OpenPGP subpackages, so module presence alone is not proof of reachability.
Neither automatic suppression nor a claim of non-exploitability is justified by
the current integration tests. The mandatory gate remains enabled.

Resolving this requires reviewed patched image/build choices and, where relevant,
package-level applicability evidence. Do not silently add exceptions or strip
scanner metadata. Re-run the complete lifecycle and immutable-image scan after
any image change. Current package/image decisions and the remaining blocker must
be resolved before merging FCB-60.

The local stack provides infrastructure for the existing Content API. It does not
implement card/deck domain endpoints, API authentication, production event
publishers, or business seed data. SeaweedFS is the explicitly approved local S3
replacement for the historical MinIO requirement in FCB-60. This choice does not
select a production object-storage provider or update Jira automatically.

## Prerequisites and startup

Use Docker with the modern `docker compose` plugin supporting profiles and
`up --wait`, Python 3.14, and the repository's pinned uv toolchain.
Start Docker before running the stack. Run commands from the repository root:

```bash
python3 -m scripts.local.stack --root . --project flashcards up --profile core
```

The helper prepares project-local configuration, preserves existing credentials,
builds the application, and waits for the selected long-running services to become
healthy. The migration container must finish successfully before the API starts.
Never commit or upload `.local/`, `.env`, rendered Compose JSON, or raw container
inspection output: these may contain credentials.

For observability and developer tools as well:

```bash
python3 -m scripts.local.stack --root . --project flashcards up --profile full
```

The `core`, `observability`, `tools`, and `test` Compose profiles describe different
local workloads. `full` is a helper convenience for core, observability and tools;
the one-shot test probe is invoked explicitly:

```bash
python3 -m scripts.local.stack --root . --project flashcards probe
```

Use the helper rather than sourcing an environment file into your interactive
shell. Configuration generation is idempotent: recreating passwords while
retaining initialized PostgreSQL volumes would break access to existing data.

## Responsibilities and endpoints

| Component | Responsibility | Default host endpoint |
|---|---|---|
| Gateway | Route the Content API and local OIDC provider | `http://127.0.0.1:18080` |
| Content API | Existing status/health API, database runtime and telemetry | `http://127.0.0.1:18002` |
| Content PostgreSQL | Content-owned database and Alembic revision | No host port |
| Identity PostgreSQL | Keycloak-owned database | No host port |
| Keycloak | Local `flashcards` realm and development OIDC client | Gateway `/auth/` |
| NATS JetStream | Authenticated, persistent messaging infrastructure | `127.0.0.1:14222` |
| Redis | Authenticated local cache/test storage | `127.0.0.1:16379` |
| SeaweedFS | Private, S3-compatible local object storage | `http://127.0.0.1:18333` |
| OTel collector | Receive local OTLP telemetry and expose diagnostic output | `127.0.0.1:14317` / `14318` |
| Adminer | Optional local database administration UI | `http://127.0.0.1:18081` |

Only loopback ports are published. Service-to-service connections use Compose DNS
names and container ports, not host ports or `localhost`. PostgreSQL ownership is
isolated through separate containers, credentials, volumes, and data networks.
An API container must not access another service's database.

The Content API uses PostgreSQL in this stack, but its standalone defaults still
disable the database and telemetry. NATS, Redis and S3 are verified as infrastructure
dependencies; the Content API does not yet use them for domain operations.

## Readiness, migrations and observability

`/health/live` checks the running process. `/health/ready` additionally checks the
configured required database and returns HTTP 503 when that dependency is
unavailable. Losing the collector is not a reason to remove an otherwise healthy
API from traffic. Compose health-based dependency ordering governs startup; it is
not a general runtime recovery controller.

Alembic is run by a one-shot migration job. A successful exit is the expected
state for that container, not a permanent `healthy` state. The initial migration
contains no domain tables. Do not interpret a successful migration as completed
deck/card functionality.

The observability profile enables actual application export to the collector.
Its diagnostic exporter is intended for local verification, not production
retention, a tracing UI, or a log archive. Do not send production personal data or
secrets through this development environment.

## OIDC scope

The public issuer is the gateway URL followed by `/auth/realms/flashcards`.
Discovery, JWKS, and a development client-credentials flow are tested. The issuer
must remain consistent with the published gateway port; an internal Docker DNS
name is not a browser-facing issuer URL.

Running Keycloak does not protect Content endpoints. Token validation, user
sessions, authorization, PKCE browser login, and application permissions belong
to the identity/security stories. Development client credentials are server-side
secrets and must never be embedded in a browser application.

## Persistence and shutdown

```bash
python3 -m scripts.local.stack --root . --project flashcards down
```

Normal shutdown preserves named volumes and generated credentials. Starting the
same project again reuses that state. Named volumes are not backups and a local
single-node stack is not highly available.

Redis uses AOF with `appendfsync everysec`: the restart test does not establish a
zero-data-loss guarantee after a host crash. JetStream and SeaweedFS also use
single-node local storage, not replicated production durability.

There is no general reset command in this task. FCB-59 will define domain seeds
and a separately guarded reset workflow. Never use global Docker pruning to
repair this stack. Disposable integration tests remove only their own randomly
named, ownership-labelled project resources.

## Verification and CI

Install locked tooling and run the real integration suite:

```bash
uv sync --project .ci/security-tools --frozen
FCB_RUN_LOCAL_STACK=1 uv run --project .ci/security-tools --no-sync python -m pytest \
  -c .ci/security-tools/pyproject.toml \
  scripts/tests/integration/test_local_stack.py \
  --junitxml=reports/local-stack/junit.xml
```

Tests own a unique Compose project and local configuration. They check functional
protocols, credentials, persistence, failure handling and cleanup, rather than
accepting container startup alone as proof. Missing Docker or a failed required
dependency is a failure, not a silently skipped test.

The image-identity report produced by this run is consumed by the additional
infrastructure security gate:

```bash
uv run --project .ci/security-tools --no-sync python -m scripts.security.infrastructure \
  --root . --identities reports/local-stack/images.json \
  --output reports/infrastructure --install-tools
```

Use current reports for the current commit. The gate verifies the complete image
inventory and immutable image identities; a moved tag or missing report fails.
The existing service/template security gates, complete unit coverage, contract
compatibility and path-aware runtime checks remain mandatory.

Standalone Compose inputs are listed in `security/compose-targets.json`. The
scanner renders all profiles with controlled, synthetic configuration and keeps
rendered secret-bearing data out of artifacts. An additional Compose input must
be classified explicitly; overlays are not silently treated as complete stacks.

## Local versus production

Loopback HTTP, a single-node broker/object store, diagnostic telemetry, local
credential files and Keycloak development mode are local conveniences. Production
requires its own TLS, secret management, storage/backup/restore policy, capacity,
identity hardening, lifecycle controls and Kubernetes deployment review. This
task does not deploy Helm charts, provision Terraform resources or make the local
stack a production-ready cluster.

Keycloak intentionally has a writable container filesystem because development
startup rebuilds Quarkus metadata. Other long-running services use read-only
root filesystems plus explicit writable mounts. The one-shot volume initializer
only adjusts the top-level ownership of its three named data volumes; it is not
a recursive data repair or reset operation.

## Tooling license metadata

The S3 integration test uses boto3 in the isolated CI tools environment, not in
the Content service. Its transitive dependency `python-dateutil==2.9.0.post0`
declares `Apache Software License; BSD License`. The policy maps exactly that
package, version and declaration to the already approved `BSD-3-Clause`
expression. The upstream release's LICENSE explicitly permits the BSD option for
all code, including code otherwise covered by Apache. This is a narrowly scoped
metadata normalization, not a global approval of ambiguous license labels or a
temporary exception. Regression tests reject a different package, version or
declaration. Recheck the license when upgrading the dependency.

## References

- [Compose profiles](https://docs.docker.com/compose/how-tos/profiles/)
- [Compose startup ordering](https://docs.docker.com/compose/how-tos/startup-order/)
- [Keycloak hostname and issuer configuration](https://www.keycloak.org/server/hostname)
- [SeaweedFS S3 API](https://github.com/seaweedfs/seaweedfs/wiki/Amazon-S3-API)
- [python-dateutil 2.9.0.post0 license](https://github.com/dateutil/dateutil/blob/2.9.0.post0/LICENSE)
