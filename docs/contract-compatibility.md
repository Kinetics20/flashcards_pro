# Contract compatibility and reference delivery

## Scope

FCB-70 adds compatibility checks against an exact Git commit and executable reference producer/consumer fixtures. It does not implement a production event publisher, transactional outbox, Study Service, or business projection.

The existing Content Service status endpoint supplies the HTTP reference. The event reference uses a real NATS JetStream server in a separate, temporary Compose project. SQLite is a test projection/inbox store, not a replacement for service-owned PostgreSQL databases.

## Supported bindings

`contracts/registry.json` owns contract metadata and schema locations. `contracts/support.json` maps every registered contract to a family, exact version, transport locator and explicitly implemented fixture. The fixture identifier comes from a code allowlist; JSON cannot name arbitrary Python modules or shell commands.

Keep the existing reference event v1 while adding v2. The new version requires aggregate identity, aggregate sequence and trace context; silently adding those requirements to v1 would break its existing contract. The legacy reference is not a recommended format for new production events.

A version bump alone is never an exemption. Existing supported IDs, versions and bindings must remain available. A parallel replacement needs its own schema, ID, locator, generated DTOs and executable adapter. The fixture suite must exercise the declared bindings. Removing old support requires a separately designed retirement process; changing lifecycle metadata does not bypass this gate.

Versions are dispatched exactly. An old generated DTO with a version constant does not automatically accept a new minor version. Additive-field tolerance and accepting another version number are separate capabilities.

## Compatibility check

From the repository root, after installing the frozen tooling and Content Service environments:

```bash
CONTRACT_BASE_SHA=$(git merge-base origin/main HEAD)
uv run --project .ci/security-tools --no-sync python \
  -m scripts.contracts.compatibility --root . --base "$CONTRACT_BASE_SHA" \
  --install-tools --output reports/contracts/compatibility.json
```

For a local uncommitted task based directly on `main`, this compares committed baseline contracts with the working-tree candidate. Before interpreting the result, verify that the chosen SHA is the intended pre-change baseline. Do not compare a changed contract against itself and call that a migration check.

The command reads regular Git blobs from the baseline without checking it out or executing its Python code. It validates both registries and their local reference graphs. The initial FCB-70 PR may compare against FCB-67 without a support sidecar; the older contracts are still compared and cannot be removed or rewritten incompatibly.

OpenAPI is checked with pinned, checksum-verified `oasdiff`. External reference retrieval is disabled. The current exporter uses internal references; introducing external file references requires a reviewed offline bundling implementation. Tool installation may need network access even though schema resolution does not.

The event comparator is deliberately conservative. It accepts annotation changes and proven optional-property additions under the reference consumer's additive-field policy. It blocks removed fields, changed constraints and unsupported changes. It is not a general proof engine for arbitrary JSON Schema language inclusion. Local referenced schemas are included, so changing a common UUID or timestamp definition cannot evade comparison by leaving the top-level event file unchanged.

An unrecognized or unprovable change fails the check. Do not downgrade it to a warning or add a blanket bypass. Preserve the old supported version and add a reviewed adapter for a new version where appropriate. Semantic changes that retain the same schema still require human review and behavioral tests. [OpenAPI change analysis](https://github.com/oasdiff/oasdiff/blob/v1.33.0/docs/DIFF.md).

## Wire validation and generated DTOs

The producer validates the canonical schema before and after DTO serialization. Generated Pydantic models do not preserve every JSON Schema constraint.

The reference consumer validates known fields while allowing unknown object properties, then parses the generated client model. It must still reject invalid UUIDs, timestamps, trace fields, constants and unsupported versions. It does not disable validation for the entire message merely to tolerate additions. Map-valued constraints and other known validation rules remain significant.

## Delivery policy

The reference runtime atomically records the projection effect and event ID in SQLite, commits, and only then acknowledges the message. Reopening the store after a simulated failure before ACK demonstrates deduplication beyond one in-memory consumer object. Reusing an event ID for different content is a conflict, not a second business event.

Publisher deduplication and consumer idempotency are distinct. The producer waits for JetStream PubAck and uses `Nats-Msg-Id`; the consumer still needs its durable inbox. Replay retains business event identity while using an appropriate transport publication identity or a new consumer. [JetStream publishing and deduplication](https://docs.nats.io/learn/jetstream/advanced-publishing).

Temporary failures use bounded delayed NAK retries. Invalid payloads and unsupported versions enter quarantine. A DLQ publication must receive PubAck before the source delivery is acknowledged. The fixture also handles persisted maximum-delivery advisories so an exhausted delivery is observable after a worker failure. JetStream does not create a DLQ automatically, and consumer backoff does not delay a plain NAK. [Acknowledgment and exhausted deliveries](https://docs.nats.io/learn/jetstream/acknowledgment).

For v2, only the next aggregate sequence can update the projection. Gaps and stale conflicting events are quarantined, not silently reordered or applied. An event rejected for a gap is not recorded as a successfully applied inbox item; it can be replayed after the missing predecessor. Legacy v1 has no aggregate-ordering guarantee.

The reference streams have bounded message count, size and retention. File storage is backed by temporary test storage in Compose: this tests consumer recovery and replay within the test lifetime, not production broker backup, multi-node durability or recovery after deleting the test container.

## Run the reference suite

Docker must be available. Required broker tests fail when Docker or NATS cannot start; absence is not treated as a successful skip.

```bash
uv run --project .ci/security-tools --no-sync python -m pytest \
  -c .ci/security-tools/pyproject.toml \
  scripts/tests/integration/test_contract_registry.py \
  scripts/tests/integration/test_contract_delivery.py \
  --junitxml=reports/contracts/delivery-junit.xml
```

The delivery fixture owns a unique Compose project and an ephemeral loopback port. Cleanup targets that project only. Do not replace scoped cleanup with Docker-wide pruning. Existing unrelated containers and volumes are outside the fixture's ownership.

Run all tooling unit tests, registry validation, generation drift checks, Ruff, dependency/license scans and policy validation as well. The FCB-67 reference HTTP tests use FastAPI TestClient; do not interpret those ASGI assertions as a network/load test. Read the delivery test names and validation report for the separate TCP/broker assertions.

## CI and diagnostics

The mandatory `contract-compatibility` job uses the PR merge base, the previous push commit, or the first parent for manual/scheduled runs. A missing baseline fails comparison rather than silently skipping it. Manual/scheduled runs execute all fixtures but do not claim to compare every historical release.

Delivery tests run even when compatibility comparison reports a breaking change, unless the workflow is cancelled. Results are uploaded as `contract-compatibility-results`, separate from FCB-62 security evidence. `CI success` requires this job to pass.

Read `reports/contracts/compatibility.json` for contract IDs and comparison failures, and the JUnit report for the failing behavior. Reference logs use stable outcome codes and correlation identifiers without logging complete payloads. Fixture counters are test diagnostics, not an installed production metrics backend.
