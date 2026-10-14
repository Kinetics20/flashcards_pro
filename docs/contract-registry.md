# API and event contract registry

FCB-67 establishes an executable registry. FCB-70 adds cross-version compatibility
and full producer-consumer scenarios; FCB-65 will use the registry to select affected
consumers in CI. This change does not introduce a broker, production event publisher,
HTTP client SDK, or deck/card endpoints.

## Sources of truth

`contracts/registry.json` owns contract identity, semantic version, producer,
consumers, visibility, lifecycle, and deprecation metadata. The owner must match
`services/<producer>/OWNERS.yaml`. An empty consumers list means no implemented
service consumer is registered yet, not permission to omit future consumers.

For the existing `content-service`, application route declarations and Pydantic
request/response models remain the code-first HTTP source of truth. The build
exports the actual application's complete OpenAPI document, including its health
routes, in an isolated subprocess with controlled settings. It never starts the
application lifespan or connects to a database. The committed snapshot is checked
against a fresh export in CI. Its contract version is set explicitly by the
registry; it is independent of the process release version and OpenAPI dialect.

Event schemas and examples are schema-first files under `contracts/events/`.
The first event is reference-only: it is not evidence of a production publisher,
subscriber, delivery guarantee, or integration with a message broker.

Generated Python classes are transport DTOs derived from these schemas. They are
not domain models, generated FastAPI server implementations, or complete HTTP SDKs.
The initial service does not import these DTOs back into its code-first models:
doing so would create a circular generation dependency. Consumers can package the
generated artifacts through a separate release process later; services must not
import another service's internal `app` package.

## Layout and commands

Run all commands from the monorepo root:

```bash
uv sync --project .ci/security-tools --frozen
uv sync --project services/content-service --all-groups --frozen
uv run --project .ci/security-tools --no-sync python -m scripts.contracts.build --root .
uv run --project .ci/security-tools --no-sync python -m scripts.contracts.validate --root .
uv run --project .ci/security-tools --no-sync python -m scripts.contracts.build --root . --check
uv run --project .ci/security-tools --no-sync python -m pytest \
  -c .ci/security-tools/pyproject.toml scripts/tests/unit
uv run --project .ci/security-tools --no-sync python -m pytest \
  -c .ci/security-tools/pyproject.toml scripts/tests/integration/test_contract_registry.py
```

The tool environment is locked in `.ci/security-tools/uv.lock`. The generator,
validator, formatter settings, and target Python version are fixed. Generation is
offline once those environments are installed. Generated files contain no build
timestamp or machine-specific path. `--check` compares against fresh temporary
outputs without updating committed files; missing, stale, or extra output files
fail the check. Review and commit regenerated snapshots, DTOs, and HTML together.

Open `contracts/generated/docs/index.html` directly in a browser. The reference
contains ownership, lifecycle/deprecation fields, operations, models, and event
examples. It embeds no CDN scripts or externally loaded assets. The CI artifact
`contract-registry-reference` contains the same documentation and integration-test
results; download and extract it before opening the HTML.

## Shared wire conventions

Common JSON Schemas document the baseline for new endpoints/events:

- UUID identifiers are strings with the `uuid` format.
- Event timestamps use RFC 3339 UTC strings ending in `Z`.
- Trace identifiers use lowercase hexadecimal W3C-sized trace/span IDs. Request
  identifiers remain strings because the existing API does not guarantee UUIDs.
- The event envelope identifies the event, type, semantic schema version, source,
  occurrence time, correlation context, and typed payload.
- The existing error shape is `{ "error": { "code", "message", "request_id", "details" } }`.
  Optional fields retain the existing API's nullability. This convention does not
  claim that every framework-generated error already uses this shape.
- Pagination is a cursor-based convention for future collection endpoints, not
  a claim that a paginated deck API already exists.

Schema validation checks structure, local references, examples, UUIDs, and
timestamps. Unknown producers/consumers, owner mismatches, duplicate identifiers,
unsafe paths, unsupported reference forms, and invalid lifecycle metadata fail.
Remote reference retrieval is not part of the build. Generated DTOs are useful
typed boundaries but are not a complete replacement for JSON Schema validation;
keep schema-level validation for constraints not expressible in a DTO.
For example, the generated timestamp type accepts non-UTC offsets, while the
canonical schema requires a `Z` suffix. An optional trace object can be omitted,
but the event schema does not allow explicit `null`. Serialize the reference
event with `model_dump_json(exclude_none=True)` and validate the resulting wire
JSON against its schema. Integration tests demonstrate both these differences
and a fully schema-valid producer-to-consumer round trip.

## Versioning and deprecation

The contract's semantic version is not the `openapi` field (the specification
dialect), nor is it automatically the service's runtime version. Before a change,
review its wire-level impact with the producer owner and every registered consumer.
Use a major release for incompatible changes once a contract is stable, minor
for reviewed backward-compatible additions, and patch for non-breaking corrections.
For `0.x` contracts, explicitly review all wire changes rather than assuming
stability. Enum expansion, tighter validation, field removal, or new required
fields can break consumers. An additive response field is safe only if a given
consumer actually tolerates it; the generated client DTOs do.

The initial registry represents the currently checked versions. Keep historical
releases in immutable Git tags or release artifacts; do not silently rewrite a
published release. For a new current version, move its schema directory, update
the registry version/path, and regenerate all outputs in one reviewed PR. Parallel
major-version serving requires a later extension of the registry/export mapping;
do not pretend that an archived schema proves a live endpoint still exists.

To deprecate a contract, set its lifecycle and provide the deprecation start date,
sunset date, and replacement identifier according to the validator. Coordinate
the sunset with consumers and document migration steps in the PR. A removed
contract is a coordinated change, not just deleting a file. The HTML publishes
these fields even when the active contract has no deprecation dates.

FCB-67 checks current validity and generation drift. It does **not** yet compare
against the base branch for breaking changes or exercise retries, duplicates,
ordering, dead-letter queues, and replay. Those are explicit FCB-70 deliverables.

## Updating a contract

1. Update the actual API source or the event schema, then update version and
   ownership/consumer metadata as appropriate.
2. Add valid and invalid examples for new constraints. Register a real consumer
   before relying on it for impact selection.
3. Regenerate, inspect the schema/DTO/documentation diff, and run the commands above.
4. Run the normal repository quality and dependency/license gates. New tooling
   dependencies are covered by the existing FCB-62 supply-chain policy.
5. Include scope, consumers, compatibility considerations, and migration details
   in the PR. Require the `Contract registry` job through the aggregate `CI success`
   check as well as the existing checks.

## Troubleshooting

| Failure | Action |
|---|---|
| Service Python environment is missing | Sync the locked service environment first. |
| Registry metadata/ownership fails | Correct the metadata or producer's reviewed ownership record. |
| Invalid example or reference | Fix the schema/example or approved local reference; do not suppress validation. |
| Generated artifacts are stale | Run build without `--check`, inspect the diff, and commit it. |
| Unexpected generated file | Review whether it belongs to an old contract; remove it deliberately or move non-generated notes outside the generated directory. |
| Dependency/license job turns red | Review the new locked packages using the existing security procedure; do not disable the gate. |

## Primary references

- [OpenAPI specification](https://spec.openapis.org/oas/v3.1.1.html)
- [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core)
- [JSON Schema validation and formats](https://python-jsonschema.readthedocs.io/en/stable/validate/)
- [Generator CLI](https://datamodel-code-generator.koxudaxi.dev/cli-reference/)
- [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
