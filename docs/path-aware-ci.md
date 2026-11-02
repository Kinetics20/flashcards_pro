# Change-aware integration CI (FCB-65)

## Scope and invariants

The workflow optimizes **additional runtime integration tests**, not the security
baseline. Every current project still runs the complete unit/lint/type/documentation
suite, dependency and license checks, image build/smoke/security checks, and aggregate
unit coverage. Repository security, template conformance and the contract registry
also remain mandatory. This is deliberately a partial cost optimization: FCB-62's
complete evidence inventory and coverage denominator are not weakened.

No existing test is replaced with a placeholder. Content currently has no database
runtime or domain endpoints: its selected integration profile exercises real FastAPI
lifespan and HTTP handling. The template's PostgreSQL profile additionally exercises
the existing Alembic chain, a real SQL transaction/rollback, database-aware readiness,
startup failure and engine disposal. The initial migration is empty; its round trip
proves migration plumbing, not future card/deck schema correctness.

Registered consumers receive their own runtime checks when a producer changes.
There are currently no registered downstream services. The full FCB-67 contract job
continues exercising actual API payloads and generated transport DTOs. Future service
business integrations must extend these tests; a dependency edge does not invent a
consumer's missing business functionality.

## Planning rules

`python -m scripts.ci.plan` uses the checked-out repository, validated service inventory
and contract ownership/consumer registry. It does not fetch or execute a PR artifact.

| Input | Additional integration scope |
| --- | --- |
| PR | `merge-base(base.sha, head.sha)..head.sha`; tests run on the checked-out merge commit |
| Push | `before..after`; `after` must equal the tested checkout |
| Manual or scheduled run | Every service and template |
| Missing history, new branch zero SHA, unknown event | Every service and template |
| Service change | Service and transitive contract consumers |
| Registered schema change | Producer, consumers and their transitive consumers |
| Template, registry, shared contract refs, tooling, workflow, unknown or removed project | Every service and template |
| Only root README/CONTRIBUTING or known documentation text/image files under docs/adr | No additional runtime matrix; full baseline still runs |

Rename detection is disabled when listing changed paths so both deleted and added
paths contribute to impact. NUL-delimited paths preserve embedded/leading newlines;
they cannot accidentally become allowlisted documentation names. Broken registry ownership/unknown consumers fail planning
instead of silently omitting checks. Git revisions must be full 40/64-character hex
commit IDs; shell expressions and branch names are never interpolated as commands.
All planning jobs fetch full history. An unavailable comparison is expensive but safe:
it selects everything.

## Evidence and required checks

`execution-plan` uploads `ci-execution-plan` with a seven-day retention. Its matrix
contains only inventory-derived target IDs. A job-level `if` guards the empty matrix.

Each selected job independently recomputes the plan before installing its target's
frozen environment and executing tests. It uploads only that target's JUnit/status
files as `ci-runtime-<target>`, also for seven days. These artifact names deliberately
do not match FCB-62's `evidence-*` download pattern.

`integration-evidence` always runs. It rejects failed/cancelled planning or required
test jobs, independently recomputes the plan again, and requires exact selected target
coverage, matching commit/plan hashes, zero test exit status, the JUnit SHA-256 and the
complete expected capability test names. DTDs, inconsistent counters, empty suites,
failures and skipped selected tests fail validation. An empty matrix is accepted only
when a valid recomputed plan genuinely selects no integration targets.

Keep **CI success** as the stable required branch-protection check. It requires both
planning and integration-evidence in addition to all existing checks. Do not configure
individual dynamic matrix job names as the sole protection. When FCB-70 is merged,
keep its contract-compatibility job independently mandatory; path selection must not
make it optional. If a merge queue is later enabled, add `merge_group` to the workflow
events: the planner already safely treats it as a full run. No `pull_request_target`
workflow is used.

## Caching and retention

uv dependency caching remains keyed by setup-uv's platform/Python/cache inputs and
the explicit lockfile glob. Every install still uses `--frozen`; a cache hit is not a
test or dependency-audit result. No `.env`, credentials, test reports or PostgreSQL
data are cached.

Buildx uses the GitHub cache backend with a separate `fcb-<target>-<architecture>`
scope per image. BuildKit's content-addressed build graph invalidates changed inputs;
the scope name is not used as proof that an image is current. Only final-image layers
are exported (`mode=min`). Pull requests, including forks, restore eligible caches
but do not export image caches. No image is pushed. The built image is loaded once,
resolved to its immutable local ID, and the same ID is smoked and scanned.

GitHub manages cache eviction, not artifact `retention-days`: caches unused for seven
days are evicted and repository storage limits also apply (default allowance 10 GB;
administrators may change it). Cache misses/evictions must not change the required
checks. New integration artifacts expire after seven days; existing security evidence
retains its established 30-day/90-day scheduled policy. Do not cache secrets because
fork PRs may read eligible base-branch caches. A trusted workflow/code review remains
necessary: these integrity checks detect inconsistent evidence, not a malicious PR
that rewrites the entire checker.

## Local verification

Run from the monorepo root. Docker must be available for the PostgreSQL profile.
The fixture uses a pinned multi-architecture official PostgreSQL image, a generated
test-only password, a unique container name/label and a random loopback host port.
Before yielding the database, it waits up to 30 seconds for an authenticated
`SELECT 1` through that host port. A socket probe inside the container can report
the temporary initialization server as ready before the final TCP server starts.
Only the exact created container and its anonymous volume are removed in `finally`.
No Compose environment, existing database or unrelated Docker resource is reset.
Creation itself is inside that cleanup scope. If `docker run` fails after creating
the container, cleanup resolves its preassigned UUID name, checks the ownership label
and removes only the resolved matching ID. An unavailable Docker daemon can prevent
cleanup; restore connectivity and inspect that exact test name rather than pruning.
The PostgreSQL integration profile is required when either the database runtime or
Alembic configuration is present (and always for the FastAPI template). Removing
only Alembic configuration therefore fails required tests instead of downgrading to ASGI.
The test interpreter uses `-I` and a fresh temporary working directory, with inherited
`APP_*` variables removed. Alembic uses an absolute configuration path in that same
empty directory, and receives only the fixture's database configuration with telemetry
disabled. This prevents module-level application imports and migration settings from
reading a developer's repository/project `.env`.

```bash
uv sync --project .ci/security-tools --frozen
uv sync --project services/content-service --all-groups --frozen
uv sync --project templates/fastapi-microservice --all-groups --frozen
uv run --project .ci/security-tools --frozen python -m pytest \
  -c .ci/security-tools/pyproject.toml scripts/tests/unit \
  --cov=scripts/security --cov=scripts/contracts --cov=scripts/ci --cov-branch \
  --cov-config=.ci/security-tools/pyproject.toml

# A unique directory prevents accidentally reusing stale results from a previous run.
mkdir -p reports/local
run_dir="$(mktemp -d "$(pwd)/reports/local/run.XXXXXX")"
uv run --project .ci/security-tools --frozen python -m scripts.ci.plan \
  --event workflow_dispatch --output "$run_dir/ci-plan.json"
GITHUB_EVENT_NAME=workflow_dispatch GITHUB_EVENT_PATH= \
uv run --project .ci/security-tools --frozen python -m scripts.ci.run_integration run \
  --plan "$run_dir/ci-plan.json" --reports "$run_dir/results" --target content-service
GITHUB_EVENT_NAME=workflow_dispatch GITHUB_EVENT_PATH= \
uv run --project .ci/security-tools --frozen python -m scripts.ci.run_integration run \
  --plan "$run_dir/ci-plan.json" --reports "$run_dir/results" --target template-fastapi
GITHUB_EVENT_NAME=workflow_dispatch GITHUB_EVENT_PATH= \
uv run --project .ci/security-tools --frozen python -m scripts.ci.run_integration verify \
  --plan "$run_dir/ci-plan.json" --reports "$run_dir/results"
```

Use a fresh output directory after each commit or retry. A missing status after a
timeout is a failure, not an exception to evidence requirements. Additional new
projects must be included in the local run by reading the plan's `selected` list.

## Primary references

- [Git diff comparison semantics](https://git-scm.com/docs/git-diff)
- [Compose/project isolation is separate from this disposable test fixture](https://docs.docker.com/compose/how-tos/project-name/)
- [Docker GitHub cache backend and scope](https://docs.docker.com/build/cache/backends/gha/)
- [GitHub cache access and eviction](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [Required checks and skipped workflows](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/troubleshooting-required-status-checks)
