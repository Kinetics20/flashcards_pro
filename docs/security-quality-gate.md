# Security and quality gates

The root CI workflow checks every service, the FastAPI template and the isolated
CI Python environment on pull requests, pushes to `main`, manual runs and the
weekly schedule. Path-aware selection belongs to FCB-65 and is intentionally not
implemented here. The schedule runs on Monday at 03:17 UTC from the default
branch; GitHub may delay scheduled runs.

## Policy

`security/policy.json` is the reviewed source of thresholds. The initial policy is:

| Check | Blocking result |
| --- | --- |
| Gitleaks | Any detected secret; no secret exceptions |
| pip-audit | Any known vulnerability without a valid exact exception |
| Image / IaC / Compose | HIGH or CRITICAL findings, and unclassified security findings |
| Python dependency licenses | Missing, unknown or non-approved complete license expression |
| Coverage | Combined line-and-branch coverage below 90% in any project or overall |
| Evidence | Missing, malformed, mismatched or failed scanner/test reports |
| Exceptions | Invalid, expired or overly broad entries, even if unused |

`pip-audit` has no consistent severity field, so it is not filtered to HIGH and
CRITICAL. The absence of a fix does not hide a finding. Unknown severity must
never be interpreted as LOW. Critical findings cannot be excepted.

The Python license gate uses metadata from every installed locked dependency
group, including development/documentation tools. It excludes only the exact
first-party project identity. It is intentionally **not** a complete legal
review. License expressions require explicit approval, not substring matching:
`MIT OR GPL-3.0-only` is not approved merely because `MIT` appears in it. Ambiguous
metadata such as `BSD License` requires investigation; do not guess an SPDX ID.
Image license reports are retained for review, but OS-package licenses are not
evaluated with the Python allowlist.

## Run locally

Run these commands from the repository root after copying in the implementation:

```bash
uv sync --project .ci/security-tools --frozen
uv run --project .ci/security-tools --frozen python -m scripts.security.gate validate-policy --root .
uv run --project .ci/security-tools --frozen python -m scripts.security.discover_targets --root . --output reports/manifest.json
uv run --project .ci/security-tools --frozen python -m pytest scripts/tests/unit
```

The scanner installer supports the platforms recorded in `security/tools.lock.json`:
Linux x86-64 for CI and macOS arm64 for local work. It also requires uv, Git and a
working Docker Engine/Compose installation for the relevant phases, plus network
access to release assets and vulnerability data. Unsupported platforms fail;
do not edit checksums or silently substitute a system binary to bypass this.

```bash
uv run --project .ci/security-tools --frozen python -m scripts.security.run_scans \
  --phase repository --root . --output reports --install-tools

uv run --project .ci/security-tools --frozen python -m scripts.security.run_scans \
  --phase python --root . --target content-service --output reports --install-tools

uv run --project .ci/security-tools --frozen python -m scripts.security.run_scans \
  --phase tests --root . --target content-service --output reports
```

Repeat the Python and test phases for **every** target in `reports/manifest.json`,
including `template-fastapi` and `repo-security-tools`. Each service and template
also needs an image report from the exact locally built image, for example:

```bash
docker build --tag flashcards-content-service:local services/content-service
image_id="$(docker image inspect --format '{{.Id}}' flashcards-content-service:local)"
uv run --project .ci/security-tools --frozen python -m scripts.security.run_scans \
  --phase image --root . --target content-service --image "$image_id" \
  --output reports --install-tools

uv run --project .ci/security-tools --frozen python -m scripts.security.gate evaluate --root . \
  --manifest reports/manifest.json --reports reports
uv run --project .ci/security-tools --frozen python -m scripts.security.aggregate_coverage --root . \
  --manifest reports/manifest.json --reports reports
```

A partial local run intentionally fails complete-repository evaluation. It is not
permission to remove expected targets or fabricate success reports. CI runs every
phase for every declared target and also preserves generator conformance checks.
Use a fresh report directory for a new run; do not mix artifacts from commits,
run attempts or local environments.

Keep service/template `.dockerignore` files aligned with the generator exclusions:
`reports/`, `.coverage*`, `coverage.xml`, `coverage.json`, `htmlcov/` and `.tox/`
must not enter the image build context. The generator regression tests seed these
artifacts in a temporary copy of the real template and verify that the generated
service excludes them without changing the source template.

## Investigate a red CI run

1. Open the first failed job, not only the final `CI success` job.
2. Download its `evidence-*` artifact, or the final `security-quality-results`.
3. Check the target, checked-out commit, scanner version, status and artifact
   hashes. A PR run normally checks GitHub's merge commit, not the PR head SHA.
4. Distinguish a finding from a scanner failure. An unavailable vulnerability
   database, failed installation or malformed report means the scan did not
   establish safety. Restore the dependency/tool service and rerun it.
5. Fix the underlying issue, rerun the relevant phase, then run full CI.

For a secret, revoke/rotate the credential first, then remove it from source and
assess history cleanup with the repository owner. Removing only the current line
does not remove the value from Git history. Do not post raw secrets in issues,
exceptions, screenshots or CI artifacts. Redaction is enabled in Gitleaks reports.

For a vulnerability, identify the affected direct/transitive package, upgrade the
appropriate dependency constraint, regenerate that project's `uv.lock`, inspect
the lockfile diff and rerun tests plus scans. Base-image fixes require rebuilding
and rescanning; the image report identifies the actual local image ID. A local
image has no registry digest until it is published, so the report does not invent
one.

For a license finding, inspect the installed distribution and upstream license,
confirm its exact expression, then replace the dependency or propose a reviewed
policy/alias correction. The scanner does not provide legal authorization.

For Compose or IaC findings, fix the reported configuration or propose a narrowly
scoped temporary exception. `docker compose config` checks normalization/syntax;
the separate Compose rules check risky runtime settings. Local development
defaults may be deliberately rejected by the policy and need an explicit review.
Neither these rules nor Trivy prove that a deployment is secure. Helm/Terraform
directories containing only README files do not constitute scanned deployments.

## Exceptions

`security/exceptions.json` starts with an empty `exceptions` array. Add an entry
only with reviewed evidence and a tracked remediation issue. Required fields are
`id`, `check`, `target`, `finding_id`, `owner`, `reason`, `tracking_issue`,
`created_at`, `expires_at` and `compensating_control`. Package findings additionally
require the exact `package` and `version`; IaC/Compose findings need the exact
`path` copied from the report. Wildcard selectors are not accepted.

Dates use `YYYY-MM-DD`; an exception expires at 00:00 UTC on `expires_at`, not at
the end of that date. The maximum lifetime is 30 days. Expired entries block CI
even when their original finding is no longer present: remove the stale entry
with a reviewed change. Test failures, missing reports, coverage failures and
secrets are not suppressible. CRITICAL findings are never suppressed.

For an unclassified dependency finding, include a `severity_review` object with
the exact `finding_id`, a noncritical `severity`, `reviewed_by`, `reviewed_at` and
an HTTPS `source` linking to the actual advisory. This records a human assessment;
it does not make the declared assessment automatically trustworthy. Reviewers
must inspect it. Validate before pushing:

```bash
uv run --project .ci/security-tools --frozen python -m scripts.security.gate validate-policy --root .
```

Require review of policy, exception, scanner and workflow changes through
repository branch rules/CODEOWNERS appropriate to the team. A string in an
`owner` field is not evidence of approval. Configure the `CI success` check as a
required check in repository branch rules; committing YAML does not configure
those settings.

## Coverage and test evidence

The aggregate is calculated from counters, never by averaging percentages:

```text
100 * SUM(lines-covered + branches-covered)
    / SUM(lines-valid + branches-valid)
```

The same 90% minimum applies to each declared coverage target and the total.
Branch coverage is included in that combined percentage; this is not a separate
90% branch-only threshold. Missing, duplicate, zero-denominator or wrong-commit
reports fail. Percentages are not rounded upward to pass a threshold.

Services/templates run their existing tox test, lint, type and documentation
environments. CI captures JUnit and coverage XML without requiring developers to
change application test settings. Security tooling tests cover the repository
automation independently. Template coverage is counted once from the template
itself; the generated reference service is a separate conformance check and is
not counted a second time in the aggregate.

Offline unit tests exercise policy, exception scope/expiry, malformed/missing
evidence, coverage arithmetic and Compose rules. The mandatory scanner integration
job checks actual Gitleaks detection using a synthetic secret constructed in a
temporary directory and actual Trivy detection using a known-vulnerable dependency fixture.
It does not install the vulnerable package. A scanner crash is not a passing
negative test.

## Artifacts, pins and updates

Reports include commit/run provenance, scanner identity, policy/exception/tool
lock hashes and hashes of raw evidence. Image artifacts include a CycloneDX SBOM,
vulnerability results and license inventory. Vulnerability database metadata is
recorded because new advisories can change the outcome for the same commit.
CI uploads available evidence even when a check fails. The final job verifies
completeness; publishing a partial artifact does not make the workflow pass.

Artifacts are retained for 30 days on PR/push/manual runs and 90 days on scheduled
runs, subject to the repository/organization retention limit. Do not cache reports
or credentials. Dependency caches are not security evidence.

The binary versions/download checksums are in `security/tools.lock.json`;
Python tools and transitive dependencies are in `.ci/security-tools/uv.lock`.
GitHub Actions use full upstream commit SHA pins. Update pins through reviewed
PRs, verify release hashes from official upstream releases, regenerate Python
locks with uv and run unit plus scanner integration tests. A pinned binary still
uses evolving vulnerability data; pinning is not proof that software is safe.

This initial implementation is scoped to the repository's Python projects,
Docker images and current infrastructure files. Introducing another language,
ecosystem, deployment format or external artifact requires extending discovery,
scanner coverage and the expected-evidence contract before relying on these gates.

## References

- [Gitleaks CLI and configuration](https://github.com/gitleaks/gitleaks)
- [pip-audit behavior and limitations](https://github.com/pypa/pip-audit)
- [pip-licenses environment selection](https://github.com/raimon49/pip-licenses)
- [Trivy Python coverage](https://trivy.dev/docs/dev/guide/coverage/language/python/)
- [Trivy SBOM support](https://trivy.dev/docs/latest/supply-chain/sbom/)
- [GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub scheduled workflow semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
