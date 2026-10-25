from __future__ import annotations

import json

import pytest

from scripts.ci import plan

TARGETS = [
    {"id": name, "kind": "service", "path": f"services/{name}", "lockfile_sha256": "a" * 64}
    for name in ("content-service", "study-service", "analytics-service")
] + [
    {
        "id": "template-fastapi",
        "kind": "template",
        "path": "templates/fastapi-microservice",
        "lockfile_sha256": "b" * 64,
    }
]
REGISTRY = {
    "contracts": [
        {
            "producer": "content-service",
            "consumers": ["study-service"],
            "schema_path": "contracts/openapi/content.json",
        },
        {
            "producer": "study-service",
            "consumers": ["analytics-service"],
            "schema_path": "contracts/events/study.json",
        },
    ]
}


@pytest.mark.parametrize(
    "paths,expected",
    [
        (["README.md", "docs/workflow.md", "adr/0001.md"], []),
        ([], []),
        (
            ["services/content-service/src/app/main.py"],
            ["analytics-service", "content-service", "study-service"],
        ),
        (["services/study-service/uv.lock"], ["analytics-service", "study-service"]),
        (["contracts/events/study.json"], ["analytics-service", "study-service"]),
        (
            ["services/analytics-service/removed.py", "services/study-service/renamed.py"],
            ["analytics-service", "study-service"],
        ),
    ],
)
def test_dependency_impact(paths, expected):
    assert plan.select_targets(TARGETS, REGISTRY, paths)[0] == expected


@pytest.mark.parametrize(
    "path",
    [
        "templates/fastapi-microservice/src/app/main.py",
        "contracts/registry.json",
        "contracts/common/problem.json",
        "scripts/create-service.sh",
        ".github/workflows/ci.yml",
        ".ci/security-tools/uv.lock",
        "compose.yaml",
        "services/deleted-service/src/app/main.py",
        "unknown-new-directory/file",
        "docs-not-really-code.py",
        "docs/build.py",
        "adr/check.sh",
    ],
)
def test_uncertain_changes_are_full(path):
    assert plan.select_targets(TARGETS, REGISTRY, [path])[0] == sorted(t["id"] for t in TARGETS)


def test_dependency_cycle_is_bounded_and_unknown_consumer_rejected():
    registry = {
        "contracts": [
            *REGISTRY["contracts"],
            {
                "producer": "analytics-service",
                "consumers": ["content-service"],
                "schema_path": "contracts/cycle.json",
            },
        ]
    }
    assert len(plan.select_targets(TARGETS, registry, ["services/study-service/file"])[0]) == 3
    registry["contracts"][-1]["consumers"] = ["unknown"]
    with pytest.raises(ValueError, match="outside"):
        plan.select_targets(TARGETS, registry, ["services/study-service/file"])


def commit(root, filename, text):
    file = root / filename
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text)
    plan.git(root, "add", "--", filename)
    plan.git(root, "commit", "-m", "fixture")
    return plan.git(root, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path):
    plan.git(tmp_path, "init", "-b", "main")
    plan.git(tmp_path, "config", "user.name", "CI fixture")
    plan.git(tmp_path, "config", "user.email", "fixture@example.invalid")
    plan.git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def test_pr_uses_merge_base_not_moving_base_tip(repository):
    first = commit(repository, "shared.txt", "base")
    plan.git(repository, "checkout", "-b", "feature")
    head = commit(repository, "services/content-service/change.py", "change")
    plan.git(repository, "checkout", "main")
    base = commit(repository, "unrelated-base-only.txt", "base advance")
    plan.git(repository, "merge", "--no-ff", "feature", "-m", "test merge")
    payload = {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
    paths, compared_base, compared_head = plan.changed_paths(repository, "pull_request", payload)
    assert paths == ["services/content-service/change.py"]
    assert (compared_base, compared_head) == (first, head)


def test_push_rename_deletion_and_spaces(repository):
    before = commit(repository, "services/old/deleted file.py", "same")
    plan.git(repository, "mv", "services/old/deleted file.py", "renamed file.py")
    plan.git(repository, "commit", "-m", "rename")
    after = plan.git(repository, "rev-parse", "HEAD")
    paths, _, _ = plan.changed_paths(repository, "push", {"before": before, "after": after})
    assert paths == ["renamed file.py", "services/old/deleted file.py"]
    with pytest.raises(ValueError, match="checkout"):
        plan.changed_paths(repository, "push", {"before": before, "after": before})


@pytest.mark.parametrize("filename", ["\nREADME.md", "README.md\n", "\nREADME.md\n"])
def test_nul_delimited_diff_preserves_newlines_in_filenames(repository, filename):
    before = commit(repository, "initial.txt", "base")
    after = commit(repository, filename, "not an allowlisted documentation path")
    paths, _, _ = plan.changed_paths(repository, "push", {"before": before, "after": after})
    assert paths == [filename]
    assert plan.select_targets(TARGETS, REGISTRY, paths)[0] == sorted(t["id"] for t in TARGETS)


@pytest.mark.parametrize("sha", ["HEAD", "--help", "0" * 40, "f" * 41, "f" * 63, "xyz", None])
def test_revision_rejects_ambiguous_or_option_input(tmp_path, sha):
    with pytest.raises(ValueError):
        plan.revision(tmp_path, sha)


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts/registry.json").write_text(json.dumps(REGISTRY))
    monkeypatch.setattr(plan, "discover", lambda root: {"commit": "c" * 40, "targets": TARGETS})
    monkeypatch.setattr(plan, "load_registry", lambda root: REGISTRY)
    monkeypatch.setattr(plan, "validate_registry_metadata", lambda *args: [])
    return tmp_path


@pytest.mark.parametrize("persistence_marker", ["alembic.ini", "src/app/platform/database.py"])
def test_database_service_never_silently_downgrades_to_asgi(inventory, persistence_marker):
    marker = inventory / "services/content-service" / persistence_marker
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("persistence marker")
    result = plan.build_plan(inventory, "workflow_dispatch", {})
    target = next(t for t in result["targets"] if t["id"] == "content-service")
    assert target["integration_profile"] == "postgres"
    if persistence_marker.endswith("database.py"):
        assert not (inventory / "services/content-service/alembic.ini").exists()


@pytest.mark.parametrize(
    "event,payload",
    [
        ("workflow_dispatch", {}),
        ("schedule", {}),
        ("merge_group", {}),
        ("pull_request", {}),
        ("push", {"before": "0" * 40, "after": "1" * 40}),
        ("push", {"before": "f" * 40, "after": "1" * 40}),
    ],
)
def test_unavailable_comparison_falls_back_full(inventory, event, payload):
    result = plan.build_plan(inventory, event, payload)
    assert result["selected"] == sorted(t["id"] for t in TARGETS)
    assert result["comparison_base"] is None
    assert result["baseline"] == "full-security-unit-coverage-and-image-checks"


def test_current_plan_is_deterministic_and_verified(inventory, monkeypatch):
    monkeypatch.setattr(
        plan, "changed_paths", lambda *args: (["docs/readme.md"], "a" * 40, "b" * 40)
    )
    result = plan.build_plan(inventory, "workflow_dispatch", {})
    assert result["selected"] == []
    assert plan.digest(result) == plan.digest(dict(reversed(list(result.items()))))
    source = inventory / "plan.json"
    source.write_text(json.dumps(result))
    monkeypatch.setattr(plan, "context", lambda *args: ("workflow_dispatch", {}))
    assert plan.expected_plan(inventory, source) == result
    source.write_text(json.dumps({**result, "selected": ["content-service"]}))
    with pytest.raises(ValueError, match="does not match"):
        plan.expected_plan(inventory, source)


def test_bad_registry_is_a_failure_not_a_skip(inventory, monkeypatch):
    monkeypatch.setattr(plan, "validate_registry_metadata", lambda *args: ["unknown consumer"])
    with pytest.raises(ValueError, match="unknown consumer"):
        plan.build_plan(inventory, "workflow_dispatch", {})
    assert plan.main(["--root", str(inventory)]) == 2


def test_context_and_cli(inventory, monkeypatch):
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    assert plan.context() == ("workflow_dispatch", {})
    event = inventory / "event.json"
    event.write_text("{}")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    assert plan.context() == ("schedule", {})
    output, github = inventory / "plan.json", inventory / "github-output"
    assert (
        plan.main(
            ["--root", str(inventory), "--output", str(output), "--github-output", str(github)]
        )
        == 0
    )
    assert "has_targets=true" in github.read_text()
    assert (
        plan.main(
            [
                "--root",
                str(inventory),
                "--output",
                str(output),
                "--event",
                "schedule",
                "--event-path",
                str(event),
            ]
        )
        == 0
    )
    event.write_text("[]")
    with pytest.raises(ValueError, match="object"):
        plan.context()
