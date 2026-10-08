"""Coverage must fail closed, including at rounding and provenance boundaries."""

from copy import deepcopy

import pytest

from scripts.security import aggregate_coverage as module
from scripts.security.common import sha256_file, write_json

COMMIT = "a" * 40


def manifest(*ids):
    return {
        "schema_version": 1,
        "commit": COMMIT,
        "targets": [{"id": name, "coverage": True, "checks": ["tests"]} for name in ids],
    }


def evidence(root, name="service-a", lines=(90, 100), branches=(0, 0)):
    folder = root / name
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "coverage.xml").write_text(
        f'<coverage lines-covered="{lines[0]}" lines-valid="{lines[1]}" '
        f'branches-covered="{branches[0]}" branches-valid="{branches[1]}"/>',
    )
    (folder / "junit.xml").write_text(
        '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
        '<testcase name="example"/></testsuite></testsuites>',
    )
    report = {
        "schema_version": 1,
        "commit": COMMIT,
        "target": name,
        "check": "tests",
        "status": "ok",
        "branch_coverage": True,
        "artifacts": [],
    }
    for filename in ("coverage.xml", "junit.xml"):
        report["artifacts"].append(
            {
                "path": f"{name}/{filename}",
                "sha256": sha256_file(folder / filename),
            }
        )
    write_json(folder / "tests.json", report)
    return report


def test_weighted_counts_not_mean_percentages(tmp_path):
    evidence(tmp_path, "small", (90, 100))
    evidence(tmp_path, "large", (100, 1000))
    result = module.aggregate(manifest("small", "large"), tmp_path)
    assert result["total"]["combined_percent"] == pytest.approx(100 * 190 / 1100)
    assert not result["passed"]
    assert result["complete"]


def test_good_total_does_not_hide_bad_target(tmp_path):
    evidence(tmp_path, "small", (0, 1))
    evidence(tmp_path, "large", (1000, 1000))
    result = module.aggregate(manifest("small", "large"), tmp_path)
    assert result["total"]["combined_percent"] > 90
    assert not result["passed"]


def test_combined_branches_and_no_rounding(tmp_path):
    evidence(tmp_path, lines=(100, 100), branches=(80, 100))
    result = module.aggregate(manifest("service-a"), tmp_path)
    assert result["passed"] and result["total"]["combined_percent"] == 90
    assert result["total"]["branch_percent"] == 80
    evidence(tmp_path, lines=(89999, 100000))
    assert not module.aggregate(manifest("service-a"), tmp_path)["passed"]


def test_missing_report_fails(tmp_path):
    result = module.aggregate(manifest("missing"), tmp_path)
    assert not result["passed"] and not result["complete"]
    assert result["total"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("commit", "b" * 40),
        ("target", "elsewhere"),
        ("status", "error"),
        ("branch_coverage", False),
        ("schema_version", 2),
        ("artifacts", None),
        ("artifacts", [42]),
    ],
)
def test_invalid_evidence_provenance(tmp_path, field, value):
    report = evidence(tmp_path)
    report[field] = value
    write_json(tmp_path / "service-a/tests.json", report)
    assert not module.aggregate(manifest("service-a"), tmp_path)["passed"]


def test_modified_artifact_and_duplicate_artifact(tmp_path):
    report = evidence(tmp_path)
    report["artifacts"].append(deepcopy(report["artifacts"][0]))
    write_json(tmp_path / "service-a/tests.json", report)
    assert not module.aggregate(manifest("service-a"), tmp_path)["passed"]
    evidence(tmp_path)
    (tmp_path / "service-a/coverage.xml").write_text("tampered")
    assert not module.aggregate(manifest("service-a"), tmp_path)["passed"]


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"schema_version": 2},
        {"schema_version": 1, "commit": "bad"},
        {"schema_version": 1, "commit": COMMIT, "targets": []},
        {"schema_version": 1, "commit": COMMIT, "targets": [42]},
        manifest("same", "same"),
        manifest("../escape"),
        {
            "schema_version": 1,
            "commit": COMMIT,
            "targets": [{"id": "a", "coverage": "yes"}],
        },
        {
            "schema_version": 1,
            "commit": COMMIT,
            "targets": [{"id": "a", "coverage": True}],
        },
        {
            "schema_version": 1,
            "commit": COMMIT,
            "targets": [{"id": "a", "coverage": False}],
        },
    ],
)
def test_invalid_manifest(tmp_path, data):
    with pytest.raises(ValueError):
        module.aggregate(data, tmp_path)


@pytest.mark.parametrize("minimum", [-1, 101, True, 90.0, "90"])
def test_invalid_threshold(tmp_path, minimum):
    with pytest.raises(ValueError):
        module.aggregate(manifest("a"), tmp_path, minimum)


@pytest.mark.parametrize(
    "xml",
    [
        "<wrong/>",
        "<coverage/>",
        '<coverage lines-covered="-1" lines-valid="100" branches-covered="0" branches-valid="0"/>',
        '<coverage lines-covered="101" lines-valid="100" branches-covered="0" branches-valid="0"/>',
        '<coverage lines-covered="0" lines-valid="0" branches-covered="0" branches-valid="0"/>',
        "<!DOCTYPE coverage><coverage/>",
        '<!ENTITY x "1"><coverage/>',
    ],
)
def test_invalid_xml_counts(tmp_path, xml):
    file = tmp_path / "report.xml"
    file.write_text(xml)
    with pytest.raises(ValueError):
        module.coverage_counts(file)


@pytest.mark.parametrize(
    "xml",
    [
        "<wrong/>",
        "<testsuites/>",
        '<testsuite tests="1"/>',
        '<testsuite tests="1" failures="1" errors="0" skipped="0"/>',
        '<testsuite tests="1" failures="0" errors="1" skipped="0"/>',
        '<testsuite tests="1" failures="0" errors="0" skipped="1"/>',
    ],
)
def test_junit_failures(tmp_path, xml):
    file = tmp_path / "report.xml"
    file.write_text(xml)
    with pytest.raises(ValueError):
        module.validate_junit(file)


def test_oversized_xml(tmp_path):
    file = tmp_path / "large.xml"
    with file.open("wb") as handle:
        handle.truncate(21 * 1024 * 1024)
    with pytest.raises(ValueError):
        module.coverage_counts(file)


def test_main_success_failure_and_wrong_commit(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "git_commit", lambda root: COMMIT)
    monkeypatch.setattr(module, "discover", lambda root: manifest("service-a"))
    write_json(tmp_path / "manifest.json", manifest("service-a"))
    write_json(tmp_path / "security/policy.json", {"coverage": {"minimum_percent": 90}})
    args = ["--root", str(tmp_path), "--manifest", str(tmp_path / "manifest.json")]
    evidence(tmp_path)
    assert module.main(args) == 0
    evidence(tmp_path, lines=(10, 100))
    assert module.main(args) == 1
    monkeypatch.setattr(module, "git_commit", lambda root: "b" * 40)
    assert module.main(args) == 2


def test_main_rejects_manifest_scope_tampering(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "git_commit", lambda root: COMMIT)
    monkeypatch.setattr(module, "discover", lambda root: manifest("service-a", "service-b"))
    write_json(tmp_path / "manifest.json", manifest("service-a"))
    assert (
        module.main(["--root", str(tmp_path), "--manifest", str(tmp_path / "manifest.json")]) == 2
    )


@pytest.mark.parametrize(
    "case",
    [
        "",
        "<testcase><failure/></testcase>",
        "<testcase><error/></testcase>",
        "<testcase><skipped/></testcase>",
    ],
)
def test_junit_attributes_cannot_hide_bad_or_missing_cases(tmp_path, case):
    report = tmp_path / "junit.xml"
    report.write_text(
        f'<testsuite tests="1" failures="0" errors="0" skipped="0">{case}</testsuite>'
    )
    with pytest.raises(ValueError):
        module.validate_junit(report)


def test_repository_target_is_not_in_coverage(tmp_path):
    evidence(tmp_path)
    data = manifest("service-a")
    data["targets"].append({"id": "repository", "coverage": False})
    assert module.aggregate(data, tmp_path)["passed"]
