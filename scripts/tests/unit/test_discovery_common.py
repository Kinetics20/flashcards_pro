from types import SimpleNamespace

import pytest

from scripts.security import common
from scripts.security import discover_targets as module


def tree(root):
    for relative in (
        "services/content-service",
        "templates/fastapi-microservice",
        ".ci/security-tools",
    ):
        folder = root / relative
        folder.mkdir(parents=True)
        (folder / "pyproject.toml").write_text('[project]\nname="example"\n')
        for name in ("uv.lock", "Dockerfile", "pytest.toml", "tox.toml", "OWNERS.yaml"):
            (folder / name).write_text("example\n")
    for name in ("policy.json", "exceptions.json", "tools.lock.json"):
        common.write_json(root / "security" / name, {})
    (root / "security/gitleaks.toml").write_text("[extend]\nuseDefault=true\n")


def test_discovery_and_outputs(tmp_path, monkeypatch):
    tree(tmp_path)
    monkeypatch.setattr(module, "git_commit", lambda root: "a" * 40)
    result = module.discover(tmp_path)
    assert [t["id"] for t in result["targets"]] == [
        "content-service",
        "template-fastapi",
        "repo-security-tools",
        "repository",
    ]
    assert len(result["inputs"]) == 4
    output = tmp_path / "manifest.json"
    github = tmp_path / "github.txt"
    assert (
        module.main(
            [
                "--root",
                str(tmp_path),
                "--output",
                str(output),
                "--github-output",
                str(github),
            ]
        )
        == 0
    )
    assert 'services=["content-service"]' in github.read_text()
    assert module.main(["--root", str(tmp_path), "--output", str(output)]) == 0


@pytest.mark.parametrize(
    "problem",
    [
        "missing-file",
        "missing-name",
        "bad-name",
        "empty",
        "missing-directory",
        "duplicate-id",
    ],
)
def test_discovery_rejects_incomplete_inventory(tmp_path, monkeypatch, problem):
    tree(tmp_path)
    monkeypatch.setattr(module, "git_commit", lambda root: "a" * 40)
    service = tmp_path / "services/content-service"
    if problem == "missing-file":
        (service / "uv.lock").unlink()
    elif problem == "missing-name":
        (service / "pyproject.toml").write_text("[project]\n")
    elif problem == "bad-name":
        service.rename(service.with_name("Bad_Name"))
    elif problem == "empty":
        service.rename(tmp_path / "removed-service")
    elif problem == "missing-directory":
        (tmp_path / "services").rename(tmp_path / "removed-services")
    else:
        service.rename(service.with_name("repo-security-tools"))
    with pytest.raises(ValueError):
        module.discover(tmp_path)
    assert module.main(["--root", str(tmp_path)]) == 2


def test_second_template_gets_distinct_id(tmp_path, monkeypatch):
    tree(tmp_path)
    monkeypatch.setattr(module, "git_commit", lambda root: "a" * 40)
    old = tmp_path / "templates/fastapi-microservice"
    old.rename(old.with_name("other"))
    assert module.discover(tmp_path)["targets"][1]["id"] == "template-other"


def test_json_hash_and_clock(tmp_path):
    file = tmp_path / "a/b.json"
    common.write_json(file, {"ok": True})
    assert common.read_json(file) == {"ok": True}
    assert len(common.sha256_file(file)) == 64
    assert "+00:00" in common.utc_now()
    for text in ('{"x":1,"x":2}', '{"x":NaN}'):
        file.write_text(text)
        with pytest.raises(ValueError):
            common.read_json(file)


def test_contained_paths(tmp_path):
    assert common.contained_path(tmp_path, "hello") == tmp_path / "hello"
    for relative in ("../hello", "/tmp"):
        with pytest.raises(ValueError):
            common.contained_path(tmp_path, relative)
    (tmp_path / "escape").symlink_to(tmp_path.parent, target_is_directory=True)
    with pytest.raises(ValueError):
        common.contained_path(tmp_path, "escape/file")


def test_git_commit_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(
        common.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout="a" * 40 + "\n"),
    )
    assert common.git_commit(tmp_path) == "a" * 40
    monkeypatch.setattr(
        common.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout="secret-like untrusted error"),
    )
    with pytest.raises(ValueError, match="committed HEAD"):
        common.git_commit(tmp_path)
