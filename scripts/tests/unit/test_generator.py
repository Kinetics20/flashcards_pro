"""Exercise the real generator using a temporary copy, never the live template."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
GENERATOR = ROOT / "scripts/create-service.sh"
IGNORED = shutil.ignore_patterns(
    ".git",
    ".venv",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "*.pyc",
    ".coverage*",
    "coverage.xml",
    "coverage.json",
    "htmlcov",
    "reports",
    "_build",
    ".env",
)


def template_copy(tmp_path: Path) -> Path:
    """Allow standalone copy-kit validation without embedding a personal path."""
    if shutil.which("rsync") is None:
        pytest.skip("The service generator requires rsync; install it before running CI")
    source = Path(
        os.environ.get(
            "FCB62_TEMPLATE_SOURCE",
            str(ROOT / "templates/fastapi-microservice"),
        )
    )
    if not source.is_dir():
        pytest.fail("Template is missing; run in the repository or set FCB62_TEMPLATE_SOURCE")
    destination = tmp_path / "template"
    shutil.copytree(source, destination, ignore=IGNORED)
    return destination


def generate(template: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            str(GENERATOR),
            "test-service",
            "Test Service",
            "--owner",
            "test-team",
            "--template",
            str(template),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_generated_service_excludes_reports_coverage_and_caches(tmp_path):
    template = template_copy(tmp_path)
    fixture_paths = (
        "reports/security.json",
        "tests/reports/junit.xml",
        ".coverage",
        ".coverage.worker-1",
        "coverage.xml",
        "coverage.json",
        "htmlcov/index.html",
        ".tox/py314/state.json",
        ".venv/fixture.txt",
        ".github/workflows/fixture.yml",
    )
    for relative in fixture_paths:
        fixture = template / relative
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text("generated-test-artifact\n", encoding="utf-8")
    output = tmp_path / "generated-service"

    result = generate(template, output)

    assert result.returncode == 0, result.stderr
    for relative in fixture_paths:
        assert not (output / relative).exists(), f"Leaked template artifact: {relative}"
        assert (template / relative).is_file(), "Generator must not modify its source"
    for relative in (".git", "compose.yaml", "deploy", ".tox", "reports", "htmlcov"):
        assert not (output / relative).exists()
    assert (output / "src/app/main.py").is_file()
    assert (output / "uv.lock").is_file()
    assert 'name = "flashcards-test-service"' in (output / "pyproject.toml").read_text()
    assert "Test Service" in (output / "README.md").read_text()
    assert "test-team" in (output / "OWNERS.yaml").read_text()
    for file in output.rglob("*"):
        if not file.is_file() or file.name in {"README.md", "TEMPLATE_METADATA.yaml"}:
            continue
        try:
            content = file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert "fastapi-microservice" not in content, str(file.relative_to(output))
        assert "FastAPI Microservice" not in content, str(file.relative_to(output))


def test_generator_refuses_to_overwrite_existing_output(tmp_path):
    template = template_copy(tmp_path)
    output = tmp_path / "already-exists"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("user content", encoding="utf-8")

    result = generate(template, output)

    assert result.returncode != 0
    assert "refusing to overwrite" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "user content"
    assert sorted(path.name for path in output.iterdir()) == ["keep.txt"]
