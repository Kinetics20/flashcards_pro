"""Real tools + real vulnerability DB; run explicitly, independently of unit tests."""

import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.security import run_scans


@pytest.mark.integration
def test_pinned_scanners_detect_and_policy_rejects_negative_controls(tmp_path, monkeypatch):
    kit = Path(__file__).resolve().parents[3]
    fixture = tmp_path / "fixture-repository"
    fixture.mkdir()
    shutil.copytree(kit / "security", fixture / "security")
    for arguments in (
        ["init", "--quiet"],
        ["add", "security"],
        [
            "-c",
            "user.email=scanner-fixture@example.invalid",
            "-c",
            "user.name=Scanner Fixture",
            "commit",
            "--quiet",
            "-m",
            "scanner fixture",
        ],
    ):
        subprocess.run(["git", *arguments], cwd=fixture, check=True, capture_output=True)
    original = run_scans.verified_tool
    # Cache placement only is overridden; the real checksum verifier and actual
    # scanners execute. No vulnerable package is installed or imported.
    monkeypatch.setattr(
        run_scans, "verified_tool", lambda root, name, install: original(kit, name, install=install)
    )
    output = tmp_path / "reports"
    assert run_scans.self_test_scanners(fixture, output, install=True), run_scans.read_json(
        output / "scanner-self-test.json"
    )
    report = run_scans.read_json(output / "scanner-self-test.json")
    assert report["commit"] == run_scans.git_commit(fixture)
    assert "critical-vulnerability-rejected" in report["controls"]
    assert "clean-file-accepted" in report["controls"]
