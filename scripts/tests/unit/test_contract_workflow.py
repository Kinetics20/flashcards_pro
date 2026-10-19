"""Execute the real workflow baseline selector against isolated Git histories."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]


def workflow():
    return yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)


def git(directory, *arguments):
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Contract Test",
            "-c",
            "user.email=contract@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *arguments,
        ],
        cwd=directory,
        env=environment(),
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    return result.stdout.strip()


def environment():
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


@pytest.fixture
def history(tmp_path):
    directory = tmp_path / "repo"
    directory.mkdir()
    git(directory, "init", "--initial-branch=main")
    git(directory, "commit", "--allow-empty", "-m", "common ancestor")
    ancestor = git(directory, "rev-parse", "HEAD")
    git(directory, "switch", "-c", "feature")
    git(directory, "commit", "--allow-empty", "-m", "feature change")
    head = git(directory, "rev-parse", "HEAD")
    git(directory, "switch", "main")
    git(directory, "commit", "--allow-empty", "-m", "base branch advanced")
    base = git(directory, "rev-parse", "HEAD")
    return directory, {"ancestor": ancestor, "head": head, "base": base}


def run_selector(directory, event_name, event, tmp_path):
    steps = workflow()["jobs"]["contract-compatibility"]["steps"]
    script = next(step["run"] for step in steps if step.get("id") == "baseline")
    lines = script.strip().splitlines()
    assert lines[0] == "python3 - <<'PY'" and lines[-1] == "PY"
    program = "\n".join(lines[1:-1])
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(event))
    output = tmp_path / "github-output.txt"
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program],
        cwd=directory,
        env={
            **environment(),
            "GITHUB_EVENT_NAME": event_name,
            "GITHUB_EVENT_PATH": str(event_file),
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    return result, output.read_text() if output.exists() else ""


def test_pull_request_uses_merge_base_not_tip_of_base_branch(history, tmp_path):
    directory, commits = history
    event = {"pull_request": {"base": {"sha": commits["base"]}, "head": {"sha": commits["head"]}}}
    result, output = run_selector(directory, "pull_request", event, tmp_path)
    assert result.returncode == 0, result.stderr
    assert output == "sha=" + commits["ancestor"] + "\n"


def test_push_uses_event_before_sha(history, tmp_path):
    directory, commits = history
    result, output = run_selector(directory, "push", {"before": commits["head"]}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert output == "sha=" + commits["head"] + "\n"


@pytest.mark.parametrize("event_name", ["workflow_dispatch", "schedule"])
def test_manual_and_schedule_use_first_parent_not_second_parent(history, tmp_path, event_name):
    directory, commits = history
    git(directory, "merge", "--no-ff", "feature", "-m", "merge fixture")
    result, output = run_selector(directory, event_name, {}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert output == "sha=" + commits["base"] + "\n"


@pytest.mark.parametrize("before", ["0" * 40, "f" * 40, "main", None, "A" * 40])
def test_invalid_zero_or_unavailable_push_commit_fails(history, tmp_path, before):
    directory, _ = history
    result, output = run_selector(directory, "push", {"before": before}, tmp_path)
    assert result.returncode != 0
    assert output == ""


def test_pull_request_missing_history_fails(history, tmp_path):
    directory, commits = history
    event = {"pull_request": {"base": {"sha": commits["base"]}, "head": {"sha": "f" * 40}}}
    result, output = run_selector(directory, "pull_request", event, tmp_path)
    assert result.returncode != 0
    assert output == ""


def test_schedule_without_parent_fails(history, tmp_path):
    directory, commits = history
    git(directory, "switch", "--detach", commits["ancestor"])
    result, output = run_selector(directory, "schedule", {}, tmp_path)
    assert result.returncode != 0
    assert output == ""


def test_workflow_requires_history_fail_closed_gate_and_independent_delivery():
    document = workflow()
    assert "pull_request" in document["on"]
    jobs = document["jobs"]
    assert "contract-compatibility" in jobs["ci-success"]["needs"]
    steps = jobs["contract-compatibility"]["steps"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == "0"
    assert checkout["with"]["persist-credentials"] == "false"
    compatibility = next(
        step for step in steps if "scripts.contracts.compatibility" in step.get("run", "")
    )
    assert compatibility.get("continue-on-error", "false") == "false"
    assert '--base "$BASE_SHA"' in compatibility["run"]
    delivery = next(step for step in steps if "test_contract_delivery.py" in step.get("run", ""))
    assert delivery["if"] == "${{ !cancelled() }}"
    assert delivery.get("continue-on-error", "false") == "false"
    upload = next(
        step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert upload["if"] == "always()"
    assert upload["with"]["name"] == "contract-compatibility-results"
    assert not upload["with"]["name"].startswith("evidence-")
    assert upload["with"]["if-no-files-found"] == "error"
