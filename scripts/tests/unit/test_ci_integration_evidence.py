import asyncio
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from scripts.ci import run_integration as module
from scripts.ci.plan import digest
from scripts.security.common import sha256_file
from scripts.tests.integration import test_service_runtime as runtime_suite

PLAN = {
    "commit": "a" * 40,
    "selected": ["content-service"],
    "targets": [
        {"id": "content-service", "path": "services/content-service", "integration_profile": "asgi"}
    ],
}
JUNIT = (
    '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
    '<testcase name="test_real_asgi_lifecycle_and_http" /></testsuite></testsuites>'
)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "expected_plan", lambda *args: PLAN)
    return tmp_path


def evidence(root, target="content-service", **changes):
    directory = root / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "junit.xml").write_text(JUNIT)
    status = {
        "schema_version": 1,
        "commit": PLAN["commit"],
        "plan_sha256": digest(PLAN),
        "target": target,
        "exit_code": 0,
        "passed_tests": 1,
        "junit_sha256": sha256_file(directory / "junit.xml"),
        "scope": "integration-only; not included in unit coverage",
        **changes,
    }
    (directory / "status.json").write_text(json.dumps(status))


def test_evidence_success_and_cli(setup):
    evidence(setup)
    module.verify(setup, setup / "plan.json", setup)
    assert module.main(["verify", "--root", str(setup), "--reports", str(setup)]) == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"exit_code": 1},
        {"commit": "b" * 40},
        {"plan_sha256": "tampered"},
        {"passed_tests": 2},
        {"extra": "untrusted"},
    ],
)
def test_stale_failed_or_forged_evidence_rejected(setup, changes):
    evidence(setup, **changes)
    with pytest.raises(ValueError, match="Invalid"):
        module.verify(setup, setup / "plan.json", setup)


def test_missing_unexpected_and_empty_selection(setup, monkeypatch):
    with pytest.raises(ValueError, match="Missing"):
        module.verify(setup, setup / "plan.json", setup)
    evidence(setup, "unexpected")
    with pytest.raises(ValueError, match="unexpected"):
        module.verify(setup, setup / "plan.json", setup)
    monkeypatch.setattr(module, "expected_plan", lambda *args: {**PLAN, "selected": []})
    module.verify(setup, setup / "plan.json", setup / "empty")


@pytest.mark.parametrize(
    "body",
    [
        "<testsuites />",
        "<testsuites><testcase><failure /></testcase></testsuites>",
        "<testsuites><testcase><error /></testcase></testsuites>",
        "<testsuites><testcase><skipped /></testcase></testsuites>",
    ],
)
def test_junit_requires_executed_successful_tests(tmp_path, body):
    path = tmp_path / "junit.xml"
    path.write_text(body)
    with pytest.raises(ValueError):
        module.passed_junit(path)


def test_runner_validates_selection_and_stale_output(setup):
    with pytest.raises(ValueError, match="not required"):
        module.run(setup, setup / "plan", setup, "unknown")
    evidence(setup)
    with pytest.raises(ValueError, match="stale"):
        module.run(setup, setup / "plan", setup, "content-service")


@pytest.mark.parametrize("code", [0, 1])
def test_runner_uses_project_env_and_records_result(setup, monkeypatch, code):
    (setup / ".env").write_text("APP_DATABASE_ENABLED=true\nAPP_UNRECOGNIZED=value\n")
    temporary_cwds = []

    def command(args, **kwargs):
        assert args[0] == str(setup / "services/content-service/.venv/bin/python")
        assert kwargs["env"]["FCB_INTEGRATION_PROJECT"] == str(setup / "services/content-service")
        assert "APP_UNTRUSTED" not in kwargs["env"]
        assert kwargs["timeout"] == 600
        assert "-I" in args
        cwd = Path(kwargs["cwd"])
        assert cwd.is_dir() and cwd.resolve() != setup.resolve()
        assert not (cwd / ".env").exists()
        temporary_cwds.append(cwd)
        (setup / "content-service/junit.xml").write_text(JUNIT)
        return SimpleNamespace(returncode=code)

    monkeypatch.setenv("APP_UNTRUSTED", "ignored")
    monkeypatch.setattr(module.subprocess, "run", command)
    assert (
        module.main(
            ["run", "--root", str(setup), "--reports", str(setup), "--target", "content-service"]
        )
        == code
    )
    status = json.loads((setup / "content-service/status.json").read_text())
    assert status["passed_tests"] == (1 if code == 0 else 0)
    assert temporary_cwds and all(not cwd.exists() for cwd in temporary_cwds)


def test_cli_reports_errors(setup):
    assert module.main(["run", "--root", str(setup)]) == 2
    assert module.main(["verify", "--root", str(setup), "--reports", str(setup)]) == 2


def test_junit_rejects_changed_content_even_when_test_count_matches(setup):
    evidence(setup)
    path = setup / "content-service/junit.xml"
    path.write_text(JUNIT.replace("<testcase ", '<testcase time="1" '))
    with pytest.raises(ValueError, match="Invalid"):
        module.verify(setup, setup / "plan", setup)


def test_postgres_requires_all_three_capability_cases(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(JUNIT)
    with pytest.raises(ValueError, match="required capability"):
        module.passed_junit(path, "postgres")
    extra = (
        '<testcase name="test_real_migration_round_trip_and_transaction_rollback" />'
        '<testcase name="test_real_database_readiness_failure_and_lifespan_cleanup" />'
    )
    path.write_text(
        JUNIT.replace('tests="1"', 'tests="3"').replace("</testsuite>", extra + "</testsuite>")
    )
    assert module.passed_junit(path, "postgres") == 3
    path.write_text(
        JUNIT.replace('tests="1"', 'tests="2"')
        .replace('skipped="0"', 'skipped="1"')
        .replace("</testsuite>", '<testcase name="skipped"><skipped /></testcase></testsuite>')
    )
    with pytest.raises(ValueError, match="may not be skipped"):
        module.passed_junit(path)


def test_junit_rejects_doctype(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text("<!DOCTYPE testsuites []>" + JUNIT)
    with pytest.raises(ValueError, match="DTD"):
        module.passed_junit(path)


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.TimeoutExpired("docker run", 90),
        subprocess.CalledProcessError(1, "docker run"),
        OSError("docker connection lost after creation"),
    ],
)
def test_postgres_creation_failure_still_cleans_its_labelled_container(
    tmp_path, monkeypatch, failure
):
    (tmp_path / "alembic.ini").write_text("fixture")
    token, container_id = "a" * 32, "b" * 64
    monkeypatch.setattr(runtime_suite.uuid, "uuid4", lambda: SimpleNamespace(hex=token))
    commands = []

    def docker_command(*args, **kwargs):
        commands.append(args)
        if args[0] == "run":
            raise failure
        assert args[-1] == f"fcb65-postgres-{token}"
        return f"{container_id} {token}"

    removals = []
    monkeypatch.setattr(runtime_suite, "docker", docker_command)
    monkeypatch.setattr(runtime_suite.subprocess, "run", lambda args, **kw: removals.append(args))
    fixture = runtime_suite.postgres.__wrapped__(tmp_path)
    with pytest.raises(type(failure)):
        next(fixture)
    assert [command[0] for command in commands] == ["run", "inspect"]
    assert removals == [["docker", "rm", "--force", "--volumes", container_id]]


def test_cleanup_never_removes_container_with_other_owner(monkeypatch):
    monkeypatch.setattr(runtime_suite, "docker", lambda *args: "id other-owner")
    removals = []
    monkeypatch.setattr(runtime_suite.subprocess, "run", lambda *args, **kw: removals.append(args))
    runtime_suite.remove_test_container("fcb65-postgres-ours", "our-token")
    assert removals == []


def test_cleanup_preserves_failure_when_container_already_removed(monkeypatch):
    def absent(*args):
        raise subprocess.CalledProcessError(1, "docker inspect")

    monkeypatch.setattr(runtime_suite, "docker", absent)
    runtime_suite.remove_test_container("fcb65-postgres-ours", "our-token")


def test_postgres_readiness_retries_connection_and_query_failures(monkeypatch):
    class PostgresError(Exception):
        pass

    starting = SimpleNamespace(
        execute=AsyncMock(side_effect=PostgresError("starting up")), terminate=Mock()
    )
    ready = SimpleNamespace(execute=AsyncMock(), terminate=Mock())
    connect = AsyncMock(side_effect=[ConnectionError("connection lost"), starting, ready])
    monkeypatch.setitem(
        sys.modules, "asyncpg", SimpleNamespace(connect=connect, PostgresError=PostgresError)
    )
    monkeypatch.setattr(runtime_suite.asyncio, "sleep", AsyncMock())

    asyncio.run(
        runtime_suite.wait_for_postgres(
            "postgresql+asyncpg://postgres:secret@127.0.0.1:50052/fcb65_test"
        )
    )

    assert connect.await_count == 3
    for call in connect.await_args_list:
        assert call.args == ("postgresql://postgres:secret@127.0.0.1:50052/fcb65_test",)
        assert call.kwargs == {"timeout": 1}
    starting.terminate.assert_called_once()
    ready.execute.assert_awaited_once_with("SELECT 1", timeout=1)
    ready.terminate.assert_called_once()


def test_postgres_readiness_deadline_closes_pending_connection(monkeypatch):
    async def stalled_query(*args, **kwargs):
        await asyncio.sleep(60)

    connection = SimpleNamespace(execute=stalled_query, terminate=Mock())
    monkeypatch.setitem(
        sys.modules,
        "asyncpg",
        SimpleNamespace(
            connect=AsyncMock(return_value=connection),
            PostgresError=type("PostgresError", (Exception,), {}),
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="did not become ready through its host port"):
        asyncio.run(runtime_suite.wait_for_postgres("postgresql://unused", timeout=0.01))
    connection.terminate.assert_called_once()


def test_postgres_readiness_failure_cleans_container_before_yield(tmp_path, monkeypatch):
    (tmp_path / "alembic.ini").write_text("fixture")
    monkeypatch.setattr(runtime_suite, "docker", Mock(side_effect=["container-id", "50052"]))
    cleanup = Mock()
    monkeypatch.setattr(runtime_suite, "remove_test_container", cleanup)
    readiness = AsyncMock(side_effect=pytest.fail.Exception("not ready"))
    monkeypatch.setattr(runtime_suite, "wait_for_postgres", readiness)
    with pytest.raises(pytest.fail.Exception, match="not ready"):
        next(runtime_suite.postgres.__wrapped__(tmp_path))
    assert "@127.0.0.1:50052/fcb65_test" in readiness.await_args.args[0]
    cleanup.assert_called_once()
