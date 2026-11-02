"""Real project lifecycle and isolated PostgreSQL tests, not coverage substitutes.

Run via scripts.ci.run_integration in the target project's locked environment.
The only created Docker resource is a uniquely labelled disposable container.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import subprocess
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
POSTGRES = (
    "postgres:17.11-alpine3.24@"
    "sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"
)


@pytest.fixture(scope="module")
def project():
    value = os.environ.get("FCB_INTEGRATION_PROJECT")
    if not value:
        pytest.fail("Run this suite through scripts.ci.run_integration")
    return Path(value)


def docker(*args, env=None):
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True, timeout=90, env=env
    ).stdout.strip()


def remove_test_container(name, token):
    """Resolve only our UUID name and verify ownership before removing its exact ID."""
    try:
        identity = docker(
            "inspect",
            "--format",
            '{{.Id}} {{index .Config.Labels "flashcards.ci.integration"}}',
            name,
        ).split()
    except OSError, subprocess.SubprocessError:
        # --rm may already have removed a stopped container. Preserve an initial
        # creation exception if the daemon is unavailable during cleanup as well.
        return
    if len(identity) == 2 and identity[1] == token:
        subprocess.run(
            ["docker", "rm", "--force", "--volumes", identity[0]],
            capture_output=True,
            timeout=30,
            check=False,
        )


async def wait_for_postgres(url, timeout=30):
    """Wait for a query through the published host port, not the init server's socket."""
    import asyncpg

    try:
        async with asyncio.timeout(timeout):
            while True:
                connection = None
                try:
                    connection = await asyncpg.connect(
                        url.replace("postgresql+asyncpg://", "postgresql://", 1), timeout=1
                    )
                    await connection.execute("SELECT 1", timeout=1)
                    return
                except OSError, asyncpg.PostgresError:
                    # Initialization and Docker port forwarding can briefly reject
                    # or reset connections before the final server accepts queries.
                    await asyncio.sleep(0.5)
                finally:
                    if connection is not None:
                        connection.terminate()
    except TimeoutError:
        pytest.fail("Dedicated test PostgreSQL did not become ready through its host port")


@pytest.fixture
def postgres(project):
    if not (project / "alembic.ini").is_file():
        pytest.fail("Selected PostgreSQL integration profile requires actual Alembic migrations")
    token = uuid.uuid4().hex
    password = secrets.token_urlsafe(32)
    container_name = f"fcb65-postgres-{token}"
    try:
        # A timed-out docker run may still have created the container. Its UUID
        # name is known before creation and remains available to the finally block.
        container = docker(
            "run",
            "--detach",
            "--rm",
            "--label",
            f"flashcards.ci.integration={token}",
            "--name",
            container_name,
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_PASSWORD",
            "--env",
            "POSTGRES_DB=fcb65_test",
            POSTGRES,
            env={**os.environ, "POSTGRES_PASSWORD": password},
        )
        port = docker(
            "inspect",
            "--format",
            '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}',
            container,
        )
        url = f"postgresql+asyncpg://postgres:{password}@127.0.0.1:{port}/fcb65_test"
        asyncio.run(wait_for_postgres(url))
        yield {
            "container": container,
            "url": url,
        }
    finally:
        remove_test_container(container_name, token)


def test_real_asgi_lifecycle_and_http(project):
    from app.core.config import Settings
    from app.main import create_app
    from fastapi.testclient import TestClient

    application = create_app(Settings(_env_file=None, environment="test"))
    with TestClient(application) as client:
        for route in ("/health/live", "/health/ready", "/api/v1/status"):
            response = client.get(route)
            assert response.status_code == 200
            assert isinstance(response.json(), dict)


def test_real_migration_round_trip_and_transaction_rollback(project, postgres):
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from app.core.config import Settings
    from app.platform.database import DatabaseRuntime
    from sqlalchemy import text

    expected_heads = set(
        ScriptDirectory.from_config(Config(str(project / "alembic.ini"))).get_heads()
    )
    assert expected_heads
    environment = {
        **os.environ,
        "APP_ENVIRONMENT": "test",
        "APP_DATABASE_ENABLED": "true",
        "APP_DATABASE_URL": postgres["url"],
        "APP_TELEMETRY_ENABLED": "false",
        "APP_METRICS_ENABLED": "false",
    }

    def migrate(*args):
        subprocess.run(
            [
                str(project / ".venv/bin/python"),
                "-I",
                "-B",
                "-m",
                "alembic",
                "-c",
                str(project / "alembic.ini"),
                *args,
            ],
            # Inherit the runner's empty cwd, not the project containing a local .env.
            cwd=Path.cwd(),
            env=environment,
            capture_output=True,
            timeout=60,
            check=True,
        )

    async def inspect_database(expected, transactions=False):
        runtime = DatabaseRuntime(
            Settings(_env_file=None, database_enabled=True, database_url=postgres["url"]).database
        )
        try:
            await runtime.ping()
            async with runtime.session() as session:
                versions = set(
                    (
                        await session.execute(text("SELECT version_num FROM alembic_version"))
                    ).scalars()
                )
                assert versions == expected
            if transactions:
                async with runtime.session() as session:
                    # A disposable test table, not an invented application domain model.
                    await session.execute(
                        text("CREATE TABLE ci_transaction_probe (id integer PRIMARY KEY)")
                    )
                    await session.execute(text("INSERT INTO ci_transaction_probe VALUES (1)"))
                    await session.commit()
                with pytest.raises(RuntimeError, match="rollback probe"):
                    async with runtime.session() as session:
                        await session.execute(text("INSERT INTO ci_transaction_probe VALUES (2)"))
                        raise RuntimeError("rollback probe")
                async with runtime.session() as session:
                    assert list(
                        (
                            await session.execute(text("SELECT id FROM ci_transaction_probe"))
                        ).scalars()
                    ) == [1]
                    await session.execute(text("DROP TABLE ci_transaction_probe"))
                    await session.commit()
        finally:
            await runtime.close()

    migrate("upgrade", "head")
    asyncio.run(inspect_database(expected_heads, transactions=True))
    migrate("downgrade", "base")
    asyncio.run(inspect_database(set()))
    migrate("upgrade", "head")
    asyncio.run(inspect_database(expected_heads))


def test_real_database_readiness_failure_and_lifespan_cleanup(project, postgres):
    from app.core.config import Settings
    from app.main import create_app
    from fastapi.testclient import TestClient
    from sqlalchemy import event

    settings = Settings(
        _env_file=None,
        environment="test",
        database_enabled=True,
        database_url=postgres["url"],
        database_connect_timeout_seconds=1,
    )
    application = create_app(settings)
    disposed = []
    event.listen(
        application.state.database.engine.sync_engine,
        "engine_disposed",
        lambda engine: disposed.append(True),
    )
    with TestClient(application) as client:
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json()["checks"]["database"]["status"] == "ok"
        docker("stop", "--time", "5", postgres["container"])
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 503
    assert disposed == [True]
    failed = create_app(settings)
    failed_disposed = []
    event.listen(
        failed.state.database.engine.sync_engine,
        "engine_disposed",
        lambda engine: failed_disposed.append(True),
    )
    with pytest.raises(Exception):
        with TestClient(failed):
            pytest.fail("Startup must not succeed when the configured database is unavailable")
    assert failed_disposed == [True]
