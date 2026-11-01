"""Explicit, real local-stack proof using one isolated, fixture-owned Compose project.

Run only with FCB_RUN_LOCAL_STACK=1. No developer project is reset, no secrets or
expanded Compose configuration are written to reports, and images remain for audit.
The ordered lifecycle is one test so persistence checks cannot run before setup.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from uuid import uuid4

import boto3
import nats
import pytest
import redis
from botocore.config import Config
from botocore.exceptions import ClientError
from nats.js.api import StorageType

from scripts.local.stack import (
    bootstrap,
    compose_args,
    config_environment,
    load_settings,
    process_environment,
)
from scripts.security.common import write_json

ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.integration
BUCKET = "flashcards-local"
CLIENT = "flashcards-dev"
STREAM = "FCB60_DURABILITY"
SUBJECT = "fcb60.durability"
DURABLE = "fcb60-proof"
MARKER = b"fixture-owned-persistence-marker"


def checked(command, *, environment=None, timeout=90, allow_failure=False):
    """Never attach subprocess output or expanded environment to an exception."""
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment or process_environment(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except OSError, subprocess.SubprocessError:
        pytest.fail(
            "Local-stack subprocess failed; inspect only the fixture-owned project", pytrace=False
        )
    if not allow_failure and result.returncode:
        pytest.fail(
            "Local-stack command failed; command output and credentials are withheld", pytrace=False
        )
    return result


def http(url, *, data=None, headers=None):
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def fingerprint(settings):
    return hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()


def redact_diagnostic(value, secrets):
    """Conservative local-only redaction, not a promise that logs are safe to publish."""
    if isinstance(value, dict):
        return {key: redact_diagnostic(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_diagnostic(item, secrets) for item in value]
    if not isinstance(value, str):
        return value
    for secret in secrets:
        value = value.replace(secret, "[REDACTED]")
    lines = []
    for line in value.splitlines():
        if re.search(
            r"authorization|bearer|access_token|refresh_token|id_token|client_secret|"
            r"password|credential|secret|x-amz-|x-goog-|signature",
            line,
            re.IGNORECASE,
        ):
            lines.append("[REDACTED sensitive diagnostic line]")
            continue
        line = re.sub(r"(https?://[^\s?]+)\?[^\s]+", r"\1?[REDACTED-QUERY]", line)
        line = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED-JWT]", line)
        lines.append(line)
    return "\n".join(lines)


class LocalStack:
    def __init__(self, project, settings, reports):
        self.project = project
        self.settings = settings
        self.reports = reports
        self.ports = settings["ports"]
        self.stage = "bootstrap"

    def cli(self, action, profile="full"):
        return checked(
            [
                sys.executable,
                "-m",
                "scripts.local.stack",
                "--root",
                str(ROOT),
                "--project",
                self.project,
                action,
                "--profile",
                profile,
            ],
            timeout=900,
        )

    def compose(self, arguments, *, profile="full", timeout=90, allow_failure=False):
        return checked(
            ["docker", *compose_args(ROOT, self.project, profile), *arguments],
            environment=config_environment(ROOT, self.project, profile, self.settings),
            timeout=timeout,
            allow_failure=allow_failure,
        )

    def container(self, service):
        identifier = self.compose(["ps", "--all", "--quiet", service]).stdout.strip()
        assert identifier and "\n" not in identifier, "Expected one fixture service container"
        return identifier

    def inspect(self, identifier, expression):
        return checked(["docker", "inspect", "--format", expression, identifier]).stdout.strip()

    def owned(self, labels):
        return (
            labels.get("com.docker.compose.project") == self.project
            and labels.get("flashcards.local.owner") == self.settings["owner_token"]
        )

    def sql(self, service, database, statement):
        return self.compose(
            [
                "exec",
                "-T",
                service,
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-d",
                database,
                "-tAc",
                statement,
            ]
        ).stdout.strip()

    def require_healthy(self, services):
        for service in services:
            state = json.loads(self.inspect(self.container(service), "{{json .State}}"))
            assert state["Status"] == "running", f"Fixture service is not running: {service}"
            assert state.get("Health", {}).get("Status") == "healthy", (
                f"Fixture service is not healthy: {service}"
            )

    def gateway(self, path):
        return f"http://127.0.0.1:{self.ports['gateway']}{path}"

    def cache(self, *, authenticated=True):
        return redis.Redis(
            host="127.0.0.1",
            port=self.ports["redis"],
            password=self.settings["credentials"]["redis_password"] if authenticated else None,
            socket_connect_timeout=5,
            socket_timeout=5,
        )

    def objects(self, *, invalid_credentials=False):
        credentials = self.settings["credentials"]
        return boto3.client(
            "s3",
            endpoint_url=f"http://127.0.0.1:{self.ports['s3']}",
            aws_access_key_id=(
                "invalid-fixture-key" if invalid_credentials else credentials["s3_access_key"]
            ),
            aws_secret_access_key=(
                "invalid-fixture-secret" if invalid_credentials else credentials["s3_secret_key"]
            ),
            region_name="us-east-1",
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
                connect_timeout=5,
                read_timeout=10,
                retries={"max_attempts": 1},
            ),
        )

    async def broker(self):
        return await nats.connect(
            servers=[f"nats://127.0.0.1:{self.ports['nats']}"],
            user="flashcards",
            password=self.settings["credentials"]["nats_password"],
            connect_timeout=5,
            max_reconnect_attempts=0,
        )

    def failure_diagnostics(self):
        """Preserve bounded, redacted failure evidence before fixture cleanup."""

        def capture(arguments):
            result = subprocess.run(
                ["docker", *arguments],
                env=process_environment(),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            return result.stdout + result.stderr

        try:
            identifiers = capture(
                [
                    "ps",
                    "--all",
                    "--quiet",
                    "--filter",
                    f"label=com.docker.compose.project={self.project}",
                ]
            ).split()
            evidence = []
            for identifier in identifiers:
                state = json.loads(capture(["inspect", "--format", "{{json .State}}", identifier]))
                evidence.append(
                    {
                        "container_id": identifier,
                        "state": state,
                        "logs": capture(["logs", "--tail", "40", identifier]),
                    }
                )
            document = redact_diagnostic(
                {"project": self.project, "stage": self.stage, "containers": evidence},
                [*self.settings["credentials"].values(), self.settings["owner_token"]],
            )
            # Keep troubleshooting logs outside all report/artifact paths. Even
            # redacted logs are local-sensitive and must be reviewed before sharing.
            path = ROOT / ".local" / self.project / "diagnostics.json"
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2)
        except OSError, ValueError, subprocess.SubprocessError:
            # Diagnostics must not replace the actual test failure or prevent cleanup.
            return

    def cleanup(self):
        """Delete only this newly created UUID project's ownership-verified resources."""
        filters = ["--filter", f"label=com.docker.compose.project={self.project}"]
        containers = checked(["docker", "ps", "--all", "--quiet", *filters]).stdout.split()
        for identifier in containers:
            labels = json.loads(self.inspect(identifier, "{{json .Config.Labels}}"))
            assert self.owned(labels), "Refusing cleanup of a container with foreign ownership"
        networks = checked(["docker", "network", "ls", "--quiet", *filters]).stdout.split()
        for identifier in networks:
            labels = json.loads(
                checked(
                    ["docker", "network", "inspect", "--format", "{{json .Labels}}", identifier]
                ).stdout
            )
            assert self.owned(labels), "Refusing cleanup of a network with foreign ownership"
        volumes = checked(["docker", "volume", "ls", "--quiet", *filters]).stdout.split()
        for name in volumes:
            labels = json.loads(
                checked(
                    [
                        "docker",
                        "volume",
                        "inspect",
                        "--format",
                        "{{json .Labels}}",
                        name,
                    ]
                ).stdout
            )
            assert self.owned(labels), "Refusing cleanup of a volume with foreign ownership"
        self.cli("down")  # The normal CLI down intentionally preserves data.
        for name in volumes:
            # Recheck exact ownership immediately before the fixture-only deletion.
            labels = json.loads(
                checked(
                    [
                        "docker",
                        "volume",
                        "inspect",
                        "--format",
                        "{{json .Labels}}",
                        name,
                    ]
                ).stdout
            )
            assert self.owned(labels), "Volume ownership changed during fixture cleanup"
            checked(["docker", "volume", "rm", name])
        assert not checked(["docker", "ps", "--all", "--quiet", *filters]).stdout.strip()
        assert not checked(["docker", "volume", "ls", "--quiet", *filters]).stdout.strip()
        assert not checked(["docker", "network", "ls", "--quiet", *filters]).stdout.strip()

    def record_images(self):
        references = set(self.compose(["--profile", "*", "config", "--images"]).stdout.splitlines())
        assert references, "All-profile image inventory is empty"
        identities = {
            reference: checked(
                ["docker", "image", "inspect", "--format", "{{.Id}}", reference]
            ).stdout.strip()
            for reference in sorted(references)
        }
        observed = set()
        containers = self.compose(["--profile", "*", "ps", "--all", "--quiet"]).stdout.split()
        for identifier in containers:
            reference = self.inspect(identifier, "{{.Config.Image}}")
            image_id = self.inspect(identifier, "{{.Image}}")
            assert reference in identities, "Running container uses an undeclared image"
            assert identities[reference] == image_id, "Tag no longer points at the tested image"
            observed.add(reference)
        assert observed == references, "Not every unique all-profile image was exercised"
        commit = checked(["git", "rev-parse", "HEAD"]).stdout.strip()
        write_json(
            self.reports / "images.json",
            {
                "schema_version": 1,
                "commit": commit,
                "local_image_tag": self.project,
                "images": [
                    {"reference": reference, "image_id": image_id}
                    for reference, image_id in identities.items()
                ],
            },
        )


@pytest.fixture
def stack():
    if os.environ.get("FCB_RUN_LOCAL_STACK") != "1":
        pytest.fail("Explicitly set FCB_RUN_LOCAL_STACK=1 to run the real local stack; no skip")
    project = "fcb60-" + uuid4().hex[:16]
    reports = Path(os.environ.get("FCB_LOCAL_STACK_REPORT_DIR", ROOT / "reports/local-stack"))
    if not reports.is_absolute():
        reports = ROOT / reports
    reports = reports.resolve()
    assert reports.is_relative_to(ROOT / "reports"), "Reports must stay under repository reports/"
    assert not (reports / "images.json").exists(), (
        "Use a fresh report directory, not stale evidence"
    )
    settings = bootstrap(ROOT, project, ephemeral_ports=True)
    current = LocalStack(project, settings, reports)
    try:
        assert fingerprint(load_settings(ROOT, project)) == fingerprint(settings)
        yield current
    except BaseException:
        current.failure_diagnostics()
        raise
    finally:
        current.cleanup()


def check_http(stack):
    for path in ("/health/live", "/health/ready", "/api/v1/status"):
        status, body = http(stack.gateway(path))
        assert status == 200, f"Gateway did not serve {path}"
        payload = json.loads(body)
        assert payload["status"] == "ok"
    assert (
        json.loads(http(stack.gateway("/health/ready"))[1])["checks"]["database"]["status"] == "ok"
    )


def check_database(stack):
    assert (
        stack.sql("postgres-content", "content", "SELECT version_num FROM alembic_version")
        == "dac39c4ce2a9"
    )
    for service, database, role in (
        ("postgres-content", "content", "content"),
        ("postgres-identity", "keycloak", "keycloak"),
    ):
        privileges = stack.sql(
            service,
            database,
            f"SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname='{role}'",
        )
        assert privileges == "f|f|f", "Application database role must not be an administrator"
        rejected = stack.compose(
            [
                "exec",
                "-T",
                "--env",
                "PGPASSWORD=invalid-fixture-password",
                service,
                "psql",
                "-X",
                "-h",
                "127.0.0.1",
                "-U",
                role,
                "-d",
                database,
                "-tAc",
                "SELECT 1",
            ],
            allow_failure=True,
        )
        assert rejected.returncode != 0, "PostgreSQL accepted a wrong application password"
        # An imported realm can reappear in a fresh database. This marker cannot.
        stack.sql(
            service,
            database,
            "CREATE TABLE fcb60_persistence_probe (id integer PRIMARY KEY)",
        )
        stack.sql(service, database, "INSERT INTO fcb60_persistence_probe VALUES (1)")
    content_networks = json.loads(
        stack.inspect(stack.container("content-service"), "{{json .NetworkSettings.Networks}}")
    )
    identity_networks = json.loads(
        stack.inspect(stack.container("postgres-identity"), "{{json .NetworkSettings.Networks}}")
    )
    assert not set(content_networks).intersection(identity_networks), (
        "Content can access identity DB network"
    )
    result = stack.compose(
        [
            "exec",
            "-T",
            "content-service",
            "python",
            "-c",
            "import socket; socket.create_connection(('postgres-identity', 5432), timeout=2)",
        ],
        allow_failure=True,
    )
    assert result.returncode != 0, "Content unexpectedly connected to identity database"


async def check_jetstream(stack):
    connection = await stack.broker()
    try:
        jetstream = connection.jetstream()
        await jetstream.add_stream(name=STREAM, subjects=[SUBJECT], storage=StorageType.FILE)
        subscription = await jetstream.pull_subscribe(SUBJECT, DURABLE, stream=STREAM)
        acknowledgement = await jetstream.publish(SUBJECT, b"before-reconnect")
        assert acknowledgement.stream == STREAM and acknowledgement.seq == 1
        message = (await subscription.fetch(1, timeout=5))[0]
        assert message.data == b"before-reconnect"
        await message.ack_sync()
    finally:
        await connection.close()
    connection = await stack.broker()
    try:
        jetstream = connection.jetstream()
        subscription = await jetstream.pull_subscribe(SUBJECT, DURABLE, stream=STREAM)
        await jetstream.publish(SUBJECT, b"after-reconnect")
        message = (await subscription.fetch(1, timeout=5))[0]
        assert message.data == b"after-reconnect"
        await message.ack_sync()
        acknowledgement = await jetstream.publish(SUBJECT, MARKER)
        assert acknowledgement.seq == 3
    finally:
        await connection.close()


def check_redis(stack):
    anonymous = stack.cache(authenticated=False)
    try:
        with pytest.raises(redis.exceptions.AuthenticationError):
            anonymous.ping()
    finally:
        anonymous.close()
    client = stack.cache()
    try:
        assert client.ping() is True
        assert client.config_get("appendonly")["appendonly"] == "yes"
        assert client.set("fcb60:persistence", MARKER) is True
        assert client.get("fcb60:persistence") == MARKER
    finally:
        client.close()


def check_s3(stack):
    client = stack.objects()
    key = "fcb60/persistence.bin"
    try:
        client.head_bucket(Bucket=BUCKET)
        client.put_object(Bucket=BUCKET, Key=key, Body=MARKER)
        response = client.get_object(Bucket=BUCKET, Key=key)
        with response["Body"] as body:
            assert body.read() == MARKER
        assert key in {
            entry["Key"]
            for entry in client.list_objects_v2(Bucket=BUCKET, Prefix="fcb60/")["Contents"]
        }
        url = client.generate_presigned_url(
            "get_object", Params={"Bucket": BUCKET, "Key": key}, ExpiresIn=60
        )
        status, payload = http(url)
        assert status == 200 and payload == MARKER
        status, _ = http(f"http://127.0.0.1:{stack.ports['s3']}/{BUCKET}/{key}")
        assert status == 403, "Anonymous S3 GET must be forbidden"
        client.put_object(Bucket=BUCKET, Key="fcb60/delete.bin", Body=b"delete-probe")
        client.delete_object(Bucket=BUCKET, Key="fcb60/delete.bin")
        with pytest.raises(ClientError) as deleted:
            client.head_object(Bucket=BUCKET, Key="fcb60/delete.bin")
        assert deleted.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404
    finally:
        client.close()
    invalid = stack.objects(invalid_credentials=True)
    try:
        with pytest.raises(ClientError) as rejected:
            invalid.get_object(Bucket=BUCKET, Key=key)
        assert rejected.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403
    finally:
        invalid.close()


def check_oidc(stack):
    issuer = stack.gateway("/auth/realms/flashcards")
    status, body = http(issuer + "/.well-known/openid-configuration")
    assert status == 200
    discovery = json.loads(body)
    assert discovery["issuer"] == issuer
    status, keys = http(discovery["jwks_uri"])
    assert status == 200
    key_ids = {key["kid"] for key in json.loads(keys)["keys"]}
    status, token_body = http(
        discovery["token_endpoint"],
        data=urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": CLIENT,
                "client_secret": stack.settings["credentials"]["oidc_client_secret"],
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 200, "OIDC client credentials grant did not succeed"
    token = json.loads(token_body)["access_token"]
    header, claims, signature = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    claims = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))
    assert signature and header["kid"] in key_ids
    assert claims["iss"] == issuer
    audience = claims["aud"]
    assert CLIENT in ([audience] if isinstance(audience, str) else audience)
    assert claims["exp"] > time.time()
    # This tests discovery and actual issuance, NOT cryptographic JWT validation.


def check_trace_export(stack):
    trace_id, parent_id = uuid4().hex, uuid4().hex[:16]
    status, _ = http(
        stack.gateway("/api/v1/status"),
        headers={"traceparent": f"00-{trace_id}-{parent_id}-01"},
    )
    assert status == 200
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        logs = stack.compose(["logs", "--no-color", "otel-collector"]).stdout
        if trace_id in logs:
            return
        time.sleep(0.5)
    pytest.fail("Collector did not receive the trace ID from an actual gateway HTTP request")


async def require_jetstream_persistence(stack):
    connection = await stack.broker()
    try:
        jetstream = connection.jetstream()
        info = await jetstream.stream_info(STREAM)
        assert info.state.messages == 3
        assert (await jetstream.get_msg(STREAM, seq=3)).data == MARKER
        consumer = await jetstream.consumer_info(STREAM, DURABLE)
        assert consumer.ack_floor.stream_seq == 2
    finally:
        await connection.close()


def check_persistence(stack):
    assert stack.sql("postgres-content", "content", "SELECT id FROM fcb60_persistence_probe") == "1"
    assert (
        stack.sql(
            "postgres-identity",
            "keycloak",
            "SELECT count(*) FROM realm WHERE name='flashcards'",
        )
        == "1"
    )
    assert (
        stack.sql("postgres-identity", "keycloak", "SELECT id FROM fcb60_persistence_probe") == "1"
    )
    asyncio.run(require_jetstream_persistence(stack))
    cache = stack.cache()
    try:
        assert cache.get("fcb60:persistence") == MARKER
    finally:
        cache.close()
    objects = stack.objects()
    try:
        with objects.get_object(Bucket=BUCKET, Key="fcb60/persistence.bin")["Body"] as body:
            assert body.read() == MARKER
    finally:
        objects.close()
    check_oidc(stack)


def exercise_stack(stack):
    core = [
        "postgres-content",
        "postgres-identity",
        "keycloak",
        "nats",
        "redis",
        "s3",
        "content-service",
        "gateway",
    ]
    original_settings = fingerprint(stack.settings)
    stack.stage = "core startup and health"
    stack.cli("up", "core")
    stack.require_healthy(core)
    check_http(stack)
    stack.stage = "PostgreSQL migration, credentials and isolation"
    check_database(stack)
    stack.stage = "JetStream acknowledgements and durable reconnect"
    asyncio.run(check_jetstream(stack))
    stack.stage = "Redis authentication and AOF"
    check_redis(stack)
    stack.stage = "private S3 CRUD and presigned access"
    check_s3(stack)
    stack.stage = "OIDC discovery and token issuance"
    check_oidc(stack)

    stack.stage = "full startup, profile probe and telemetry export"
    stack.cli("up", "full")
    stack.require_healthy([*core, "otel-collector", "adminer"])
    check_http(stack)
    stack.cli("probe", "full")
    check_trace_export(stack)

    stack.stage = "database loss and readiness recovery"
    stack.compose(["stop", "--timeout", "10", "postgres-content"])
    assert http(stack.gateway("/health/live"))[0] == 200
    assert http(stack.gateway("/health/ready"))[0] == 503
    stack.compose(["up", "--detach", "--no-build", "--wait", "--wait-timeout", "240"], timeout=600)
    check_http(stack)

    stack.stage = "restart persistence"
    stack.compose(["restart", "--timeout", "10"], timeout=180)
    stack.compose(["up", "--detach", "--no-build", "--wait", "--wait-timeout", "240"], timeout=600)
    stack.require_healthy([*core, "otel-collector", "adminer"])
    check_persistence(stack)

    stack.stage = "down and up persistence"
    stack.cli("down")
    assert fingerprint(bootstrap(ROOT, stack.project, ephemeral_ports=True)) == original_settings
    stack.compose(["up", "--detach", "--no-build", "--wait", "--wait-timeout", "240"], timeout=600)
    stack.require_healthy([*core, "otel-collector", "adminer"])
    check_http(stack)
    check_persistence(stack)
    check_trace_export(stack)
    assert fingerprint(load_settings(ROOT, stack.project)) == original_settings
    stack.stage = "tested image identity inventory"
    stack.record_images()


def test_real_local_stack_protocols_isolation_and_persistence(stack):
    failure_type = None
    try:
        exercise_stack(stack)
    except (Exception, pytest.fail.Exception) as error:
        failure_type = type(error).__name__
        stack.failure_diagnostics()
    if failure_type:
        # Do not render SDK frames, locals or request parameters containing credentials.
        pytest.fail(
            f"Local stack stage '{stack.stage}' failed ({failure_type}); "
            f"inspect local-only .local/{stack.project}/diagnostics.json",
            pytrace=False,
        )
