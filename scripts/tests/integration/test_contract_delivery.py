"""Real TCP HTTP and isolated JetStream proof; never silently skip a missing broker."""

from __future__ import annotations

import asyncio
import copy
import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

import nats
import pytest
from nats.errors import TimeoutError as NatsTimeout

from scripts.contracts.build import clean_environment
from scripts.contracts.reference import (
    FETCH_TIMEOUT,
    MAX_DELIVER,
    ContractFixtures,
    ReferenceRuntime,
    ReferenceStore,
    Rejected,
    SimulatedCrash,
)
from scripts.security.common import read_json
from scripts.security.run_scans import run, verified_tool

ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def broker():
    project = "fcb70-" + uuid4().hex[:12]
    command = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--env-file",
        "/dev/null",
        "--file",
        str(ROOT / "compose.contracts.yaml"),
    ]
    try:
        result = subprocess.run(
            command + ["up", "--detach", "--wait", "--wait-timeout", "60"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        assert result.returncode == 0, "Isolated contract broker failed to become healthy"
        port = subprocess.run(
            command + ["port", "broker", "4222"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
        assert port.startswith("127.0.0.1:")
        yield "nats://" + port
    finally:
        # This UUID-scoped project belongs only to this fixture. No global prune/rm.
        subprocess.run(
            command + ["down", "--volumes", "--remove-orphans", "--timeout", "5"],
            cwd=ROOT,
            capture_output=True,
            timeout=30,
            check=True,
        )


@pytest.fixture(scope="module")
def http_url(tmp_path_factory):
    directory = tmp_path_factory.mktemp("real-contract-http")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    script = """
import sys
sys.path.insert(0, sys.argv[1])
import uvicorn
from app.core.config import Settings
from app.main import create_app
uvicorn.run(create_app(Settings(_env_file=None, environment="test")),
            fd=int(sys.argv[2]), log_level="warning")
"""
    service = ROOT / "services/content-service"
    try:
        process = subprocess.Popen(
            [
                str(service / ".venv/bin/python"),
                "-I",
                "-B",
                "-c",
                script,
                str(service / "src"),
                str(listener.fileno()),
            ],
            cwd=directory,
            env=clean_environment(directory),
            pass_fds=(listener.fileno(),),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    finally:
        listener.close()
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                with urllib.request.urlopen(base + "/health/live", timeout=1) as response:
                    assert response.status == 200
                break
            except OSError, urllib.error.URLError:
                assert process.poll() is None and time.monotonic() < deadline, (
                    "HTTP fixture did not start"
                )
                time.sleep(0.05)
        yield base
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@asynccontextmanager
async def runtime(url, directory):
    connection = await nats.connect(url, connect_timeout=2, max_reconnect_attempts=0)
    store = ReferenceStore(directory / "projection.sqlite")
    current = ReferenceRuntime(
        connection.jetstream(), ContractFixtures(ROOT), store, "test" + uuid4().hex[:12]
    )
    try:
        await current.setup()
        yield current
    finally:
        current.store.close()
        await connection.close()


def example(fixtures, binding, **changes):
    path = fixtures.entries[binding["contract_id"]]["schema_path"]
    payload = copy.deepcopy(read_json(ROOT / path)["examples"][0])
    payload["id"] = str(uuid4())
    if "aggregate_id" in payload:
        payload["aggregate_id"] = str(uuid4())
    return {**payload, **changes}


async def next_message(consumer):
    return (await consumer.fetch(batch=1, timeout=FETCH_TIMEOUT))[0]


def test_every_supported_http_binding_uses_real_network_response(http_url):
    fixtures = ContractFixtures(ROOT)
    visited = []
    for binding in fixtures.bindings:
        if binding["transport"] == "http":
            with urllib.request.urlopen(http_url + binding["locator"], timeout=2) as response:
                payload = json.load(response)
                assert response.status == 200
            assert fixtures.http(binding, payload).name
            visited.append(binding["contract_id"])
    assert visited, "At least one real HTTP binding is required"


def test_real_locked_oasdiff_distinguishes_additive_and_breaking_changes(tmp_path):
    binary, version = verified_tool(ROOT, "oasdiff", install=True)
    assert version == "1.33.0"
    original = read_json(ROOT / "contracts/openapi/content-service/0.1.0/openapi.json")
    base = tmp_path / "base.json"
    candidate = tmp_path / "candidate.json"
    base.write_text(json.dumps(original))
    additive = copy.deepcopy(original)
    additive["paths"]["/api/v1/extra-status"] = copy.deepcopy(original["paths"]["/api/v1/status"])
    additive["paths"]["/api/v1/extra-status"]["get"]["operationId"] = "extra_status"
    candidate.write_text(json.dumps(additive))
    command = [
        binary,
        "breaking",
        "--format",
        "json",
        "--fail-on",
        "WARN",
        "--allow-external-refs=false",
        str(base),
        str(candidate),
    ]
    assert run(command, ROOT, allowed=(0, 1)).returncode == 0
    breaking = copy.deepcopy(original)
    del breaking["paths"]["/api/v1/status"]
    candidate.write_text(json.dumps(breaking))
    result = run(command, ROOT, allowed=(0, 1))
    assert result.returncode == 1
    assert json.loads(result.stdout), "The real scanner must explain the removed operation"


def test_all_event_versions_publish_consume_and_deduplicate(broker, tmp_path):
    async def scenario():
        async with runtime(broker, tmp_path) as current:
            visited = []
            for index, binding in enumerate(current.fixtures.bindings):
                if binding["transport"] != "nats":
                    continue
                consumer = await current.consumer(binding, f"consumer_{index}")
                payload = example(current.fixtures, binding)
                first = await current.publish(binding, payload)
                assert await current.handle(await next_message(consumer)) == "applied"
                duplicate = await current.publish(binding, payload)
                assert duplicate.duplicate is True and duplicate.seq == first.seq
                await current.publish(binding, payload, replay=True)
                assert await current.handle(await next_message(consumer)) == "duplicate"
                assert current.store.state(payload.get("aggregate_id", payload["id"])) == (1, 1)
                visited.append(binding["contract_id"])
            assert set(visited) == {
                item["contract_id"]
                for item in current.fixtures.bindings
                if item["transport"] == "nats"
            }

    asyncio.run(scenario())


def test_crash_after_commit_before_ack_survives_consumer_restart(broker, tmp_path):
    async def scenario():
        async with runtime(broker, tmp_path) as current:
            binding = current.fixtures.event_binding("2.0.0")
            consumer = await current.consumer(binding, "crash")
            payload = example(current.fixtures, binding)
            await current.publish(binding, payload)
            with pytest.raises(SimulatedCrash):
                await current.handle(await next_message(consumer), crash_before_ack=True)
            current.store.close()
            current.store = ReferenceStore(tmp_path / "projection.sqlite")
            restarted = await current.js.pull_subscribe_bind(durable="crash", stream=current.stream)
            message = await next_message(restarted)
            assert message.metadata.num_delivered >= 2
            assert await current.handle(message) == "duplicate"
            assert current.store.state(payload["aggregate_id"]) == (1, 1)

    asyncio.run(scenario())


def test_retry_then_success_and_handled_exhaustion_to_dlq(broker, tmp_path):
    async def scenario():
        async with runtime(broker, tmp_path) as current:
            binding = current.fixtures.event_binding("2.0.0")
            consumer = await current.consumer(binding, "retry")
            payload = example(current.fixtures, binding)
            await current.publish(binding, payload)
            first = await next_message(consumer)
            assert await current.handle(first, transient_failure=True) == "retry"
            second = await next_message(consumer)
            assert second.metadata.num_delivered == 2
            assert await current.handle(second) == "applied"
            poison = example(current.fixtures, binding)
            await current.publish(binding, poison)
            for attempt in range(1, MAX_DELIVER + 1):
                message = await next_message(consumer)
                assert message.metadata.num_delivered == attempt
                result = await current.handle(message, transient_failure=True)
                assert result == ("quarantined" if attempt == MAX_DELIVER else "retry")
            dead = await current.js.get_last_msg(
                "DLQ_" + current.namespace, current.namespace + ".dlq"
            )
            assert dead.headers["FCB-Reason"] == "max_attempts"
            assert current.store.state(poison["aggregate_id"]) is None

    asyncio.run(scenario())


def test_unhandled_last_attempt_is_recovered_from_persisted_advisory(broker, tmp_path):
    async def scenario():
        async with runtime(broker, tmp_path) as current:
            binding = current.fixtures.event_binding("2.0.0")
            consumer = await current.consumer(binding, "unhandled")
            await current.publish(binding, example(current.fixtures, binding))
            for attempt in range(1, MAX_DELIVER + 1):
                message = await next_message(consumer)
                assert message.metadata.num_delivered == attempt
                # Simulate process failure: neither business commit nor ACK/NAK happens.
            with pytest.raises(NatsTimeout):
                await next_message(consumer)
            advisories = await current.js.pull_subscribe_bind(
                durable="recover", stream=current.advisory_stream
            )
            advisory = await next_message(advisories)
            await current.recover_exhausted(advisory)
            dead = await current.js.get_last_msg(
                "DLQ_" + current.namespace, current.namespace + ".dlq"
            )
            assert dead.headers["FCB-Reason"] == "max_deliveries"

    asyncio.run(scenario())


def test_additive_fields_unsupported_versions_and_invalid_known_fields(broker, tmp_path):
    async def scenario():
        async with runtime(broker, tmp_path) as current:
            binding = current.fixtures.event_binding("2.0.0")
            consumer = await current.consumer(binding, "validation")
            payload = example(current.fixtures, binding)
            additive = {
                **payload,
                "future": "ignored",
                "data": {**payload["data"], "future": 1},
            }
            with pytest.raises(Rejected, match="invalid_schema"):
                current.fixtures.wire(binding, additive)  # Strict producer contract stays strict.
            await current.js.publish(
                current.namespace + "." + binding["locator"],
                json.dumps(additive).encode(),
            )
            assert await current.handle(await next_message(consumer)) == "applied"
            legacy = current.fixtures.event_binding("1.0.0")
            legacy_consumer = await current.consumer(legacy, "legacy_additions")
            old_payload = example(current.fixtures, legacy)
            await current.js.publish(
                current.namespace + "." + legacy["locator"],
                json.dumps(
                    {
                        **old_payload,
                        "aggregate_id": "ignored",
                        "aggregate_sequence": "ignored",
                    }
                ).encode(),
            )
            assert await current.handle(await next_message(legacy_consumer)) == "applied"
            assert current.store.state(old_payload["id"]) == (1, 1)
            assert current.store.state("ignored") is None
            for changes, reason in (
                ({"version": "9.0.0"}, "unsupported_version"),
                ({"id": "not-a-uuid"}, "invalid_schema"),
                ({"trace": {"traceparent": "invalid"}}, "invalid_schema"),
            ):
                invalid = {
                    **example(current.fixtures, binding),
                    **changes,
                    "future": True,
                }
                await current.js.publish(
                    current.namespace + "." + binding["locator"],
                    json.dumps(invalid).encode(),
                )
                assert await current.handle(await next_message(consumer)) == "quarantined"
                dead = await current.js.get_last_msg(
                    "DLQ_" + current.namespace, current.namespace + ".dlq"
                )
                assert dead.headers["FCB-Reason"] == reason

    asyncio.run(scenario())


def test_order_quarantine_replay_and_fresh_projection_rebuild(broker, tmp_path):
    async def scenario():
        async with runtime(broker, tmp_path) as current:
            binding = current.fixtures.event_binding("2.0.0")
            consumer = await current.consumer(binding, "ordered")
            first = example(current.fixtures, binding)
            second = example(
                current.fixtures,
                binding,
                aggregate_id=first["aggregate_id"],
                aggregate_sequence=2,
            )
            await current.publish(binding, second)
            assert await current.handle(await next_message(consumer)) == "quarantined"
            assert current.store.state(first["aggregate_id"]) is None
            start = await current.publish(binding, first)
            assert await current.handle(await next_message(consumer)) == "applied"
            await current.publish(binding, second, replay=True)
            assert await current.handle(await next_message(consumer)) == "applied"
            assert current.store.state(first["aggregate_id"]) == (2, 2)
            rebuild = ReferenceStore(tmp_path / "rebuild.sqlite")
            try:
                replay = ReferenceRuntime(current.js, current.fixtures, rebuild, current.namespace)
                reader = await replay.consumer(binding, "rebuild", start_sequence=start.seq)
                assert await replay.handle(await next_message(reader)) == "applied"
                assert await replay.handle(await next_message(reader)) == "applied"
                assert rebuild.state(first["aggregate_id"]) == (2, 2)
            finally:
                rebuild.close()

    asyncio.run(scenario())
