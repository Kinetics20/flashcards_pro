"""Reference adapter failure paths and wire constraints without external services."""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from scripts.contracts import reference as module
from scripts.security.common import read_json

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def fixtures():
    return module.ContractFixtures(ROOT)


@pytest.fixture
def binding(fixtures):
    return fixtures.event_binding("2.0.0")


@pytest.fixture
def payload(fixtures, binding):
    entry = fixtures.entries[binding["contract_id"]]
    result = copy.deepcopy(read_json(ROOT / entry["schema_path"])["examples"][0])
    result["id"], result["aggregate_id"] = str(uuid4()), str(uuid4())
    return result


@pytest.fixture
def runtime(tmp_path, fixtures):
    js = SimpleNamespace(
        **{
            name: AsyncMock()
            for name in (
                "add_stream",
                "add_consumer",
                "pull_subscribe_bind",
                "publish",
                "get_msg",
            )
        }
    )
    store = module.ReferenceStore(tmp_path / "reference.sqlite")
    value = module.ReferenceRuntime(js, fixtures, store, "test123456abcdef")
    yield value
    store.close()


def message(runtime, payload, *, attempts=1, subject=None, raw=None):
    binding = runtime.fixtures.event_binding("2.0.0")
    return SimpleNamespace(
        data=raw if raw is not None else json.dumps(payload).encode(),
        subject=subject or runtime.namespace + "." + binding["locator"],
        metadata=SimpleNamespace(num_delivered=attempts, sequence=SimpleNamespace(stream=42)),
        ack_sync=AsyncMock(),
        nak=AsyncMock(),
    )


@pytest.mark.parametrize(
    "raw,reason",
    [
        (b"x" * (module.MAX_PAYLOAD_BYTES + 1), "payload_too_large"),
        (b"broken", "invalid_json"),
        (b"\xff", "invalid_json"),
        (b'{"x":1,"x":2}', "invalid_json"),
        (b'{"x":NaN}', "invalid_json"),
        (b"[]", "invalid_envelope"),
        (b"null", "invalid_envelope"),
    ],
)
def test_wire_decoder_fails_closed(raw, reason):
    with pytest.raises(module.Rejected, match=reason):
        module.decode(raw)


def test_deep_json_is_bounded_independently_of_python_parser():
    nested = b'{"x":' + b"[" * 70 + b"0" + b"]" * 70 + b"}"
    with pytest.raises(module.Rejected, match="payload_too_deep"):
        module.decode(nested)
    assert module.decode(b'{"x":[1, {"key": true}]}') == {"x": [1, {"key": True}]}


def test_additive_profile_only_relaxes_unknown_object_fields():
    original = {
        "additionalProperties": False,
        "unevaluatedProperties": False,
        "properties": {"additionalProperties": False, "title": {"type": "string"}},
        "items": {"additionalProperties": {"type": "integer"}},
        "allOf": [{"additionalProperties": False}],
        "const": {"additionalProperties": False},
    }
    result = module.additive_schema(original)
    assert result["additionalProperties"] is True
    assert result["unevaluatedProperties"] is True
    assert result["properties"]["additionalProperties"] is False
    assert result["properties"]["title"] == {"type": "string"}
    assert result["items"]["additionalProperties"] == {"type": "integer"}
    assert result["allOf"][0]["additionalProperties"] is True
    assert result["const"]["additionalProperties"] is False
    assert original["additionalProperties"] is False


def test_missing_module_spec_fails(monkeypatch):
    monkeypatch.setattr(module.importlib.util, "spec_from_file_location", lambda *args: None)
    with pytest.raises(ValueError, match="Missing generated"):
        module.ContractFixtures(ROOT)


def test_consumer_additions_do_not_weaken_producer(fixtures, binding, payload):
    future = {
        **payload,
        "future": {"nested": 1},
        "data": {**payload["data"], "new": True},
    }
    assert fixtures.event(binding, future, consumer=True)
    with pytest.raises(module.Rejected, match="invalid_schema"):
        fixtures.event(binding, future, consumer=False)
    assert module.decode(fixtures.wire(binding, payload)) == payload


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "bad"},
        {"aggregate_id": "bad"},
        {"aggregate_sequence": "1"},
        {"aggregate_sequence": 0},
        {"aggregate_sequence": True},
        {"aggregate_sequence": 9223372036854775808},
        {"trace": None},
        {"trace": {"traceparent": "00-" + "0" * 32 + "-" + "1" * 16 + "-01"}},
        {"occurred_at": "2026-10-14T02:00:00+02:00"},
        {"occurred_at": "not-a-time"},
        {"data": {"status": "unknown"}},
        {"source": "unknown"},
    ],
)
def test_tolerant_consumer_rejects_invalid_known_fields(fixtures, binding, payload, changes):
    with pytest.raises(module.Rejected, match="invalid_schema"):
        fixtures.event(binding, {**payload, **changes, "future": True}, consumer=True)


@pytest.mark.parametrize("version", [None, "", "9.0.0", "2.0", "v2.0.0", 2, {}])
def test_versions_are_exact(fixtures, binding, payload, version):
    with pytest.raises(module.Rejected, match="unsupported_version"):
        fixtures.event_binding(version)
    with pytest.raises(module.Rejected, match="unsupported_version"):
        fixtures.event(binding, {**payload, "version": version}, consumer=True)


def test_http_binding_is_explicit(fixtures):
    binding = next(item for item in fixtures.bindings if item["transport"] == "http")
    assert fixtures.http(binding, {"name": "Reference", "version": "0.1.0", "environment": "test"})
    with pytest.raises(module.Rejected, match="unsupported_http_fixture"):
        fixtures.http({**binding, "fixture": "unknown"}, {})


def test_store_deduplicates_and_rejects_conflicting_identity(runtime, payload):
    assert runtime.store.apply(payload) == "applied"
    assert runtime.store.apply(payload) == "duplicate"
    with pytest.raises(module.Rejected, match="event_id_conflict"):
        runtime.store.apply({**payload, "data": {"status": "unavailable"}})
    assert runtime.store.state(payload["aggregate_id"]) == (1, 1)


def test_store_gap_can_be_replayed_after_predecessor(runtime, payload):
    second = {**payload, "id": str(uuid4()), "aggregate_sequence": 2}
    with pytest.raises(module.Rejected, match="sequence_gap"):
        runtime.store.apply(second)
    assert runtime.store.state(payload["aggregate_id"]) is None
    runtime.store.apply(payload)
    runtime.store.apply(second)
    with pytest.raises(module.Rejected, match="stale_sequence"):
        runtime.store.apply({**payload, "id": str(uuid4())})
    assert runtime.store.state(payload["aggregate_id"]) == (2, 2)


def test_store_legacy_no_ordering_contract(runtime):
    payload = {"id": str(uuid4()), "data": {"status": "ok"}}
    runtime.store.apply(payload)
    assert runtime.store.state(payload["id"]) == (1, 1)


def test_runtime_requires_scoped_namespace(runtime):
    with pytest.raises(ValueError, match="namespace"):
        module.ReferenceRuntime(runtime.js, runtime.fixtures, runtime.store, "production")


def test_broker_setup_persists_advisories_before_publication(runtime):
    asyncio.run(runtime.setup())
    assert runtime.js.add_stream.await_count == 3
    streams = runtime.js.add_stream.await_args_list
    assert all(call.kwargs["storage"].value == "file" for call in streams)
    assert all(call.kwargs["retention"].value == "limits" for call in streams)
    assert "MAX_DELIVERIES" in streams[2].kwargs["subjects"][0]
    runtime.js.add_consumer.assert_awaited_once()


@pytest.mark.parametrize("start", [None, 5])
def test_consumer_options_and_bound_subscription(runtime, binding, start):
    result = asyncio.run(runtime.consumer(binding, "reader", start_sequence=start))
    config = runtime.js.add_consumer.await_args.kwargs["config"]
    assert config.opt_start_seq == start
    assert config.max_deliver == module.MAX_DELIVER
    assert config.ack_policy.value == "explicit"
    assert result == runtime.js.pull_subscribe_bind.return_value


def test_consumer_rejects_invalid_name(runtime, binding):
    with pytest.raises(ValueError, match="consumer name"):
        asyncio.run(runtime.consumer(binding, "../../outside"))


@pytest.mark.parametrize("replay", [False, True])
def test_publish_waits_for_ack_and_replay_retains_business_identity(
    runtime, binding, payload, replay
):
    asyncio.run(runtime.publish(binding, payload, replay=replay))
    call = runtime.js.publish.await_args
    assert module.decode(call.args[1])["id"] == payload["id"]
    publication = call.kwargs["headers"]["Nats-Msg-Id"]
    assert publication.endswith(payload["id"])
    assert publication.startswith("replay:") is replay


def test_observability_has_trace_but_no_payload_dump(runtime, payload, caplog):
    with caplog.at_level(logging.INFO, logger=module.__name__):
        runtime.observe("applied", {**payload, "secret": "never-log-this"})
        runtime.observe("empty")
        runtime.observe("invalid_trace", {"trace": "wrong"})
    assert runtime.metrics["applied"] == 1
    assert caplog.records[0].traceparent == payload["trace"]["traceparent"]
    assert caplog.records[0].event_id == payload["id"]
    assert "never-log-this" not in caplog.text


def test_business_commit_precedes_ack_and_crash_causes_safe_duplicate(runtime, payload):
    item = message(runtime, payload)
    with pytest.raises(module.SimulatedCrash):
        asyncio.run(runtime.handle(item, crash_before_ack=True))
    item.ack_sync.assert_not_awaited()
    assert runtime.store.state(payload["aggregate_id"]) == (1, 1)
    assert asyncio.run(runtime.handle(item)) == "duplicate"
    item.ack_sync.assert_awaited_once()


def test_successful_message_is_applied(runtime, payload):
    item = message(runtime, payload)
    assert asyncio.run(runtime.handle(item)) == "applied"
    item.ack_sync.assert_awaited_once_with(timeout=module.FETCH_TIMEOUT)


def test_legacy_additions_are_ignored_by_business_projection(runtime):
    binding = runtime.fixtures.event_binding("1.0.0")
    path = runtime.fixtures.entries[binding["contract_id"]]["schema_path"]
    payload = {
        **read_json(ROOT / path)["examples"][0],
        "aggregate_id": "unknown-field-must-not-select-an-aggregate",
        "aggregate_sequence": "unknown-field-must-not-set-sequence",
    }
    item = message(runtime, payload, subject=runtime.namespace + "." + binding["locator"])
    assert asyncio.run(runtime.handle(item)) == "applied"
    assert runtime.store.state(payload["id"]) == (1, 1)
    assert runtime.store.state(payload["aggregate_id"]) is None
    assert asyncio.run(runtime.handle(item)) == "duplicate"


@pytest.mark.parametrize("attempts,expected", [(1, "retry"), (module.MAX_DELIVER, "quarantined")])
def test_retry_is_delayed_and_bounded(runtime, payload, attempts, expected):
    item = message(runtime, payload, attempts=attempts)
    assert asyncio.run(runtime.handle(item, transient_failure=True)) == expected
    if expected == "retry":
        item.nak.assert_awaited_once_with(delay=module.RETRY_DELAY)
        item.ack_sync.assert_not_awaited()
    else:
        assert runtime.js.publish.await_args.kwargs["headers"]["FCB-Reason"] == "max_attempts"
        item.ack_sync.assert_awaited_once()
    assert runtime.store.state(payload["aggregate_id"]) is None


@pytest.mark.parametrize(
    "change",
    ["invalid_json", "unsupported", "wrong_subject", "invalid_schema", "sequence_gap"],
)
def test_permanent_failures_are_quarantined(runtime, payload, change):
    changes = {
        "unsupported": {"version": "9.0.0"},
        "invalid_schema": {"id": "bad"},
        "sequence_gap": {"aggregate_sequence": 2},
    }
    item = message(
        runtime,
        {**payload, **changes.get(change, {})},
        raw=b"bad" if change == "invalid_json" else None,
        subject="wrong" if change == "wrong_subject" else None,
    )
    assert asyncio.run(runtime.handle(item)) == "quarantined"
    item.ack_sync.assert_awaited_once()
    assert runtime.js.publish.await_args.args[0].endswith(".dlq")
    assert runtime.store.state(payload["aggregate_id"]) is None


def test_dlq_publish_failure_does_not_ack_source(runtime, payload):
    item = message(runtime, {**payload, "version": "9.0.0"})
    runtime.js.publish.side_effect = TimeoutError("simulated transport failure")
    with pytest.raises(TimeoutError):
        asyncio.run(runtime.handle(item))
    item.ack_sync.assert_not_awaited()


@pytest.mark.parametrize(
    "fields",
    [{}, {"stream": "other", "stream_seq": 1}, {"stream_seq": True}, {"stream_seq": 0}],
)
def test_recovery_rejects_invalid_advisories(runtime, fields):
    payload = {"stream": runtime.stream, **fields}
    advisory = message(runtime, payload)
    with pytest.raises(module.Rejected, match="invalid_advisory"):
        asyncio.run(runtime.recover_exhausted(advisory))
    advisory.ack_sync.assert_not_awaited()


def test_recovery_routes_original_before_acknowledging_advisory(runtime):
    advisory = message(runtime, {"stream": runtime.stream, "stream_seq": 42})
    runtime.js.get_msg.return_value = SimpleNamespace(data=b"original", subject="original.subject")
    asyncio.run(runtime.recover_exhausted(advisory))
    runtime.js.get_msg.assert_awaited_once_with(runtime.stream, seq=42)
    assert runtime.js.publish.await_args.args[1] == b"original"
    assert runtime.js.publish.await_args.kwargs["headers"]["FCB-Reason"] == "max_deliveries"
    advisory.ack_sync.assert_awaited_once()
