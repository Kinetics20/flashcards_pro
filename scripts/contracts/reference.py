"""Executable reference fixtures, not a production publisher, outbox or job platform."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from uuid import uuid4

from jsonschema import Draft202012Validator, FormatChecker
from nats.js.api import (
    AckPolicy,
    ConsumerConfig,
    DeliverPolicy,
    RetentionPolicy,
    StorageType,
)
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from scripts.contracts.build import json_bytes
from scripts.contracts.support import load_support
from scripts.contracts.validate import _documents, load_registry
from scripts.security.common import _invalid_constant, _unique_pairs, read_json

MAX_PAYLOAD_BYTES = 64_000
MAX_PAYLOAD_DEPTH = 64
MAX_DELIVER = 3
ACK_WAIT = 0.3
RETRY_DELAY = 0.1
FETCH_TIMEOUT = 2.0
LOGGER = logging.getLogger(__name__)


class Rejected(ValueError):
    """A stable, safe reason code; never includes payload contents."""


class SimulatedCrash(RuntimeError):
    """Fault injected after durable commit and before acknowledging delivery."""


def decode(data: bytes) -> dict:
    if len(data) > MAX_PAYLOAD_BYTES:
        raise Rejected("payload_too_large")
    try:
        value = json.loads(data, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)
    except ValueError, UnicodeError, RecursionError:
        raise Rejected("invalid_json") from None
    if not isinstance(value, dict):
        raise Rejected("invalid_envelope")
    pending = [(value, 0)]
    while pending:
        node, depth = pending.pop()
        if depth > MAX_PAYLOAD_DEPTH:
            raise Rejected("payload_too_deep")
        if isinstance(node, dict):
            pending.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)
    return value


def additive_schema(value):
    """Relax unknown fields only; retain all constraints on known fields and maps."""
    if not isinstance(value, dict):
        return value
    output = dict(value)
    for key, item in value.items():
        if key in {"additionalProperties", "unevaluatedProperties"} and item is False:
            output[key] = True
        elif key in {
            "properties",
            "patternProperties",
            "$defs",
            "definitions",
            "dependentSchemas",
        }:
            output[key] = {name: additive_schema(child) for name, child in item.items()}
        elif key in {"allOf", "anyOf", "oneOf", "prefixItems"}:
            output[key] = [additive_schema(child) for child in item]
        elif key in {
            "items",
            "contains",
            "additionalProperties",
            "propertyNames",
            "not",
            "if",
            "then",
            "else",
            "unevaluatedProperties",
            "unevaluatedItems",
        }:
            output[key] = additive_schema(item)
    return output


class ContractFixtures:
    """All bindings are explicitly implemented adapters with generated DTO boundaries."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.bindings = load_support(self.root)["bindings"]
        self.entries = {entry["id"]: entry for entry in load_registry(self.root)["contracts"]}
        self.models = {}
        self.validators = {}
        for binding in self.bindings:
            entry = self.entries[binding["contract_id"]]
            for profile in ("server", "client"):
                name = entry["id"].replace("-", "_") + "_" + profile
                path = self.root / "contracts/generated/python" / (name + ".py")
                spec = importlib.util.spec_from_file_location("contract_fixture_" + name, path)
                if spec is None or spec.loader is None:
                    raise ValueError("Missing generated contract module")
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                self.models[(entry["id"], profile)] = module
            if entry["kind"] == "event":
                path = self.root / entry["schema_path"]
                documents = _documents(self.root, path, read_json(path))
                for profile in ("server", "client"):
                    resources = Registry().with_resources(
                        (
                            source.as_uri(),
                            Resource.from_contents(
                                additive_schema(schema) if profile == "client" else schema,
                                default_specification=DRAFT202012,
                            ),
                        )
                        for source, schema in documents.items()
                    )
                    self.validators[(entry["id"], profile)] = Draft202012Validator(
                        {"$ref": path.as_uri()},
                        registry=resources,
                        format_checker=FormatChecker(),
                    )

    def event_binding(self, version: str) -> dict:
        matches = [
            binding
            for binding in self.bindings
            if binding["transport"] == "nats" and binding["version"] == version
        ]
        if len(matches) != 1:
            raise Rejected("unsupported_version")
        return matches[0]

    def event(self, binding: dict, payload: dict, *, consumer: bool):
        if payload.get("version") != binding["version"]:
            raise Rejected("unsupported_version")
        profile = "client" if consumer else "server"
        key = (binding["contract_id"], profile)
        if next(self.validators[key].iter_errors(payload), None) is not None:
            raise Rejected("invalid_schema")
        schema = read_json(self.root / self.entries[binding["contract_id"]]["schema_path"])
        model = getattr(self.models[key], schema["title"])
        return model.model_validate(payload)

    def wire(self, binding: dict, payload: dict) -> bytes:
        model = self.event(binding, payload, consumer=False)
        data = model.model_dump_json(exclude_none=True).encode()
        self.event(binding, decode(data), consumer=False)
        return data

    def http(self, binding: dict, payload: dict):
        if binding["fixture"] != "status-http":
            raise Rejected("unsupported_http_fixture")
        module = self.models[(binding["contract_id"], "client")]
        return module.ServiceStatusResponse.model_validate(payload)


class ReferenceStore:
    """A durable test projection and inbox share one local SQLite transaction."""

    def __init__(self, path: Path):
        self.connection = sqlite3.connect(path, isolation_level=None)
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS inbox (event_id TEXT PRIMARY KEY, digest TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS projection (aggregate_id TEXT PRIMARY KEY, "
            "sequence INTEGER NOT NULL, applications INTEGER NOT NULL);"
        )

    def close(self):
        self.connection.close()

    def state(self, aggregate_id: str) -> tuple[int, int] | None:
        return self.connection.execute(
            "SELECT sequence, applications FROM projection WHERE aggregate_id = ?",
            (aggregate_id,),
        ).fetchone()

    def apply(self, payload: dict) -> str:
        digest = hashlib.sha256(json_bytes(payload)).hexdigest()
        event_id = payload["id"]
        aggregate_id = payload.get("aggregate_id", event_id)  # Legacy v1 has no ordering contract.
        sequence = payload.get("aggregate_sequence", 1)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            previous = self.connection.execute(
                "SELECT digest FROM inbox WHERE event_id = ?", (event_id,)
            ).fetchone()
            if previous:
                if previous[0] != digest:
                    raise Rejected("event_id_conflict")
                self.connection.commit()
                return "duplicate"
            state = self.state(aggregate_id)
            expected = state[0] + 1 if state else 1
            if sequence != expected:
                raise Rejected("sequence_gap" if sequence > expected else "stale_sequence")
            self.connection.execute("INSERT INTO inbox VALUES (?, ?)", (event_id, digest))
            self.connection.execute(
                "INSERT INTO projection VALUES (?, ?, 1) ON CONFLICT(aggregate_id) "
                "DO UPDATE SET sequence = excluded.sequence, applications = applications + 1",
                (aggregate_id, sequence),
            )
            self.connection.commit()
            return "applied"
        except BaseException:
            self.connection.rollback()
            raise


class ReferenceRuntime:
    """Real JetStream operations with deliberately small reference failure policies."""

    def __init__(self, js, fixtures: ContractFixtures, store: ReferenceStore, namespace: str):
        if not re.fullmatch(r"test[a-f0-9]{12}", namespace):
            raise ValueError("Use a fresh, scoped contract-test namespace")
        self.js, self.fixtures, self.store, self.namespace = (
            js,
            fixtures,
            store,
            namespace,
        )
        self.stream = "EVENTS_" + namespace
        self.advisory_stream = "ADVISORIES_" + namespace
        self.metrics: Counter = Counter()

    async def setup(self):
        for name, subjects in (
            (self.stream, [self.namespace + ".reference.>"]),
            ("DLQ_" + self.namespace, [self.namespace + ".dlq"]),
            (
                self.advisory_stream,
                [f"$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES.{self.stream}.*"],
            ),
        ):
            await self.js.add_stream(
                name=name,
                subjects=subjects,
                retention=RetentionPolicy.LIMITS,
                storage=StorageType.FILE,
                max_msgs=1000,
                max_bytes=8_000_000,
                max_age=300,
                duplicate_window=60,
            )
        await self.js.add_consumer(
            self.advisory_stream,
            config=ConsumerConfig(
                durable_name="recover",
                ack_policy=AckPolicy.EXPLICIT,
                ack_wait=ACK_WAIT,
            ),
        )

    async def consumer(self, binding: dict, name: str, *, start_sequence: int | None = None):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,50}", name):
            raise ValueError("Invalid reference consumer name")
        config = ConsumerConfig(
            durable_name=name,
            ack_policy=AckPolicy.EXPLICIT,
            ack_wait=ACK_WAIT,
            max_deliver=MAX_DELIVER,
            max_ack_pending=1,
            filter_subject=self.namespace + "." + binding["locator"],
            deliver_policy=DeliverPolicy.BY_START_SEQUENCE if start_sequence else DeliverPolicy.ALL,
            opt_start_seq=start_sequence,
        )
        await self.js.add_consumer(self.stream, config=config)
        return await self.js.pull_subscribe_bind(durable=name, stream=self.stream)

    async def publish(self, binding: dict, payload: dict, *, replay: bool = False):
        wire = self.fixtures.wire(binding, payload)
        # Replay preserves business identity, but uses a new transport publication ID.
        publication = f"replay:{uuid4()}:{payload['id']}" if replay else payload["id"]
        return await self.js.publish(
            self.namespace + "." + binding["locator"],
            wire,
            headers={"Nats-Msg-Id": publication},
            timeout=FETCH_TIMEOUT,
        )

    def observe(self, outcome: str, payload: dict | None = None):
        self.metrics[outcome] += 1
        trace = payload.get("trace", {}) if payload else {}
        LOGGER.info(
            "Reference contract delivery: %s",
            outcome,
            extra={
                "contract_outcome": outcome,
                "event_id": payload.get("id") if payload else None,
                "traceparent": trace.get("traceparent") if isinstance(trace, dict) else None,
            },
        )

    async def quarantine(self, data: bytes, subject: str, sequence: int, reason: str):
        await self.js.publish(
            self.namespace + ".dlq",
            data,
            headers={
                "Nats-Msg-Id": f"{self.stream}:{sequence}",
                "FCB-Reason": reason,
                "FCB-Source-Subject": subject,
                "FCB-Source-Sequence": str(sequence),
            },
            timeout=FETCH_TIMEOUT,
        )
        self.observe("quarantined_" + reason)

    async def handle(
        self,
        message,
        *,
        transient_failure: bool = False,
        crash_before_ack: bool = False,
    ):
        payload = None
        try:
            payload = decode(message.data)
            binding = self.fixtures.event_binding(payload.get("version"))
            if message.subject != self.namespace + "." + binding["locator"]:
                raise Rejected("subject_version_mismatch")
            # Unknown additive fields must not acquire business meaning accidentally.
            # The canonical wire validator still checks every known field before this.
            payload = self.fixtures.event(binding, payload, consumer=True).model_dump(
                mode="json", exclude_none=True
            )
            if transient_failure:
                if message.metadata.num_delivered >= MAX_DELIVER:
                    raise Rejected("max_attempts")
                await message.nak(delay=RETRY_DELAY)
                self.observe("retry", payload)
                return "retry"
            outcome = self.store.apply(payload)
        except Rejected as error:
            await self.quarantine(
                message.data,
                message.subject,
                message.metadata.sequence.stream,
                str(error),
            )
            await message.ack_sync(timeout=FETCH_TIMEOUT)
            return "quarantined"
        self.observe(outcome, payload)
        if crash_before_ack:
            raise SimulatedCrash("Durable projection committed; ACK intentionally not sent")
        await message.ack_sync(timeout=FETCH_TIMEOUT)
        return outcome

    async def recover_exhausted(self, advisory):
        payload = decode(advisory.data)
        if payload.get("stream") != self.stream or type(payload.get("stream_seq")) is not int:
            raise Rejected("invalid_advisory")
        sequence = payload["stream_seq"]
        if sequence < 1:
            raise Rejected("invalid_advisory")
        original = await self.js.get_msg(self.stream, seq=sequence)
        await self.quarantine(original.data, original.subject, sequence, "max_deliveries")
        await advisory.ack_sync(timeout=FETCH_TIMEOUT)
