"""Explicit standalone Compose inventory and secret-free, all-profile rendering."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from .common import contained_path, read_json
from .run_scans import ScanError, run

INVENTORY = "security/compose-targets.json"
TOKEN = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")


def load_targets(root: Path, tracked: list[str] | None = None) -> list[dict[str, str]]:
    """Require every tracked Compose file to be explicitly classified, never overlay-merge."""
    document = read_json(root / INVENTORY)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "targets"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(document["targets"], list)
        or not document["targets"]
    ):
        raise ScanError("Compose inventory is invalid")
    targets = document["targets"]
    ids, paths = set(), set()
    for target in targets:
        if (
            not isinstance(target, dict)
            or set(target) != {"id", "path", "kind"}
            or not isinstance(target["id"], str)
            or not TOKEN.fullmatch(target["id"])
            or not isinstance(target["kind"], str)
            or target["kind"] not in {"local", "template", "contracts"}
            or not isinstance(target["path"], str)
        ):
            raise ScanError("Compose inventory entry is invalid")
        path = contained_path(root, target["path"])
        if not path.is_file() or (root / target["path"]).is_symlink():
            raise ScanError("Compose inventory input is missing or unsafe")
        if target["id"] in ids or target["path"] in paths:
            raise ScanError("Compose inventory contains duplicate entries")
        ids.add(target["id"])
        paths.add(target["path"])
    if tracked is None:
        tracked = run(["git", "ls-files", "-z"], root).stdout.split("\0")
    discovered = {
        name
        for name in tracked
        if re.fullmatch(r"(?:docker-)?compose(?:[.-][a-zA-Z0-9_-]+)*\.ya?ml", Path(name).name)
    }
    if paths != discovered:
        raise ScanError("Tracked Compose files and explicit inventory differ")
    kinds = [target["kind"] for target in targets]
    if kinds.count("local") != 1 or kinds.count("contracts") != 1 or "template" not in kinds:
        raise ScanError("Compose inventory must include local, contracts and template stacks")
    return targets


def clean_environment() -> dict[str, str]:
    """Keep only process/Docker connectivity, never application or Compose overrides."""
    allowed = (
        "PATH",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    )
    return {
        **{name: os.environ[name] for name in allowed if name in os.environ},
        "COMPOSE_DISABLE_ENV_FILE": "1",
        "NO_COLOR": "1",
    }


def render(root: Path, target: dict[str, str], image_tag: str = "security") -> dict[str, Any]:
    """Return config in memory only; forbid implicit secondary Compose inputs."""
    if not isinstance(image_tag, str) or len(image_tag) > 63 or not TOKEN.fullmatch(image_tag):
        raise ScanError("Local image tag is invalid")
    source = contained_path(root, target["path"])
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        raise ScanError("Compose YAML is invalid; source values are withheld") from None
    if not isinstance(raw, dict) or "include" in raw:
        raise ScanError("Compose must be a standalone document without includes")
    services = raw.get("services")
    if (
        not isinstance(services, dict)
        or not services
        or any(not isinstance(item, dict) or "extends" in item for item in services.values())
    ):
        raise ScanError("Compose must define services without implicit extensions")
    environment = clean_environment()
    if target["kind"] == "local":
        from scripts.local.stack import config_environment

        environment.update(config_environment(root, "fcb-security", "full", settings=None))
        environment["FCB_LOCAL_IMAGE_TAG"] = image_tag
    result = run(
        [
            "docker",
            "compose",
            "--project-name",
            "fcb-security",
            "--env-file",
            "/dev/null",
            "--profile",
            "*",
            "-f",
            str(source),
            "config",
            "--no-env-resolution",
            "--format",
            "json",
        ],
        root,
        environment=environment,
    )
    # Do not include JSON decoder messages, source config or subprocess output in errors.
    import json

    try:
        document = json.loads(result.stdout)
    except ValueError:
        raise ScanError("Compose did not produce valid JSON") from None
    if not isinstance(document, dict) or set(document.get("services", {})) != set(services):
        raise ScanError("Compose all-profile output omitted or added services")
    return document


def documents(
    root: Path, image_tag: str = "security"
) -> list[tuple[dict[str, str], dict[str, Any]]]:
    return [(target, render(root, target, image_tag)) for target in load_targets(root)]
