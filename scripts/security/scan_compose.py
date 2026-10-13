"""Check rendered Compose JSON without retaining environment or secret values."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path, PurePosixPath
from typing import Any


class ComposeInputError(ValueError):
    """The rendered Compose document cannot be inspected safely."""


def scan_compose(document: dict[str, Any], source: str) -> list[dict[str, str]]:
    """Inspect `docker compose config --format json` using explicit local rules.

    This is a deliberately small policy scanner, not a complete Compose audit.
    Findings contain rule identifiers and configuration locations, never values
    from environment, commands, volume sources, build arguments, or credentials.
    """
    if not isinstance(document, dict):
        raise ComposeInputError("Compose document must be an object")
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise ComposeInputError("Compose document must contain nonempty services")
    if not isinstance(source, str) or not source:
        raise ComposeInputError("Compose source must be a nonempty path")
    if any(
        not isinstance(name, str) or not isinstance(value, dict) for name, value in services.items()
    ):
        raise ComposeInputError("Compose service must be a named object")

    findings: list[dict[str, str]] = []

    for service_name, service in sorted(services.items()):
        location = f"{source}#services.{service_name}"

        def report(rule: str, field: str, message: str, severity: str = "HIGH") -> None:
            findings.append(
                {
                    "id": rule,
                    "severity": severity,
                    "path": f"{location}.{field}",
                    "description": message,
                }
            )

        privileged = service.get("privileged", False)
        if not isinstance(privileged, bool):
            raise ComposeInputError("Rendered privileged setting must be boolean")
        if privileged:
            report("FCB-COMPOSE-001", "privileged", "Privileged container is forbidden")

        for field, rule in (("network_mode", "002"), ("pid", "003"), ("ipc", "004")):
            value = service.get(field)
            if value is not None and not isinstance(value, str):
                raise ComposeInputError("Rendered namespace setting must be text")
            if value == "host":
                report(f"FCB-COMPOSE-{rule}", field, "Host namespace sharing is forbidden")

        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            raise ComposeInputError("Rendered volumes must be a list")
        for index, volume in enumerate(volumes):
            if not isinstance(volume, dict) or not isinstance(volume.get("type"), str):
                raise ComposeInputError("Use rendered Compose long-form volume objects")
            if volume["type"] != "bind":
                continue
            bind_source = volume.get("source")
            target = volume.get("target")
            if not isinstance(bind_source, str) or not isinstance(target, str):
                raise ComposeInputError("Bind mounts need string source and target")
            sockets = {"docker.sock", "docker.sock.raw", "containerd.sock", "podman.sock"}
            if PurePosixPath(bind_source).name in sockets or PurePosixPath(target).name in sockets:
                report(
                    "FCB-COMPOSE-005",
                    f"volumes[{index}]",
                    "Container engine socket is exposed",
                    "CRITICAL",
                )
            elif _sensitive_host_path(bind_source):
                report(
                    "FCB-COMPOSE-006", f"volumes[{index}]", "Sensitive host filesystem is exposed"
                )

        capabilities = service.get("cap_add", [])
        if not isinstance(capabilities, list) or any(not isinstance(v, str) for v in capabilities):
            raise ComposeInputError("Rendered capabilities must be a list of strings")
        dangerous = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "DAC_READ_SEARCH", "NET_ADMIN"}
        if any(capability.upper().removeprefix("CAP_") in dangerous for capability in capabilities):
            report("FCB-COMPOSE-007", "cap_add", "High-risk Linux capability is added")

        options = service.get("security_opt", [])
        if not isinstance(options, list) or any(not isinstance(v, str) for v in options):
            raise ComposeInputError("Rendered security options must be a list of strings")
        if any(
            value.replace("=", ":")
            in {"seccomp:unconfined", "apparmor:unconfined", "label:disable"}
            for value in options
        ):
            report("FCB-COMPOSE-008", "security_opt", "Container isolation policy is disabled")

        devices = service.get("devices", [])
        if not isinstance(devices, list):
            raise ComposeInputError("Rendered devices must be a list")
        if devices:
            report("FCB-COMPOSE-009", "devices", "Host devices are exposed")

        ports = service.get("ports", [])
        if not isinstance(ports, list):
            raise ComposeInputError("Rendered ports must be a list")
        for index, port in enumerate(ports):
            if not isinstance(port, dict):
                raise ComposeInputError("Use rendered Compose long-form port objects")
            # A target-only port is not published on the host.
            if "published" not in port:
                continue
            host_ip = port.get("host_ip", "0.0.0.0")
            if not isinstance(host_ip, str):
                raise ComposeInputError("Rendered port host address must be text")
            try:
                address = ipaddress.ip_address(host_ip.strip("[]") or "0.0.0.0")
            except ValueError as exc:
                raise ComposeInputError("Rendered port host address is not an IP address") from exc
            if not address.is_loopback:
                report(
                    "FCB-COMPOSE-010",
                    f"ports[{index}]",
                    "Local-development port is published beyond loopback",
                )

    return findings


def _sensitive_host_path(value: str) -> bool:
    path = PurePosixPath(value)
    sensitive = ("/etc", "/proc", "/sys", "/dev", "/run", "/var/run", "/root")
    return str(path) == "/" or any(
        path == PurePosixPath(p) or PurePosixPath(p) in path.parents for p in sensitive
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "document", type=Path, help="Rendered JSON; do not commit or upload this input"
    )
    parser.add_argument("--source", required=True, help="Repository-relative Compose filename")
    args = parser.parse_args()
    try:
        findings = scan_compose(json.loads(args.document.read_text(encoding="utf-8")), args.source)
    except OSError, UnicodeError, ValueError, TypeError:
        print("Compose policy input is invalid; input values are withheld")
        return 2
    print(json.dumps({"source": args.source, "findings": findings}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
