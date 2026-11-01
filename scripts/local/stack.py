"""Bootstrap and run the local stack without printing credentials or deleting data."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_PORTS = {
    "gateway": 18080,
    "content": 18002,
    "s3": 18333,
    "nats": 14222,
    "redis": 16379,
    "otlp_grpc": 14317,
    "otlp_http": 14318,
    "adminer": 18081,
}
CREDENTIAL_KEYS = frozenset(
    {
        "content_db_password",
        "identity_db_password",
        "content_db_admin_password",
        "identity_db_admin_password",
        "nats_password",
        "redis_password",
        "s3_access_key",
        "s3_secret_key",
        "keycloak_admin_password",
        "oidc_client_secret",
    }
)
PROFILES = {
    "core": ("core",),
    "observability": ("core", "observability"),
    "tools": ("core", "tools"),
    "full": ("core", "observability", "tools"),
    "test": ("core", "test"),
}
PROJECT = re.compile(r"[a-z][a-z0-9-]{2,47}")
SECRET = re.compile(r"[a-f0-9]{64}")


class StackError(ValueError):
    """A local-stack operation cannot be performed safely."""


def validate_project(project: str) -> str:
    if not isinstance(project, str) or not PROJECT.fullmatch(project):
        raise StackError("Project must be 3-48 lowercase letters, digits or hyphens")
    return project


def local_directory(root: Path, project: str) -> Path:
    root = Path(root).resolve()
    validate_project(project)
    directory = root / ".local" / project
    if (root / ".local").is_symlink() or directory.is_symlink():
        raise StackError("Local state directory may not be a symlink")
    if not directory.resolve().is_relative_to(root):
        raise StackError("Local state must remain inside this checkout")
    return directory


def validate_ports(ports: dict) -> dict[str, int]:
    if not isinstance(ports, dict) or set(ports) != set(DEFAULT_PORTS):
        raise StackError("Every supported local port must be declared exactly once")
    if any(type(value) is not int or not 1024 <= value <= 65535 for value in ports.values()):
        raise StackError("Ports must be integers from 1024 through 65535")
    if len(set(ports.values())) != len(ports):
        raise StackError("Local ports must be distinct")
    return dict(ports)


def allocate_ports() -> dict[str, int]:
    """Reserve distinct loopback ports briefly; Docker remains the final collision check."""
    listeners = []
    try:
        result = {}
        for name in DEFAULT_PORTS:
            listener = socket.socket()
            listeners.append(listener)
            listener.bind(("127.0.0.1", 0))
            result[name] = listener.getsockname()[1]
        return validate_ports(result)
    finally:
        for listener in listeners:
            listener.close()


def process_environment() -> dict[str, str]:
    """Keep Docker connectivity, but ignore ambient Compose/application configuration."""
    allowed = {
        "PATH",
        "HOME",
        "USER",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "LANG",
        "LC_ALL",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "SSH_AUTH_SOCK",
        "XDG_RUNTIME_DIR",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}


def docker(arguments: list[str], *, env: dict | None = None, timeout: int = 60) -> str:
    """Capture all output: exceptions and CLI status never include expanded secrets."""
    try:
        result = subprocess.run(
            ["docker", *arguments],
            env=env or process_environment(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise StackError(
            "Docker operation failed; check the daemon and scoped stack status"
        ) from error
    if result.returncode:
        raise StackError("Docker operation failed; check the daemon and scoped stack status")
    return result.stdout


def existing_resources(project: str) -> bool:
    validate_project(project)
    filters = ["--filter", f"label=com.docker.compose.project={project}"]
    return bool(
        docker(["volume", "ls", "--quiet", *filters]).strip()
        or docker(["ps", "--all", "--quiet", *filters]).strip()
        or docker(["network", "ls", "--quiet", *filters]).strip()
    )


def validate_resource_ownership(project: str, owner_token: str) -> None:
    """Refuse mutations if any same-project Docker resource belongs to another owner."""
    validate_project(project)
    filters = ["--filter", f"label=com.docker.compose.project={project}"]
    inventory = (
        (["ps", "--all", "--quiet", *filters], ["inspect"], ".Config.Labels"),
        (["volume", "ls", "--quiet", *filters], ["volume", "inspect"], ".Labels"),
        (["network", "ls", "--quiet", *filters], ["network", "inspect"], ".Labels"),
    )
    for listing, inspection, label_path in inventory:
        for identifier in docker(listing).splitlines():
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", identifier):
                raise StackError("Invalid Docker resource identifier")
            labels = json.loads(
                docker([*inspection, identifier, "--format", "{{json " + label_path + "}} "])
            )
            if (
                not isinstance(labels, dict)
                or labels.get("flashcards.local.owner") != owner_token
                or labels.get("com.docker.compose.project") != project
            ):
                raise StackError(
                    "Existing project resources belong to another owner; refusing mutation"
                )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StackError("Duplicate local settings key")
        result[key] = value
    return result


def validate_settings(settings: dict, project: str) -> dict:
    if not isinstance(settings, dict) or set(settings) != {
        "schema_version",
        "project",
        "ports",
        "credentials",
        "owner_token",
    }:
        raise StackError("Invalid local settings structure")
    if type(settings["schema_version"]) is not int or settings["schema_version"] != 1:
        raise StackError("Unsupported local settings version")
    if settings["project"] != validate_project(project):
        raise StackError("Local settings belong to a different project")
    validate_ports(settings["ports"])
    credentials = settings["credentials"]
    if not isinstance(credentials, dict) or set(credentials) != CREDENTIAL_KEYS:
        raise StackError("Invalid local credential inventory")
    if any(not isinstance(v, str) or not SECRET.fullmatch(v) for v in credentials.values()):
        raise StackError("Invalid local credential format; values are withheld")
    if not isinstance(settings["owner_token"], str) or not SECRET.fullmatch(
        settings["owner_token"]
    ):
        raise StackError("Invalid local resource ownership token")
    return settings


def load_settings(root: Path, project: str) -> dict:
    directory = local_directory(root, project)
    path = directory / "settings.json"
    if not path.is_file() or path.is_symlink():
        raise StackError("Local settings are missing; run bootstrap first")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise StackError("Local settings must have mode 0600; do not expose credentials")
    try:
        settings = json.loads(path.read_text(), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError) as error:
        raise StackError("Cannot read valid local settings; values are withheld") from error
    return validate_settings(settings, project)


def config_environment(
    root: Path,
    project: str,
    profile: str,
    settings: dict | None = None,
) -> dict[str, str]:
    """Return controlled substitution values. None means non-secret config-only rendering."""
    validate_project(project)
    local_directory(root, project)
    if profile not in PROFILES:
        raise StackError("Unknown local profile")
    if settings is not None:
        validate_settings(settings, project)
    ports = settings["ports"] if settings is not None else DEFAULT_PORTS
    credentials = (
        settings["credentials"] if settings is not None else dict.fromkeys(CREDENTIAL_KEYS, "")
    )
    return {
        **process_environment(),
        **{f"FCB_{key.upper()}_PORT": str(value) for key, value in ports.items()},
        **{f"FCB_{key.upper()}": value for key, value in credentials.items()},
        "FCB_LOCAL_IMAGE_TAG": project,
        "FCB_LOCAL_OWNER": settings["owner_token"] if settings is not None else "config-only",
        "FCB_TELEMETRY_ENABLED": "true" if "observability" in PROFILES[profile] else "false",
        "COMPOSE_DISABLE_ENV_FILE": "1",
    }


def _private_write(path: Path, content: str) -> None:
    if path.is_symlink():
        raise StackError("Local state files may not be symlinks")
    descriptor, temporary = tempfile.mkstemp(prefix=".bootstrap-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def bootstrap(
    root: Path,
    project: str,
    *,
    ephemeral_ports: bool = False,
    ports: dict | None = None,
) -> dict:
    """Create credentials once. Never silently rotate credentials for persistent volumes."""
    directory = local_directory(root, project)
    if ephemeral_ports and ports is not None:
        raise StackError("Choose explicit ports or ephemeral ports, not both")
    if (directory / "settings.json").exists():
        settings = load_settings(root, project)
        validate_resource_ownership(project, settings["owner_token"])
        if ports is not None and validate_ports(ports) != settings["ports"]:
            raise StackError("Existing project ports are immutable; use a new project name")
    else:
        if existing_resources(project):
            raise StackError(
                "Project resources exist without credentials; restore the original local state"
            )
        if directory.exists() and any(directory.iterdir()):
            raise StackError("Partial local state exists; inspect it before bootstrapping")
        selected_ports = allocate_ports() if ephemeral_ports else ports or DEFAULT_PORTS
        settings = {
            "schema_version": 1,
            "project": project,
            "ports": validate_ports(selected_ports),
            "credentials": {name: secrets.token_hex(32) for name in sorted(CREDENTIAL_KEYS)},
            "owner_token": secrets.token_hex(32),
        }
        directory.parent.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
        _private_write(directory / "settings.json", json.dumps(settings, indent=2) + "\n")
    values = config_environment(root, project, "core", settings)
    _private_write(
        directory / "compose.env",
        "# Generated local-only credentials. Never commit or upload this file.\n"
        + "\n".join(
            f"{key}={value}" for key, value in sorted(values.items()) if key.startswith("FCB_")
        )
        + "\n",
    )
    return settings


def compose_args(root: Path, project: str, profile: str) -> list[str]:
    validate_project(project)
    if profile not in PROFILES:
        raise StackError("Unknown local profile")
    result = [
        "compose",
        "--project-name",
        project,
        "--env-file",
        "/dev/null",
        "--file",
        str(Path(root).resolve() / "compose.yaml"),
    ]
    for selected in PROFILES[profile]:
        result.extend(["--profile", selected])
    return result


def safe_status(raw: str) -> list[dict]:
    """Do not return Compose's Command, environment or arbitrary unreviewed fields."""
    rows = (
        json.loads(raw)
        if raw.strip().startswith("[")
        else [json.loads(line) for line in raw.splitlines() if line.strip()]
    )
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise StackError("Invalid Compose status response")
    return [
        {key: row[key] for key in ("Service", "State", "Health", "ExitCode") if key in row}
        for row in rows
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--project", default="flashcards")
    actions = parser.add_subparsers(dest="action", required=True)
    initialize = actions.add_parser("bootstrap")
    initialize.add_argument("--ephemeral-ports", action="store_true")
    initialize.add_argument("--port", action="append", default=[], metavar="NAME=PORT")
    for name in ("up", "down", "status", "config", "probe"):
        action = actions.add_parser(name)
        action.add_argument("--profile", choices=PROFILES, default="core")
    args = parser.parse_args(argv)
    try:
        if args.action == "bootstrap":
            ports = dict(DEFAULT_PORTS)
            for entry in args.port:
                name, value = entry.split("=", 1)
                if name not in ports:
                    raise StackError("Unknown local port name")
                ports[name] = int(value)
            bootstrap(
                args.root,
                args.project,
                ephemeral_ports=args.ephemeral_ports,
                ports=ports if args.port else None,
            )
            print("Local credentials prepared; existing credentials were preserved")
            return 0
        settings = (
            None
            if args.action == "config"
            else bootstrap(args.root, args.project)
            if args.action == "up"
            else load_settings(args.root, args.project)
        )
        environment = config_environment(args.root, args.project, args.profile, settings)
        if settings is not None:
            validate_resource_ownership(args.project, settings["owner_token"])
        command = compose_args(args.root, args.project, args.profile)
        if args.action == "up":
            command += ["up", "--detach", "--build", "--wait", "--wait-timeout", "240"]
        elif args.action == "down":
            command += ["--profile", "*", "down", "--timeout", "15"]
        elif args.action == "config":
            command += ["--profile", "*", "config", "--quiet"]
        elif args.action == "probe":
            command += ["--profile", "test", "run", "--rm", "--no-deps", "test-probe"]
        else:
            command += ["ps", "--all", "--format", "json"]
        result = docker(command, env=environment, timeout=900)
        if args.action == "status":
            print(json.dumps(safe_status(result), indent=2))
        else:
            print(f"Local stack {args.action} succeeded; persistent volumes were preserved")
        return 0
    except OSError, ValueError, subprocess.SubprocessError:
        print(
            "Local stack command failed. Check configuration, Docker and project-scoped status; "
            "credentials are withheld.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
