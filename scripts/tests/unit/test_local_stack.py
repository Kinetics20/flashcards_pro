from __future__ import annotations

import copy
import json
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts.local import stack

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setattr(stack, "docker", lambda *args, **kwargs: "")
    return tmp_path, stack.bootstrap(tmp_path, "test-stack")


@pytest.mark.parametrize("name", ["", "ab", "../escape", "/root", "ALL", "a_b", "a" * 49, None])
def test_project_names_fail_closed(name):
    with pytest.raises(stack.StackError):
        stack.validate_project(name)


@pytest.mark.parametrize(
    "ports",
    [
        None,
        {},
        {**stack.DEFAULT_PORTS, "unknown": 1111},
        {**stack.DEFAULT_PORTS, "s3": True},
        {**stack.DEFAULT_PORTS, "s3": "8333"},
        {**stack.DEFAULT_PORTS, "s3": 1023},
        {**stack.DEFAULT_PORTS, "s3": 65536},
        {**stack.DEFAULT_PORTS, "s3": 18080},
    ],
)
def test_ports_reject_unsafe_values(ports):
    with pytest.raises(stack.StackError):
        stack.validate_ports(ports)


def test_ephemeral_ports_are_distinct_and_loopback(monkeypatch):
    listeners = []

    class Listener:
        def __init__(self):
            self.port = 20000 + len(listeners)
            self.closed = False
            listeners.append(self)

        def bind(self, address):
            assert address == ("127.0.0.1", 0)

        def getsockname(self):
            return "127.0.0.1", self.port

        def close(self):
            self.closed = True

    monkeypatch.setattr(stack.socket, "socket", Listener)
    assert set(stack.allocate_ports()) == set(stack.DEFAULT_PORTS)
    assert all(item.closed for item in listeners)


def test_ephemeral_socket_closed_on_failure(monkeypatch):
    closed = []

    def broken(address):
        raise OSError("occupied")

    monkeypatch.setattr(
        stack.socket,
        "socket",
        lambda: SimpleNamespace(bind=broken, close=lambda: closed.append(True)),
    )
    with pytest.raises(OSError):
        stack.allocate_ports()
    assert closed == [True]


def test_environment_does_not_inherit_compose_app_or_secrets(monkeypatch):
    for key in ("COMPOSE_FILE", "FCB_S3_SECRET_KEY", "APP_DATABASE_URL", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(key, "do-not-inherit")
    monkeypatch.setenv("DOCKER_CONTEXT", "fixture-context")
    result = stack.process_environment()
    assert result["DOCKER_CONTEXT"] == "fixture-context"
    assert "do-not-inherit" not in result.values()


@pytest.mark.parametrize("failure", [OSError("secret"), subprocess.TimeoutExpired("docker", 1)])
def test_docker_operational_errors_withhold_output(monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(stack.subprocess, "run", fail)
    with pytest.raises(stack.StackError, match="Docker operation failed") as error:
        stack.docker(["info"])
    assert "secret" not in str(error.value)


def test_docker_captures_output_and_reports_nonzero_safely(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="safe result", stderr="hidden")

    monkeypatch.setattr(stack.subprocess, "run", run)
    assert stack.docker(["info"], env={"PATH": "/bin"}, timeout=25) == "safe result"
    assert calls[0][0] == ["docker", "info"]
    assert calls[0][1]["capture_output"] and calls[0][1]["timeout"] == 25
    monkeypatch.setattr(
        stack.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="secret", stderr="secret"),
    )
    with pytest.raises(stack.StackError) as error:
        stack.docker(["info"])
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("kind", ["volume", "ps", "network", "absent"])
def test_existing_resources_check_all_kinds(monkeypatch, kind):
    monkeypatch.setattr(stack, "docker", lambda command: "id\n" if command[0] == kind else "")
    assert stack.existing_resources("test-stack") == (kind != "absent")


@pytest.mark.parametrize("kind", ["ps", "volume", "network"])
def test_resource_ownership_checks_exact_project_and_owner(monkeypatch, kind):
    labels = {"flashcards.local.owner": "token", "com.docker.compose.project": "test-stack"}
    calls = []

    def command(args):
        calls.append(args)
        if "--quiet" in args:
            return "resource-id\n" if args[0] == kind else ""
        return json.dumps(labels)

    monkeypatch.setattr(stack, "docker", command)
    stack.validate_resource_ownership("test-stack", "token")
    assert any("resource-id" in call and "--format" in call for call in calls)
    labels["flashcards.local.owner"] = "foreign"
    with pytest.raises(stack.StackError, match="another owner"):
        stack.validate_resource_ownership("test-stack", "token")
    labels["flashcards.local.owner"] = "token"
    labels["com.docker.compose.project"] = "foreign"
    with pytest.raises(stack.StackError):
        stack.validate_resource_ownership("test-stack", "token")


def test_invalid_resource_inventory_rejected(monkeypatch):
    monkeypatch.setattr(stack, "docker", lambda *a: "--all")
    with pytest.raises(stack.StackError, match="identifier"):
        stack.validate_resource_ownership("test-stack", "token")
    monkeypatch.setattr(stack, "docker", lambda a: "resource" if "--quiet" in a else "null")
    with pytest.raises(stack.StackError, match="another owner"):
        stack.validate_resource_ownership("test-stack", "token")


@pytest.mark.parametrize("component", [".local", ".local/test-stack"])
def test_state_directory_symlinks_rejected(tmp_path, component):
    outside = tmp_path / "outside"
    outside.mkdir()
    path = tmp_path / component
    path.parent.mkdir(exist_ok=True)
    path.symlink_to(outside, target_is_directory=True)
    with pytest.raises(stack.StackError, match="symlink"):
        stack.local_directory(tmp_path, "test-stack")


def test_local_containment_defense(tmp_path, monkeypatch):
    original = Path.resolve

    def escaped(path, *args, **kwargs):
        if path.name == "test-stack":
            return Path("/outside")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", escaped)
    with pytest.raises(stack.StackError, match="inside"):
        stack.local_directory(tmp_path, "test-stack")


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s.update(extra="bad"),
        lambda s: s.update(schema_version=True),
        lambda s: s.update(schema_version=2),
        lambda s: s.update(project="different"),
        lambda s: s.update(credentials=[]),
        lambda s: s["credentials"].pop("redis_password"),
        lambda s: s["credentials"].update(redis_password=None),
        lambda s: s["credentials"].update(redis_password="weak"),
        lambda s: s.update(owner_token="short"),
        lambda s: s.update(owner_token=123),
    ],
)
def test_corrupt_settings_fail_closed(local, change):
    _, settings = local
    candidate = copy.deepcopy(settings)
    change(candidate)
    with pytest.raises(stack.StackError):
        stack.validate_settings(candidate, "test-stack")
    with pytest.raises(stack.StackError):
        stack.validate_settings([], "test-stack")


def test_bootstrap_is_idempotent_private_and_never_prints(local, capsys):
    root, original = local
    assert stack.bootstrap(root, "test-stack", ephemeral_ports=True) == original
    directory = root / ".local/test-stack"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for filename in ("settings.json", "compose.env"):
        assert stat.S_IMODE((directory / filename).stat().st_mode) == 0o600
    assert not capsys.readouterr().out
    with pytest.raises(stack.StackError, match="immutable"):
        stack.bootstrap(root, "test-stack", ports={**stack.DEFAULT_PORTS, "s3": 19000})
    assert stack.bootstrap(root, "test-stack", ports=original["ports"]) == original


def test_bootstrap_ephemeral_and_explicit_ports(tmp_path, monkeypatch):
    monkeypatch.setattr(stack, "existing_resources", lambda *a: False)
    ports = {key: 20000 + i for i, key in enumerate(stack.DEFAULT_PORTS)}
    monkeypatch.setattr(stack, "allocate_ports", lambda: ports)
    assert stack.bootstrap(tmp_path, "ephemeral", ephemeral_ports=True)["ports"] == ports
    assert stack.bootstrap(tmp_path, "explicit", ports=ports)["ports"] == ports
    with pytest.raises(stack.StackError, match="not both"):
        stack.bootstrap(tmp_path, "bad-ports", ephemeral_ports=True, ports=ports)


def test_bootstrap_never_regenerates_lost_or_partial_state(tmp_path, monkeypatch):
    monkeypatch.setattr(stack, "existing_resources", lambda *a: True)
    with pytest.raises(stack.StackError, match="resources exist"):
        stack.bootstrap(tmp_path, "test-stack")
    monkeypatch.setattr(stack, "existing_resources", lambda *a: False)
    partial = tmp_path / ".local/test-stack"
    partial.mkdir(parents=True)
    (partial / "compose.env").write_text("existing")
    with pytest.raises(stack.StackError, match="Partial"):
        stack.bootstrap(tmp_path, "test-stack")


def test_existing_credentials_do_not_authorize_foreign_resources(local, monkeypatch):
    root, _ = local

    def foreign(*a):
        raise stack.StackError("another owner")

    monkeypatch.setattr(stack, "validate_resource_ownership", foreign)
    with pytest.raises(stack.StackError, match="another owner"):
        stack.bootstrap(root, "test-stack")


def test_load_settings_checks_permissions_json_duplicates_and_symlinks(local):
    root, _ = local
    path = root / ".local/test-stack/settings.json"
    path.chmod(0o644)
    with pytest.raises(stack.StackError, match="0600"):
        stack.load_settings(root, "test-stack")
    path.chmod(0o600)
    for document in ('{"project":"one","project":"two"}', "{invalid", "\ud800"):
        path.write_text(document, errors="surrogatepass")
        with pytest.raises(stack.StackError, match="valid local"):
            stack.load_settings(root, "test-stack")
    path.unlink()
    with pytest.raises(stack.StackError, match="missing"):
        stack.load_settings(root, "test-stack")
    other = path.parent / "other"
    other.write_text("{}")
    path.symlink_to(other)
    with pytest.raises(stack.StackError, match="missing"):
        stack.load_settings(root, "test-stack")


def test_config_rendering_never_reads_local_environment(local, monkeypatch):
    root, settings = local
    (root / ".env").write_text("FCB_S3_SECRET_KEY=ambient-secret")
    monkeypatch.setenv("FCB_S3_SECRET_KEY", "ambient-secret")
    safe = stack.config_environment(root, "test-stack", "full")
    assert safe["FCB_S3_SECRET_KEY"] == ""
    assert safe["FCB_LOCAL_OWNER"] == "config-only"
    assert safe["FCB_LOCAL_IMAGE_TAG"] == "test-stack"
    assert safe["FCB_TELEMETRY_ENABLED"] == "true"
    actual = stack.config_environment(root, "test-stack", "core", settings)
    assert actual["FCB_S3_SECRET_KEY"] == settings["credentials"]["s3_secret_key"]
    assert actual["FCB_TELEMETRY_ENABLED"] == "false"
    with pytest.raises(stack.StackError, match="profile"):
        stack.config_environment(root, "test-stack", "invalid")


def test_private_write_refuses_symlinks_and_cleans_failed_temporary(local, monkeypatch):
    root, _ = local
    target = root / ".local/test-stack/symlink"
    target.symlink_to(root / "outside")
    with pytest.raises(stack.StackError, match="symlink"):
        stack._private_write(target, "secret")

    def fail(*args):
        raise OSError("failed atomic replace")

    monkeypatch.setattr(stack.os, "replace", fail)
    with pytest.raises(OSError):
        stack._private_write(target.parent / "new-file", "secret")
    assert not list(target.parent.glob(".bootstrap-*"))


def test_compose_args_control_profiles_and_environment(tmp_path):
    args = stack.compose_args(tmp_path, "test-stack", "full")
    assert args[:5] == ["compose", "--project-name", "test-stack", "--env-file", "/dev/null"]
    assert args[-6:] == ["--profile", "core", "--profile", "observability", "--profile", "tools"]
    with pytest.raises(stack.StackError):
        stack.compose_args(tmp_path, "test-stack", "invalid")


@pytest.mark.parametrize("array", [True, False])
def test_status_never_exposes_command_or_unknown_fields(array):
    row = {
        "Service": "redis",
        "State": "running",
        "Health": "healthy",
        "ExitCode": 0,
        "Command": "--password=secret",
        "Labels": "secret",
        "Ports": "secret",
    }
    result = stack.safe_status(json.dumps([row] if array else row))
    assert result == [{"Service": "redis", "State": "running", "Health": "healthy", "ExitCode": 0}]
    assert "secret" not in json.dumps(result)
    with pytest.raises(stack.StackError):
        stack.safe_status("[1]")


@pytest.mark.parametrize("action", ["up", "down", "config", "probe", "status"])
def test_cli_scoped_commands_never_delete_volumes(local, monkeypatch, capsys, action):
    root, settings = local
    calls = []

    def command(args, **kwargs):
        calls.append((args, kwargs))
        return (
            '{"Service":"content-service","State":"running","Command":"secret"}'
            if "ps" in args and "--format" in args
            else ""
        )

    monkeypatch.setattr(stack, "docker", command)
    assert (
        stack.main(["--root", str(root), "--project", "test-stack", action, "--profile", "full"])
        == 0
    )
    actual = next(call for call in calls if call[0][0] == "compose")
    assert "--project-name" in actual[0] and "test-stack" in actual[0]
    assert "--volumes" not in actual[0] and "prune" not in actual[0]
    expected = "" if action == "config" else settings["credentials"]["s3_secret_key"]
    assert actual[1]["env"]["FCB_S3_SECRET_KEY"] == expected
    if action == "probe":
        assert "--no-deps" in actual[0]
    assert "secret" not in capsys.readouterr().out


def test_cli_bootstrap_custom_ports_and_failure_messages(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(stack, "docker", lambda *a, **k: "")
    prefix = ["--root", str(tmp_path), "--project", "test-stack", "bootstrap"]
    assert stack.main([*prefix, "--port", "gateway=19001"]) == 0
    assert stack.load_settings(tmp_path, "test-stack")["ports"]["gateway"] == 19001
    for bad in ("unknown=19002", "gateway=abc", "missing-delimiter", "gateway=1"):
        assert stack.main([*prefix, "--port", bad]) == 1
    assert "abc" not in capsys.readouterr().err
    assert stack.main(["--root", str(tmp_path), "--project", "not-existing", "down"]) == 1


def test_topology_pins_images_isolates_databases_and_exposes_only_loopback():
    document = yaml.safe_load((ROOT / "compose.yaml").read_text())
    services = document["services"]
    assert set(services) == {
        "volume-init",
        "postgres-content",
        "postgres-identity",
        "content-service",
        "content-migrate",
        "gateway",
        "keycloak",
        "nats",
        "redis",
        "s3",
        "otel-collector",
        "adminer",
        "test-probe",
    }
    for name, service in services.items():
        assert service["labels"]["flashcards.local.owner"]
        assert "@sha256:" in service["image"] or "build" in service
        assert all(port.startswith("127.0.0.1:") for port in service.get("ports", []))
        assert service["cap_drop"] == ["ALL"]
        assert service["mem_limit"] and service["cpus"]
        if name not in {"volume-init", "content-migrate", "test-probe"}:
            assert service["healthcheck"]["test"][0] in {"CMD", "CMD-SHELL"}
    assert set(services["content-service"]["networks"]).isdisjoint(
        services["postgres-identity"]["networks"]
    )
    assert set(services["keycloak"]["networks"]).isdisjoint(
        services["postgres-content"]["networks"]
    )
    assert document["networks"]["content-db"]["internal"]
    assert document["networks"]["identity-db"]["internal"]
    assert (
        services["content-service"]["depends_on"]["content-migrate"]["condition"]
        == "service_completed_successfully"
    )
    for section in ("networks", "volumes"):
        assert all(
            value["labels"]["flashcards.local.owner"] for value in document[section].values()
        )


def test_development_identity_is_not_a_claim_of_api_authorization():
    realm = json.loads((ROOT / "infrastructure/local/keycloak/flashcards-realm.json").read_text())
    client = realm["clients"][0]
    assert client["clientId"] == "flashcards-dev" and not client["publicClient"]
    assert client["serviceAccountsEnabled"] and not client["directAccessGrantsEnabled"]
    assert client["secret"] == "${FCB_OIDC_CLIENT_SECRET}"
    assert client["protocolMappers"][0]["config"]["included.client.audience"] == "flashcards-dev"


def test_database_initialization_uses_sql_not_executable_host_bind():
    services = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
    for name in ("postgres-content", "postgres-identity"):
        initialization = services[name]["volumes"][1]
        assert initialization["source"].endswith("10-application-role.sql")
        assert initialization["target"].endswith("10-application-role.sql")
        assert initialization["read_only"]
    sql = (ROOT / "infrastructure/local/postgres/10-application-role.sql").read_text()
    assert "\\getenv app_password FCB_DB_APP_PASSWORD" in sql
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION" in sql


def test_nonroot_data_volumes_do_not_copy_image_owned_seed_directories():
    services = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
    for name in ("volume-init", "nats", "redis", "s3"):
        for volume in services[name]["volumes"]:
            if volume["type"] == "volume":
                assert volume["volume"]["nocopy"]
    initializer = services["volume-init"]
    assert "chown 10001:10001 /nats /redis /s3" in initializer["command"][2]
    assert "-R" not in initializer["command"][2]
    assert initializer["network_mode"] == "none"
    assert initializer["cap_add"] == ["CHOWN", "FOWNER"]
