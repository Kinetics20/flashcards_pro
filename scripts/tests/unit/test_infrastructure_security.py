"""Fail-closed all-profile inventory, runtime identities and evidence tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.security import compose_inventory as compose
from scripts.security import infrastructure as infra
from scripts.security.common import read_json, write_json
from scripts.security.run_scans import ScanError
from scripts.tests.unit.test_security_gate import finding, report

ROOT = Path(__file__).resolve().parents[3]
COMMIT = "a" * 40
IMAGE_ID = "sha256:" + "b" * 64
PULLED = "example/service:1.0@sha256:" + "c" * 64
BUILT = "flashcards-local-wrapper:fcb-test"


@pytest.mark.parametrize(
    "package,version,declaration,passes",
    [
        ("python-dateutil", "2.9.0.post0", "Apache Software License; BSD License", True),
        ("python-dateutil", "2.9.1", "Apache Software License; BSD License", False),
        ("other-package", "2.9.0.post0", "Apache Software License; BSD License", False),
        ("python-dateutil", "2.9.0.post0", "BSD License", False),
    ],
)
def test_dateutil_license_normalization_is_exact(package, version, declaration, passes):
    policy = read_json(ROOT / "security/policy.json")
    findings = [finding("UNKNOWN", package=package, version=version, license=declaration)]
    errors = infra.evaluate_report(
        report("licenses", findings), policy, {"schema_version": 1, "exceptions": []}
    )
    assert (not errors) is passes


def test_local_stack_job_is_required_and_does_not_contaminate_app_manifest():
    import yaml

    workflow = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
    jobs = workflow["jobs"]
    assert "local-stack-integration" in jobs["ci-success"]["needs"]
    steps = jobs["local-stack-integration"]["steps"]
    integration = next(step for step in steps if "test_local_stack.py" in step.get("run", ""))
    scanner = next(
        step for step in steps if "scripts.security.infrastructure" in step.get("run", "")
    )
    assert integration["env"]["FCB_RUN_LOCAL_STACK"] == "1"
    assert "--no-sync" in integration["run"]
    assert steps.index(integration) < steps.index(scanner)
    assert scanner["if"] == "${{ !cancelled() }}"
    upload = next(step for step in steps if "actions/upload-artifact@" in step.get("uses", ""))
    assert not upload["with"]["name"].startswith("evidence-")
    assert ".local" not in upload["with"]["path"]
    assert "reports/local-stack/\n" not in upload["with"]["path"]
    assert "reports/local-stack/images.json" in upload["with"]["path"]
    assert "reports/local-stack/junit.xml" in upload["with"]["path"]
    assert "!**/failure.json" in upload["with"]["path"]
    for step in steps:
        assert step.get("continue-on-error", "false") == "false"


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    targets = [
        {"id": "local", "path": "compose.yaml", "kind": "local"},
        {"id": "contracts", "path": "compose.contracts.yaml", "kind": "contracts"},
        {"id": "template", "path": "templates/example/compose.yaml", "kind": "template"},
    ]
    for target in targets:
        path = tmp_path / target["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("services:\n  api:\n    image: example:1\n")
    write_json(tmp_path / compose.INVENTORY, {"schema_version": 1, "targets": targets})
    state = {
        "tracked": [target["path"] for target in targets],
        "document": {"services": {"api": {}}},
    }
    calls = []

    def run(command, root, **kwargs):
        calls.append((command, kwargs))
        if command[0] == "git":
            return SimpleNamespace(stdout="\0".join(state["tracked"]) + "\0")
        return SimpleNamespace(stdout=json.dumps(state["document"]))

    monkeypatch.setattr(compose, "run", run)
    return tmp_path, targets, state, calls


def test_inventory_covers_explicit_named_contracts_and_templates(inventory):
    root, targets, _, _ = inventory
    assert compose.load_targets(root) == targets
    assert compose.load_targets(root, [target["path"] for target in targets]) == targets


@pytest.mark.parametrize(
    "change",
    [
        "schema",
        "version",
        "empty",
        "entry",
        "id",
        "kind",
        "path",
        "duplicate",
        "missing",
        "unlisted",
        "no-local",
        "no-contracts",
        "no-template",
    ],
)
def test_inventory_rejects_incomplete_or_ambiguous_input(inventory, change):
    root, targets, state, _ = inventory
    document = read_json(root / compose.INVENTORY)
    if change == "schema":
        document = []
    elif change == "version":
        document["schema_version"] = True
    elif change == "empty":
        document["targets"] = []
    elif change == "entry":
        document["targets"][0] = "bad"
    elif change in {"id", "kind", "path"}:
        document["targets"][0][change] = {"id": "../bad", "kind": "overlay", "path": 1}[change]
    elif change == "duplicate":
        document["targets"].append(document["targets"][0])
    elif change == "missing":
        (root / targets[0]["path"]).unlink()
    elif change == "unlisted":
        state["tracked"].append("compose.hidden.yaml")
    else:
        kind = change.removeprefix("no-")
        document["targets"] = [item for item in targets if item["kind"] != kind]
        state["tracked"] = [item["path"] for item in document["targets"]]
    write_json(root / compose.INVENTORY, document)
    with pytest.raises(ScanError):
        compose.load_targets(root)


def test_render_all_profiles_without_environment_or_service_env_files(inventory, monkeypatch):
    root, targets, _, calls = inventory
    monkeypatch.setenv("COMPOSE_FILE", "/private/overlay.yaml")
    monkeypatch.setenv("PORT", "12345")
    monkeypatch.setenv("PASSWORD", "never-publish-this")
    monkeypatch.setenv("DOCKER_HOST", "unix:///local/docker.sock")
    result = compose.render(root, targets[1])
    assert result == {"services": {"api": {}}}
    command, options = calls[-1]
    assert command[command.index("--profile") + 1] == "*"
    assert command[command.index("--env-file") + 1] == "/dev/null"
    assert "--no-env-resolution" in command
    assert set(options["environment"]) <= {
        "PATH",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "COMPOSE_DISABLE_ENV_FILE",
        "NO_COLOR",
    }
    assert options["environment"]["DOCKER_HOST"] == "unix:///local/docker.sock"


def test_local_render_uses_config_only_settings(inventory, monkeypatch):
    from scripts.local import stack

    root, targets, _, calls = inventory
    received = []

    def config(root, project, profile, settings):
        received.append((project, profile, settings))
        return {"FCB_LOCAL_IMAGE_TAG": "default"}

    monkeypatch.setattr(stack, "config_environment", config)
    compose.render(root, targets[0], "fcb-test")
    assert received == [("fcb-security", "full", None)]
    assert calls[-1][1]["environment"]["FCB_LOCAL_IMAGE_TAG"] == "fcb-test"


@pytest.mark.parametrize("tag", ["../bad", "x" * 64, "has space", 1])
def test_invalid_local_image_tag(inventory, tag):
    root, targets, _, _ = inventory
    with pytest.raises(ScanError):
        compose.render(root, targets[0], tag)


@pytest.mark.parametrize(
    "source",
    [
        "[]",
        "include: private.yaml",
        "services: {}",
        "services: {api: {extends: private.yaml}}",
        "services: {api: bad}",
    ],
)
def test_render_rejects_implicit_secondary_config(inventory, source):
    root, targets, _, _ = inventory
    (root / targets[1]["path"]).write_text(source)
    with pytest.raises(ScanError):
        compose.render(root, targets[1])


def test_render_rejects_omitted_profile_service_and_invalid_json(inventory, monkeypatch):
    root, targets, state, _ = inventory
    state["document"] = {"services": {}}
    with pytest.raises(ScanError, match="omitted"):
        compose.render(root, targets[1])
    monkeypatch.setattr(compose, "run", lambda *a, **kw: SimpleNamespace(stdout="PRIVATE"))
    with pytest.raises(ScanError, match="valid JSON") as error:
        compose.render(root, targets[1])
    assert "PRIVATE" not in str(error.value)


def test_documents_uses_every_inventory_entry(inventory, monkeypatch):
    root, targets, _, _ = inventory
    monkeypatch.setattr(compose, "render", lambda root, target, tag: {"id": target["id"]})
    assert len(compose.documents(root)) == len(targets)


def test_invalid_yaml_never_discloses_source_values(inventory):
    root, targets, _, _ = inventory
    (root / targets[1]["path"]).write_text('services: {api: "PRIVATE"')
    with pytest.raises(ScanError) as error:
        compose.render(root, targets[1])
    assert "PRIVATE" not in str(error.value)


def test_multicomponent_overlay_cannot_be_silently_omitted(inventory):
    root, _, state, _ = inventory
    state["tracked"].append("compose.dev.override.yaml")
    with pytest.raises(ScanError, match="differ"):
        compose.load_targets(root)


@pytest.fixture
def image_context(inventory, monkeypatch):
    root, targets, _, _ = inventory
    build = root / "infrastructure/wrapper"
    build.mkdir(parents=True)
    (build / "Dockerfile").write_text("FROM scratch\n")
    docs = [
        (
            targets[0],
            {
                "services": {
                    "database": {"image": PULLED},
                    "wrapper": {"image": BUILT, "build": {"context": str(build)}},
                }
            },
        ),
        (targets[1], {"services": {"same-image": {"image": PULLED}}}),
        (targets[2], {"services": {"api": {"build": {"context": "outside-this-gate"}}}}),
    ]
    monkeypatch.setattr(infra, "documents", lambda root, tag: docs)
    monkeypatch.setattr(infra, "git_commit", lambda root: COMMIT)
    monkeypatch.setattr(infra, "run", lambda *a, **kw: SimpleNamespace(stdout=IMAGE_ID))
    for name in ("policy.json", "exceptions.json", "tools.lock.json"):
        (root / "security" / name).write_bytes((ROOT / "security" / name).read_bytes())
    identity = root / "identities.json"
    write_json(
        identity,
        {
            "schema_version": 1,
            "commit": COMMIT,
            "local_image_tag": "fcb-test",
            "images": [{"reference": name, "image_id": IMAGE_ID} for name in (PULLED, BUILT)],
        },
    )
    return root, identity, docs


@pytest.mark.parametrize(
    "problem",
    [
        "schema",
        "version",
        "commit",
        "tag",
        "empty",
        "row",
        "extra",
        "duplicate",
        "reference",
        "image-id",
    ],
)
def test_identity_manifest_is_strict(image_context, problem):
    root, path, _ = image_context
    document = read_json(path)
    if problem == "schema":
        document = []
    elif problem == "version":
        document["schema_version"] = True
    elif problem == "commit":
        document["commit"] = "b" * 40
    elif problem == "tag":
        document["local_image_tag"] = "../bad"
    elif problem == "empty":
        document["images"] = []
    elif problem == "row":
        document["images"][0] = None
    elif problem == "extra":
        document["images"][0]["secret"] = "private"
    elif problem == "duplicate":
        document["images"].append(document["images"][0])
    elif problem == "reference":
        document["images"][0]["reference"] = ""
    else:
        document["images"][0]["image_id"] = "mutable:tag"
    write_json(path, document)
    with pytest.raises(ScanError):
        infra.identities(path, COMMIT)


def test_expected_images_cover_profiles_deduplicate_and_hash_inputs(image_context):
    root, _, _ = image_context
    images, inputs = infra.expected_images(root, "fcb-test")
    assert set(images) == {PULLED, BUILT}
    assert len(images[PULLED]) == 2
    assert "infrastructure/wrapper/Dockerfile" in inputs


@pytest.mark.parametrize(
    "problem", ["no-image", "mutable", "tag", "build", "context", "dockerfile", "empty"]
)
def test_unsafe_or_unpinned_image_inputs_fail(image_context, problem):
    root, _, docs = image_context
    services = docs[0][1]["services"]
    if problem == "no-image":
        services["database"].pop("image")
    elif problem == "mutable":
        services["database"]["image"] = "example:latest"
    elif problem == "tag":
        services["wrapper"]["image"] = "flashcards-local-wrapper:other"
    elif problem == "build":
        services["wrapper"]["build"] = "."
    elif problem == "context":
        services["wrapper"]["build"]["context"] = str(root.parent)
    elif problem == "dockerfile":
        services["wrapper"]["build"]["dockerfile"] = "../../../Dockerfile"
    else:
        docs[:] = docs[2:]
    with pytest.raises(ScanError):
        infra.expected_images(root, "fcb-test")


def fake_image(self, target, reference):
    assert reference == IMAGE_ID
    raw = self.directory(target) / "image.raw.json"
    write_json(raw, {"ArtifactID": reference})
    self.report(target, "image", ("trivy", "0.75.0"), lambda: ([], [raw]))


def test_scan_uses_tested_id_and_keeps_complete_evidence(image_context, monkeypatch):
    root, identity, _ = image_context
    monkeypatch.setattr(infra.Runner, "image", fake_image)
    output = root / "reports"
    assert infra.scan(root, identity, output) == []
    assert read_json(output / "result.json")["image_count"] == 2
    assert len(list(output.glob("*/image.json"))) == 2
    assert (
        infra.main(["--root", str(root), "--identities", str(identity), "--output", str(output)])
        == 0
    )


@pytest.mark.parametrize(
    "problem",
    ["missing", "policy", "changed-id", "missing-report", "extra-report", "digest", "finding"],
)
def test_scan_fails_closed(image_context, monkeypatch, problem):
    root, identity, _ = image_context
    output = root / "reports"
    monkeypatch.setattr(infra.Runner, "image", fake_image)
    if problem == "missing":
        document = read_json(identity)
        document["images"].pop()
        write_json(identity, document)
    elif problem == "policy":
        write_json(root / "security/policy.json", {})
    elif problem == "changed-id":
        monkeypatch.setattr(
            infra, "run", lambda *a, **kw: SimpleNamespace(stdout="sha256:" + "c" * 64)
        )
    elif problem == "missing-report":
        monkeypatch.setattr(infra.Runner, "image", lambda *a: None)
    elif problem == "extra-report":
        write_json(output / "unexpected/image.json", {})
    elif problem == "digest":

        def tamper(self, target, reference):
            fake_image(self, target, reference)
            (self.directory(target) / "image.raw.json").write_text("tampered")

        monkeypatch.setattr(infra.Runner, "image", tamper)
    else:
        monkeypatch.setattr(infra, "evaluate_report", lambda *a: ["blocking finding"])
        assert (
            infra.main(
                ["--root", str(root), "--identities", str(identity), "--output", str(output)]
            )
            == 1
        )
        return
    assert (
        infra.main(["--root", str(root), "--identities", str(identity), "--output", str(output)])
        == 2
    )
    assert read_json(output / "result.json")["status"] == "error"


def test_operational_error_does_not_publish_private_exception(image_context, monkeypatch, capsys):
    root, identity, _ = image_context
    monkeypatch.setattr(
        infra, "scan", lambda *a, **kw: (_ for _ in ()).throw(ValueError("PRIVATE"))
    )
    output = root / "reports"
    assert (
        infra.main(["--root", str(root), "--identities", str(identity), "--output", str(output)])
        == 2
    )
    assert "PRIVATE" not in capsys.readouterr().out
    assert "PRIVATE" not in (output / "result.json").read_text()
