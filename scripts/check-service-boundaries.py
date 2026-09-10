#!/usr/bin/env python3
"""Reject dependencies on another service's internal implementation.

The checker intentionally uses only the Python standard library so it can run
before project dependencies are installed. It is designed to run both locally
and in GitHub Actions.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tomllib

SERVICE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
DEPENDENCY_NAME_PATTERN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
NORMALIZED_NAME_PATTERN = re.compile(r"[-_.]+")
SOURCE_DIRECTORIES = ("src", "tests")
FORBIDDEN_IMPORT_ROOTS = {"services", "templates"}
SYS_PATH_MUTATIONS = {
    "sys.path.append",
    "sys.path.extend",
    "sys.path.insert",
    "sys.path.remove",
}
DYNAMIC_IMPORT_CALLS = {"__import__", "importlib.import_module"}


@dataclass(frozen=True)
class Service:
    """Metadata needed to validate one deployable service."""

    name: str
    root: Path
    project_name: str

    @property
    def import_aliases(self) -> frozenset[str]:
        """Return likely Python import names for this service distribution."""
        values = {
            self.name.replace("-", "_"),
            self.project_name.replace("-", "_").replace(".", "_"),
        }
        return frozenset(value for value in values if value)


@dataclass(frozen=True)
class Violation:
    """One deterministic boundary violation."""

    path: Path
    line: int
    code: str
    message: str


def normalize_distribution_name(value: str) -> str:
    """Normalize a Python distribution name according to PEP 503."""
    return NORMALIZED_NAME_PATTERN.sub("-", value).lower()


def is_relative_to(path: Path, parent: Path) -> bool:
    """Return whether path is contained by parent without raising ValueError."""
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML document."""
    with path.open("rb") as source:
        return tomllib.load(source)


def discover_services(repository_root: Path) -> tuple[list[Service], list[Violation]]:
    """Discover deployable services and validate their identifiers."""
    services_root = repository_root / "services"
    violations: list[Violation] = []

    if not services_root.is_dir():
        return [], [
            Violation(
                path=services_root,
                line=1,
                code="BOUNDARY001",
                message="services/ directory does not exist",
            )
        ]

    services: list[Service] = []
    for service_root in sorted(
        path for path in services_root.iterdir() if path.is_dir()
    ):
        pyproject = service_root / "pyproject.toml"
        if not pyproject.is_file():
            continue

        if SERVICE_NAME_PATTERN.fullmatch(service_root.name) is None:
            violations.append(
                Violation(
                    path=service_root,
                    line=1,
                    code="BOUNDARY002",
                    message=(
                        "service directory name must use lowercase kebab-case: "
                        f"{service_root.name}"
                    ),
                )
            )

        try:
            document = load_toml(pyproject)
        except (OSError, tomllib.TOMLDecodeError) as error:
            violations.append(
                Violation(
                    path=pyproject,
                    line=1,
                    code="BOUNDARY003",
                    message=f"cannot read pyproject.toml: {error}",
                )
            )
            continue

        project = document.get("project")
        project_name = project.get("name") if isinstance(project, dict) else None
        if not isinstance(project_name, str) or not project_name.strip():
            violations.append(
                Violation(
                    path=pyproject,
                    line=1,
                    code="BOUNDARY004",
                    message="[project].name must be a non-empty string",
                )
            )
            continue

        services.append(
            Service(
                name=service_root.name,
                root=service_root.resolve(),
                project_name=project_name,
            )
        )

    if not services:
        violations.append(
            Violation(
                path=services_root,
                line=1,
                code="BOUNDARY005",
                message="no services containing pyproject.toml were found",
            )
        )

    project_names: dict[str, Service] = {}
    for service in services:
        normalized = normalize_distribution_name(service.project_name)
        existing = project_names.get(normalized)
        if existing is not None:
            violations.append(
                Violation(
                    path=service.root / "pyproject.toml",
                    line=1,
                    code="BOUNDARY006",
                    message=(
                        f"duplicate project name {service.project_name!r}; "
                        f"already used by {existing.name}"
                    ),
                )
            )
        else:
            project_names[normalized] = service

    return services, violations


def dotted_name(node: ast.AST) -> str | None:
    """Return a dotted identifier represented by Name/Attribute nodes."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent is not None else None
    return None


class ImportBoundaryVisitor(ast.NodeVisitor):
    """Find forbidden imports and path manipulation in one Python file."""

    def __init__(
        self,
        *,
        path: Path,
        current_service: Service,
        other_services: tuple[Service, ...],
    ) -> None:
        self.path = path
        self.current_service = current_service
        self.other_services = other_services
        self.violations: list[Violation] = []

        aliases: set[str] = set()
        for service in other_services:
            aliases.update(service.import_aliases)
        self.other_import_aliases = frozenset(aliases)

    def add(self, node: ast.AST, code: str, message: str) -> None:
        """Record a violation at the node's source line."""
        self.violations.append(
            Violation(
                path=self.path,
                line=getattr(node, "lineno", 1),
                code=code,
                message=message,
            )
        )

    def forbidden_module_reason(self, module: str) -> str | None:
        """Explain why an imported module crosses a service boundary."""
        root = module.split(".", maxsplit=1)[0]
        if root in FORBIDDEN_IMPORT_ROOTS:
            return f"import from repository namespace {root!r} is forbidden"
        if root in self.other_import_aliases:
            return f"import targets another service's internal package: {root!r}"
        return None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            reason = self.forbidden_module_reason(alias.name)
            if reason is not None:
                self.add(node, "BOUNDARY101", reason)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is not None:
            reason = self.forbidden_module_reason(node.module)
            if reason is not None:
                self.add(node, "BOUNDARY102", reason)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        function_name = dotted_name(node.func)
        if function_name in SYS_PATH_MUTATIONS:
            self.add(
                node,
                "BOUNDARY103",
                f"Python import path mutation is forbidden: {function_name}",
            )

        if function_name in DYNAMIC_IMPORT_CALLS and node.args:
            module_argument = node.args[0]
            if isinstance(module_argument, ast.Constant) and isinstance(
                module_argument.value, str
            ):
                reason = self.forbidden_module_reason(module_argument.value)
                if reason is not None:
                    self.add(node, "BOUNDARY104", f"dynamic {reason}")

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if any(dotted_name(target) == "sys.path" for target in node.targets):
            self.add(node, "BOUNDARY105", "assignment to sys.path is forbidden")
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if dotted_name(node.target) == "sys.path":
            self.add(node, "BOUNDARY106", "modification of sys.path is forbidden")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, str):
            return

        normalized = node.value.replace("\\", "/")
        for service in self.other_services:
            forbidden_fragments = (
                f"services/{service.name}",
                f"../{service.name}",
                f"../services/{service.name}",
            )
            if any(fragment in normalized for fragment in forbidden_fragments):
                self.add(
                    node,
                    "BOUNDARY107",
                    f"path literal references another service: {service.name}",
                )
                break

        if "templates/fastapi-microservice" in normalized:
            self.add(
                node,
                "BOUNDARY108",
                "runtime code must not access the service template",
            )


def check_python_sources(service: Service, services: list[Service]) -> list[Violation]:
    """Parse service Python files and inspect their import boundaries."""
    violations: list[Violation] = []
    other_services = tuple(candidate for candidate in services if candidate != service)

    for directory_name in SOURCE_DIRECTORIES:
        source_root = service.root / directory_name
        if not source_root.is_dir():
            continue

        for path in sorted(source_root.rglob("*.py")):
            try:
                source = path.read_text(encoding="utf-8")
                syntax_tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError) as error:
                violations.append(
                    Violation(
                        path=path,
                        line=getattr(error, "lineno", 1) or 1,
                        code="BOUNDARY109",
                        message=f"cannot parse Python source: {error}",
                    )
                )
                continue

            visitor = ImportBoundaryVisitor(
                path=path,
                current_service=service,
                other_services=other_services,
            )
            visitor.visit(syntax_tree)
            violations.extend(visitor.violations)

    return violations


def collect_dependency_strings(document: dict[str, Any]) -> list[str]:
    """Collect PEP 508 strings from standard project dependency sections."""
    dependencies: list[str] = []
    project = document.get("project")
    if isinstance(project, dict):
        direct = project.get("dependencies")
        if isinstance(direct, list):
            dependencies.extend(value for value in direct if isinstance(value, str))

        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    dependencies.extend(
                        value for value in values if isinstance(value, str)
                    )

    groups = document.get("dependency-groups")
    if isinstance(groups, dict):
        for values in groups.values():
            if isinstance(values, list):
                dependencies.extend(value for value in values if isinstance(value, str))

    return dependencies


def extract_paths(value: Any) -> list[str]:
    """Recursively collect path fields from tool-specific dependency sources."""
    paths: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == "path" and isinstance(nested, str):
                paths.append(nested)
            else:
                paths.extend(extract_paths(nested))
    elif isinstance(value, list):
        for nested in value:
            paths.extend(extract_paths(nested))
    return paths


def path_boundary_reason(
    raw_path: str,
    *,
    service: Service,
    services: list[Service],
    repository_root: Path,
) -> str | None:
    """Return a reason when a dependency path enters another private tree."""
    normalized = raw_path.replace("\\", "/")
    if normalized.startswith("file://"):
        normalized = normalized.removeprefix("file://")

    candidate = Path(normalized)
    if not candidate.is_absolute():
        candidate = service.root / candidate
    resolved = candidate.resolve(strict=False)

    for other_service in services:
        if other_service == service:
            continue
        if is_relative_to(resolved, other_service.root):
            return f"local dependency enters another service: {other_service.name}"

    template_root = (repository_root / "templates").resolve()
    if is_relative_to(resolved, template_root):
        return "runtime dependency on templates/ is forbidden"

    return None


def check_pyproject(
    service: Service,
    services: list[Service],
    repository_root: Path,
) -> list[Violation]:
    """Reject package and path dependencies on another service."""
    path = service.root / "pyproject.toml"
    try:
        document = load_toml(path)
    except (OSError, tomllib.TOMLDecodeError):
        return []  # Discovery already reports this error.

    violations: list[Violation] = []
    other_project_names = {
        normalize_distribution_name(candidate.project_name): candidate
        for candidate in services
        if candidate != service
    }

    for dependency in collect_dependency_strings(document):
        match = DEPENDENCY_NAME_PATTERN.match(dependency)
        if match is not None:
            dependency_name = normalize_distribution_name(match.group(1))
            other_service = other_project_names.get(dependency_name)
            if other_service is not None:
                violations.append(
                    Violation(
                        path=path,
                        line=1,
                        code="BOUNDARY201",
                        message=(
                            f"dependency {match.group(1)!r} is another deployable "
                            f"service ({other_service.name})"
                        ),
                    )
                )

        normalized = dependency.replace("\\", "/")
        for other_service in services:
            if other_service == service:
                continue
            fragments = (
                f"services/{other_service.name}",
                f"../{other_service.name}",
            )
            if any(fragment in normalized for fragment in fragments):
                violations.append(
                    Violation(
                        path=path,
                        line=1,
                        code="BOUNDARY202",
                        message=(
                            "dependency string references another service path: "
                            f"{other_service.name}"
                        ),
                    )
                )
                break

        if "templates/" in normalized:
            violations.append(
                Violation(
                    path=path,
                    line=1,
                    code="BOUNDARY203",
                    message="dependency string references templates/",
                )
            )

    tool = document.get("tool")
    uv = tool.get("uv") if isinstance(tool, dict) else None
    sources = uv.get("sources") if isinstance(uv, dict) else None
    for raw_path in extract_paths(sources):
        reason = path_boundary_reason(
            raw_path,
            service=service,
            services=services,
            repository_root=repository_root,
        )
        if reason is not None:
            violations.append(
                Violation(
                    path=path,
                    line=1,
                    code="BOUNDARY204",
                    message=reason,
                )
            )

    return violations


def check_source_symlinks(service: Service) -> list[Violation]:
    """Reject source symlinks escaping the owning service directory."""
    violations: list[Violation] = []
    for directory_name in SOURCE_DIRECTORIES:
        source_root = service.root / directory_name
        if not source_root.is_dir():
            continue

        for path in sorted(source_root.rglob("*")):
            if not path.is_symlink():
                continue
            resolved = path.resolve(strict=False)
            if not is_relative_to(resolved, service.root):
                violations.append(
                    Violation(
                        path=path,
                        line=1,
                        code="BOUNDARY301",
                        message=f"source symlink escapes service directory: {resolved}",
                    )
                )
    return violations


def docker_instructions(path: Path) -> list[tuple[int, str]]:
    """Return logical Dockerfile instructions with their starting line."""
    instructions: list[tuple[int, str]] = []
    buffer = ""
    start_line = 1

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = raw_line.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start_line = line_number

        continued = stripped.endswith("\\")
        fragment = stripped[:-1].strip() if continued else stripped
        buffer = f"{buffer} {fragment}".strip()
        if not continued:
            instructions.append((start_line, buffer))
            buffer = ""

    if buffer:
        instructions.append((start_line, buffer))
    return instructions


def check_dockerfile(service: Service) -> list[Violation]:
    """Reject Docker build instructions that reach outside service context."""
    path = service.root / "Dockerfile"
    if not path.is_file():
        return [
            Violation(
                path=path,
                line=1,
                code="BOUNDARY401",
                message="service Dockerfile is missing",
            )
        ]

    violations: list[Violation] = []
    try:
        instructions = docker_instructions(path)
    except (OSError, UnicodeDecodeError) as error:
        return [
            Violation(
                path=path,
                line=1,
                code="BOUNDARY402",
                message=f"cannot read Dockerfile: {error}",
            )
        ]

    for line_number, instruction in instructions:
        match = re.match(r"^(COPY|ADD)\s+(.*)$", instruction, flags=re.IGNORECASE)
        if match is None:
            continue

        payload = match.group(2).replace("\\", "/")
        try:
            tokens = shlex.split(payload)
        except ValueError:
            tokens = payload.split()

        sources = [token for token in tokens[:-1] if not token.startswith("--")]
        forbidden = next(
            (
                source
                for source in sources
                if source == ".."
                or source.startswith(("../", "services/", "templates/"))
            ),
            None,
        )
        if forbidden is not None:
            violations.append(
                Violation(
                    path=path,
                    line=line_number,
                    code="BOUNDARY403",
                    message=(
                        f"{match.group(1).upper()} reads outside the service build "
                        f"context: {forbidden!r}"
                    ),
                )
            )

    return violations


def check_repository(repository_root: Path) -> tuple[list[Service], list[Violation]]:
    """Run every service-boundary rule."""
    services, violations = discover_services(repository_root)
    for service in services:
        violations.extend(check_python_sources(service, services))
        violations.extend(check_pyproject(service, services, repository_root))
        violations.extend(check_source_symlinks(service))
        violations.extend(check_dockerfile(service))
    return services, violations


def relative_display_path(repository_root: Path, path: Path) -> str:
    """Return a stable repository-relative path for diagnostics."""
    try:
        return path.resolve(strict=False).relative_to(repository_root).as_posix()
    except ValueError:
        return path.as_posix()


def github_escape(value: str, *, property_value: bool = False) -> str:
    """Escape a GitHub Actions workflow-command value."""
    escaped = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        escaped = escaped.replace(":", "%3A").replace(",", "%2C")
    return escaped


def report_violations(repository_root: Path, violations: list[Violation]) -> None:
    """Print local diagnostics and optional GitHub annotations."""
    ordered = sorted(
        violations,
        key=lambda item: (
            relative_display_path(repository_root, item.path),
            item.line,
            item.code,
            item.message,
        ),
    )
    github_actions = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"

    for violation in ordered:
        display_path = relative_display_path(repository_root, violation.path)
        print(
            f"{display_path}:{violation.line}: {violation.code}: {violation.message}",
            file=sys.stderr,
        )
        if github_actions:
            print(
                "::error "
                f"file={github_escape(display_path, property_value=True)},"
                f"line={violation.line},"
                f"title={github_escape(violation.code, property_value=True)}::"
                f"{github_escape(violation.message)}",
                file=sys.stderr,
            )


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    default_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Reject dependencies on another service's internal code."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=default_root,
        help="repository root; defaults to the parent of scripts/",
    )
    return parser.parse_args()


def main() -> int:
    """Run the boundary checker and return a process exit code."""
    arguments = parse_arguments()
    repository_root = arguments.root.expanduser().resolve()

    if not repository_root.is_dir():
        print(f"Repository root does not exist: {repository_root}", file=sys.stderr)
        return 2

    services, violations = check_repository(repository_root)
    if violations:
        report_violations(repository_root, violations)
        print(
            f"Service boundary check failed with {len(violations)} violation(s).",
            file=sys.stderr,
        )
        return 1

    service_names = ", ".join(service.name for service in services)
    print(f"Service boundary check passed for: {service_names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
