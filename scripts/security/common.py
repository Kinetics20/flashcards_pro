"""Small shared helpers. Never include subprocess output in error messages."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    """Hash actual bytes, not a reserialized representation of an artifact."""
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("Non-finite JSON number")


def read_json(path: Path) -> Any:
    return json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=_unique_pairs,
        parse_constant=_invalid_constant,
    )


def write_json(path: Path, document: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def git_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    commit = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("A Git checkout with a committed HEAD is required")
    return commit


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def contained_path(root: Path, relative: str) -> Path:
    """Reject traversal and symlinks pointing outside the approved directory."""
    part = Path(relative)
    if part.is_absolute() or ".." in part.parts:
        raise ValueError("Expected a repository-relative path without traversal")
    root = Path(root).resolve()
    path = (root / part).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Path escapes its approved directory")
    return path
