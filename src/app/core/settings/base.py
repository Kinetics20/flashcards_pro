from __future__ import annotations

import os
import re
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from pydantic import AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Supported runtime environments."""

    LOCAL = "local"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class ComponentSettings(BaseSettings):
    """Common environment contract for one configuration component."""

    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )


def known_environment_names(*models: type[ComponentSettings]) -> frozenset[str]:
    """Return the explicit environment-variable contract for all components."""
    names: set[str] = set()
    for model in models:
        prefix = str(model.model_config.get("env_prefix", ""))
        for name, field in model.model_fields.items():
            alias = field.validation_alias
            if isinstance(alias, str):
                names.add(alias.upper())
            elif isinstance(alias, AliasChoices):
                names.update(
                    str(choice).upper() for choice in alias.choices if isinstance(choice, str)
                )
            else:
                names.add(f"{prefix}{name}".upper())
    return frozenset(names)


_KUBERNETES_APP_SERVICE_LINK = re.compile(
    r"^APP_(?:SERVICE_(?:HOST|PORT(?:_[A-Z0-9_]+)?)|PORT(?:_[A-Z0-9_]+)?)$"
)


def reject_unknown_app_environment(known_names: frozenset[str]) -> None:
    """Fail fast on misspelled APP settings without rejecting Kubernetes links."""
    unknown = sorted(
        name
        for name in os.environ
        if name.upper().startswith("APP_")
        and name.upper() not in known_names
        and _KUBERNETES_APP_SERVICE_LINK.fullmatch(name.upper()) is None
    )
    if unknown:
        raise ValueError(f"unknown APP environment variable(s): {', '.join(unknown)}")


def reject_unknown_app_dotenv(known_names: frozenset[str], env_file: Any) -> None:
    """Apply the same strict APP contract to dotenv files."""
    if env_file is None:
        return
    if isinstance(env_file, (str, Path)):
        paths = (Path(env_file),)
    elif isinstance(env_file, (tuple, list)):
        candidates = cast("tuple[object, ...] | list[object]", env_file)
        paths = tuple(Path(path) for path in candidates if isinstance(path, (str, Path)))
    else:
        return

    unknown: set[str] = set()
    assignment = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            match = assignment.match(line.strip())
            if match is None:
                continue
            name = match.group(1).upper()
            if name.startswith("APP_") and name not in known_names:
                unknown.add(name)
    if unknown:
        raise ValueError(f"unknown APP dotenv variable(s): {', '.join(sorted(unknown))}")


def component_source_kwargs(env_file: Any) -> dict[str, Any]:
    """Forward the root dotenv selection to every component settings source."""
    return {"_env_file": env_file}


DEFAULT_ENV_FILE = Path(".env")
