from typing import Annotated, cast

from fastapi import Depends, Request

from app.core.config import Settings


def settings_from_request(request: Request) -> Settings:
    """Return the validated settings bound to the current application."""
    return cast(Settings, request.app.state.settings)


SettingsDependency = Annotated[Settings, Depends(settings_from_request)]
