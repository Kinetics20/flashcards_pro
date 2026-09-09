from collections.abc import Iterator

import pytest

from app.core.config import Environment, Settings, get_settings


@pytest.fixture(autouse=True)
def clear_settings_cache() -> Iterator[None]:
    """Prevent process-wide settings from leaking between tests."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def test_settings() -> Settings:
    """Return isolated settings without reading a local dotenv file."""
    return Settings(_env_file=None, environment=Environment.TEST, docs_enabled=True)
