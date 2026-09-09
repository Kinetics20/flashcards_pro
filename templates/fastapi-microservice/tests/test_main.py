from unittest.mock import Mock

from pytest import MonkeyPatch

from app import main
from app.core.config import Environment, Settings


def test_application_factory_configures_identity_and_documentation() -> None:
    hidden_settings = Settings(
        _env_file=None,
        name="Orders API",
        version="2.3.4",
        environment=Environment.TEST,
        docs_enabled=False,
    )
    exposed_settings = Settings(
        _env_file=None,
        environment=Environment.TEST,
        docs_enabled=True,
    )

    hidden = main.create_app(hidden_settings)
    exposed = main.create_app(exposed_settings)

    assert hidden.title == "Orders API"
    assert hidden.version == "2.3.4"
    assert hidden.docs_url is None
    assert hidden.redoc_url is None
    assert hidden.openapi_url is None
    assert exposed.docs_url == "/docs"
    assert exposed.redoc_url == "/redoc"
    assert exposed.openapi_url == "/openapi.json"


async def test_lifespan_configures_logging_and_reports_lifecycle(
    test_settings: Settings,
    monkeypatch: MonkeyPatch,
) -> None:
    configure_logging = Mock()
    info = Mock()
    app = main.create_app(test_settings)
    monkeypatch.setattr(main, "configure_logging", configure_logging)
    monkeypatch.setattr(main.logger, "info", info)

    async with main.lifespan(app):
        configure_logging.assert_called_once_with("INFO")

    assert info.call_count == 2
    assert info.call_args_list[0].args == ("Application started",)
    assert info.call_args_list[1].args == ("Application stopped",)
