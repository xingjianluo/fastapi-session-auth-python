"""测试夹具：每个用例使用独立容器与独立配置，日志打印关键判定依据。"""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app import deps
from app.config import Settings
from app.deps import create_container
from app.main import app

logger = logging.getLogger("session_auth.tests")


@pytest.fixture
def settings_factory():
    """用自定义阈值构造容器，返回 (settings, container) 工厂。"""

    def _factory(**overrides):
        settings = Settings(**overrides)
        container = create_container(settings)
        deps._container = container
        return settings, container

    return _factory


@pytest.fixture
def env(settings_factory):
    """默认环境：阈值小便于测试，锁定期用可控时钟验证自动恢复。"""
    settings, container = settings_factory(
        max_failures=3, lockout_seconds=600, session_ttl_seconds=1800
    )
    logger.info(
        "setup: fresh container max_failures=%s lockout=%ss ttl=%ss",
        settings.max_failures,
        settings.lockout_seconds,
        settings.session_ttl_seconds,
    )
    return {"settings": settings, "container": container}


@pytest.fixture
def client():
    return TestClient(app)
