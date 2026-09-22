"""共享依赖容器：配置、存储与各管理器。

默认提供一个进程级单例容器；测试可通过 create_container() 构造独立环境，
或用 reset_container() 重置全局状态。
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from app.auth.bruteforce import BruteForceGuard
from app.auth.security import seed_accounts
from app.auth.sessions import SessionManager
from app.auth.store import Store
from app.config import Settings, get_settings


@dataclass
class Container:
    settings: Settings
    store: Store
    sessions: SessionManager
    guard: BruteForceGuard


def create_container(settings: Settings | None = None) -> Container:
    settings = settings or get_settings()
    store = Store()
    store.accounts = seed_accounts(settings)
    store.resources = {
        "public-note": "anyone authenticated may read this",
        "admin-secret": "admin-only protected resource",
    }
    return Container(
        settings=settings,
        store=store,
        sessions=SessionManager(store, settings, clock=time.time),
        guard=BruteForceGuard(store, settings, clock=time.monotonic),
    )


_container: Container | None = None


def get_container() -> Container:
    global _container
    if _container is None:
        _container = create_container()
    return _container


def reset_container(settings: Settings | None = None) -> Container:
    global _container
    _container = create_container(settings)
    return _container
