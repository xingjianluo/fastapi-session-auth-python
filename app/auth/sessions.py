"""会话生命周期管理。

- 登录成功与权限变化时创建新标识（轮换），旧会话立即失效，防止会话固定。
- 校验时区分：无标识/已撤销/已过期，统一给出 session_invalid 结论。
- 会话数据以存储锁保护，并发请求读到的始终是最新状态（撤销即时生效）。
"""
from __future__ import annotations

import time
from collections.abc import Callable

from app.auth.security import new_csrf_token, new_session_id
from app.auth.store import Store
from app.config import Settings
from app.errors import session_invalid
from app.models import SessionRecord


class SessionManager:
    def __init__(
        self,
        store: Store,
        settings: Settings,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.settings = settings
        self.clock = clock

    def create(self, username: str) -> tuple[str, str]:
        """创建全新会话，返回 (会话标识, CSRF 令牌)。"""
        now = self.clock()
        sid = new_session_id(self.settings)
        csrf_token = new_csrf_token(self.settings)
        self.store.put_session(
            SessionRecord(
                sid=sid,
                username=username,
                csrf_token=csrf_token,
                created_at=now,
                expires_at=now + self.settings.session_ttl_seconds,
            )
        )
        return sid, csrf_token

    def rotate(self, sid: str) -> tuple[str, str]:
        """轮换指定会话：生成新标识与新 CSRF 令牌，旧标识立即失效。

        用于权限变化后；旧会话记录从存储中删除。
        """
        record = self.resolve(sid)
        self.store.remove_session(sid)
        now = self.clock()
        new_sid = new_session_id(self.settings)
        new_token = new_csrf_token(self.settings)
        self.store.put_session(
            SessionRecord(
                sid=new_sid,
                username=record.username,
                csrf_token=new_token,
                created_at=now,
                expires_at=now + self.settings.session_ttl_seconds,
            )
        )
        return new_sid, new_token

    def resolve(self, sid: str | None) -> SessionRecord:
        """解析会话标识，无效/撤销/过期一律抛出 session_invalid。"""
        if not sid:
            raise session_invalid()
        record = self.store.get_session(sid)
        if record is None or record.revoked:
            raise session_invalid()
        if record.expires_at <= self.clock():
            # 过期即清理，避免悬挂记录。
            self.store.remove_session(sid)
            raise session_invalid()
        return record

    def revoke(self, sid: str) -> None:
        self.store.revoke_session(sid)
