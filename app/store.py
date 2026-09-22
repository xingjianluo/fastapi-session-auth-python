"""线程安全的内存存储：用户、会话。"""
from __future__ import annotations

import threading
import time

from .errors import AuthError, Reason
from .models import Role, Session, User
from .security import new_token

# 墓碑原因：轮换 / 显式撤销，便于日志解释旧标识为何被拒。
_TOMBSTONE_ROTATED = "rotated"
_TOMBSTONE_REVOKED = "revoked"


class UserStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._users: dict[str, User] = {}

    def add(self, user: User) -> None:
        with self._lock:
            self._users[user.username] = user

    def get(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    def set_role(self, username: str, role: str) -> int:
        """变更角色并自增角色版本号，返回新版本号。"""
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise KeyError(username)
            user.role = Role(role) if not isinstance(role, Role) else role
            user.role_version += 1
            return user.role_version

    def role_version(self, username: str) -> int:
        with self._lock:
            user = self._users.get(username)
            return user.role_version if user else 0


class SessionStore:
    def __init__(self, ttl_seconds: float = 1800.0, *, clock=time.time) -> None:
        self._lock = threading.Lock()
        self._ttl = ttl_seconds
        self._clock = clock
        self._sessions: dict[str, Session] = {}
        # 已失效（撤销/轮换）标识的墓碑，用于拒绝并给出可区分原因。
        self._tombstones: dict[str, str] = {}

    def create(self, username: str, role_version: int) -> Session:
        now = self._clock()
        session = Session(
            session_id=new_token(),
            csrf_token=new_token(),
            username=username,
            created_at=now,
            expires_at=now + self._ttl,
            role_version=role_version,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get_valid(self, session_id: str | None) -> Session:
        """解析有效会话；未知/过期/失效分别抛出可区分的原因。"""
        if not session_id:
            raise AuthError(Reason.UNAUTHENTICATED, 401, "缺少会话标识")
        with self._lock:
            tombstone = self._tombstones.get(session_id)
            if tombstone is not None:
                raise AuthError(
                    Reason.SESSION_REVOKED,
                    401,
                    f"会话已{tombstone}（{tombstone}），请重新登录",
                )
            session = self._sessions.get(session_id)
            if session is None:
                raise AuthError(
                    Reason.UNAUTHENTICATED, 401, "会话不存在或从未签发"
                )
            if session.expires_at <= self._clock():
                raise AuthError(
                    Reason.SESSION_EXPIRED, 401, "会话已过期，请重新登录"
                )
            return session

    def rotate(self, old_session_id: str, role_version: int) -> Session:
        """原子轮换：旧标识立墓碑，签发新标识（含新 CSRF 令牌）。"""
        now = self._clock()
        new_session = Session(
            session_id=new_token(),
            csrf_token=new_token(),
            username="",  # 占位，持锁后从旧会话复制
            created_at=now,
            expires_at=now + self._ttl,
            role_version=role_version,
        )
        with self._lock:
            tombstone = self._tombstones.get(old_session_id)
            if tombstone is not None:
                raise AuthError(
                    Reason.SESSION_REVOKED,
                    401,
                    f"会话已{tombstone}（{tombstone}），请重新登录",
                )
            old = self._sessions.get(old_session_id)
            if old is None:
                raise AuthError(Reason.UNAUTHENTICATED, 401, "会话不存在")
            if old.expires_at <= now:
                raise AuthError(Reason.SESSION_EXPIRED, 401, "会话已过期")
            new_session.username = old.username
            self._sessions[new_session.session_id] = new_session
            del self._sessions[old_session_id]
            self._tombstones[old_session_id] = _TOMBSTONE_ROTATED
            return new_session

    def revoke(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is not None:
                self._tombstones[session_id] = _TOMBSTONE_REVOKED

    def revoke_all_for_user(self, username: str) -> int:
        with self._lock:
            ids = [
                sid
                for sid, session in self._sessions.items()
                if session.username == username
            ]
            for sid in ids:
                del self._sessions[sid]
                self._tombstones[sid] = _TOMBSTONE_REVOKED
            return len(ids)

    def find_by_csrf(self, csrf_token: str) -> Session | None:
        """按 CSRF 令牌反查会话，用于判定令牌是否跨会话复用。"""
        if not csrf_token:
            return None
        with self._lock:
            for session in self._sessions.values():
                if session.csrf_token == csrf_token:
                    return session
        return None
