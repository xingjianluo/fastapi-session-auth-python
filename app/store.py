"""线程安全的内存存储：用户、会话。"""
from __future__ import annotations

import threading
import time
from dataclasses import replace

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
    """会话存储。

    时间语义：
    - idle_ttl：空闲有效期。每次受保护访问滑动续期，长时间无操作自然到期；
    - absolute_ttl：自本次登录算起的绝对上限，续期不得越过。
    """

    def __init__(
        self,
        ttl_seconds: float = 1800.0,
        *,
        clock=time.time,
        absolute_ttl_seconds: float | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._idle_ttl = ttl_seconds
        self._absolute_ttl = (
            absolute_ttl_seconds if absolute_ttl_seconds is not None else ttl_seconds * 8
        )
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
            last_seen_at=now,
            expires_at=now + self._idle_ttl,
            absolute_expires_at=now + self._absolute_ttl,
            role_version=role_version,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def _get_valid_locked(self, session_id: str, now: float) -> Session:
        """持锁解析有效会话；未知/过期/失效分别抛出可区分的原因。"""
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
        # 空闲截止与绝对截止任一到达即自然过期（与显式撤销区分）。
        if session.expires_at <= now or session.absolute_expires_at <= now:
            raise AuthError(
                Reason.SESSION_EXPIRED, 401, "会话已过期，请重新登录"
            )
        return session

    def get_valid(self, session_id: str | None) -> Session:
        """解析有效会话；未知/过期/失效分别抛出可区分的原因。"""
        if not session_id:
            raise AuthError(Reason.UNAUTHENTICATED, 401, "缺少会话标识")
        with self._lock:
            return self._get_valid_locked(session_id, self._clock())

    def touch(self, session_id: str) -> Session:
        """受保护访问后续期：滑动空闲截止，但不得越过绝对上限。

        持锁原子完成“校验 + 滑动”，同一会话并发访问不会把到期时间改错，
        也不会误删/弄丢会话状态。
        """
        now = self._clock()
        with self._lock:
            session = self._get_valid_locked(session_id, now)
            candidate = now + self._idle_ttl
            candidate = min(candidate, session.absolute_expires_at)
            # 并发下时钟单调时取较晚者；不回退。
            session.expires_at = max(session.expires_at, candidate)
            session.last_seen_at = now
            return session

    def rotate(self, old_session_id: str, role_version: int) -> Session:
        """原子轮换：旧标识立墓碑，签发新标识（含新 CSRF 令牌）。

        新标识沿用同一登录沿袭链：登录时间与绝对上限保持不变
        （权限变化不得靠轮换重置绝对上限）；空闲窗口重新起算。
        """
        now = self._clock()
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
            if old.expires_at <= now or old.absolute_expires_at <= now:
                raise AuthError(Reason.SESSION_EXPIRED, 401, "会话已过期")
            new_session = Session(
                session_id=new_token(),
                csrf_token=new_token(),
                username=old.username,
                created_at=old.created_at,
                last_seen_at=now,
                expires_at=min(now + self._idle_ttl, old.absolute_expires_at),
                absolute_expires_at=old.absolute_expires_at,
                role_version=role_version,
            )
            self._sessions[new_session.session_id] = new_session
            del self._sessions[old_session_id]
            self._tombstones[old_session_id] = _TOMBSTONE_ROTATED
            return new_session

    def revoke(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is not None:
                self._tombstones[session_id] = _TOMBSTONE_REVOKED

    def revoke_one(self, username: str, session_id: str) -> bool:
        """撤销指定用户名下的单条会话；返回是否命中。

        不属于该用户或本不存在均返回 False，不透露标识归属。
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.username != username:
                return False
            del self._sessions[session_id]
            self._tombstones[session_id] = _TOMBSTONE_REVOKED
            return True

    def list_for_user(self, username: str) -> list[Session]:
        """列出某用户当前有效的全部会话（多端），返回快照副本。"""
        now = self._clock()
        with self._lock:
            return [
                replace(session)
                for session in self._sessions.values()
                if session.username == username
                and session.expires_at > now
                and session.absolute_expires_at > now
            ]

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
