"""认证服务：登录、登出、撤销、会话解析与 CSRF 判定。"""
from __future__ import annotations

import logging

from .errors import AuthError, Reason
from .models import Session, User
from .ratelimit import RateLimiter
from .security import verify_password
from .store import SessionStore, UserStore

logger = logging.getLogger("auth.service")


class AuthService:
    def __init__(
        self,
        users: UserStore,
        sessions: SessionStore,
        limiter: RateLimiter,
    ) -> None:
        self._users = users
        self._sessions = sessions
        self._limiter = limiter

    @property
    def sessions(self) -> SessionStore:
        return self._sessions

    @property
    def users(self) -> UserStore:
        return self._users

    def login(self, username: str, password: str, source: str) -> Session:
        # 判定顺序：先在锁内原子完成“锁定检查+失败计数”（悲观计数，
        # 并发失败不丢计数、不超阈放行），再验凭证；
        # 成功则清零计数并签发全新会话标识（防固定）。
        self._limiter.begin_attempt(username, source)
        user = self._users.get(username)
        if user is None or not verify_password(password, user.password_hash):
            logger.warning(
                "登录失败 user=%s source=%s reason=%s",
                username,
                source,
                Reason.INVALID_CREDENTIALS.value,
            )
            raise AuthError(
                Reason.INVALID_CREDENTIALS, 401, "用户名或口令错误"
            )
        self._limiter.record_success(username, source)
        session = self._sessions.create(user.username, user.role_version)
        logger.info(
            "登录成功 user=%s source=%s session=%s role=%s role_version=%s",
            username,
            source,
            session.session_id[:8],
            user.role.value,
            user.role_version,
        )
        return session

    def logout(self, session_id: str | None) -> None:
        if session_id:
            self._sessions.revoke(session_id)
            logger.info("会话登出并撤销 session=%s", session_id[:8])

    def resolve(self, session_id: str | None) -> tuple[Session, User]:
        """解析当前会话与用户实时角色（授权结果不缓存，权限变更立即生效）。"""
        session = self._sessions.get_valid(session_id)
        user = self._users.get(session.username)
        if user is None:
            self._sessions.revoke(session.session_id)
            logger.warning(
                "会话所属用户已不存在 session=%s user=%s",
                session.session_id[:8],
                session.username,
            )
            raise AuthError(Reason.UNAUTHENTICATED, 401, "账号不存在")
        logger.debug(
            "会话解析 session=%s user=%s role=%s session_v=%s user_v=%s",
            session.session_id[:8],
            user.username,
            user.role.value,
            session.role_version,
            user.role_version,
        )
        return session, user

    def needs_rotation(self, session: Session, user: User) -> bool:
        return session.role_version != user.role_version

    def rotate(self, session: Session, user: User) -> Session:
        new_session = self._sessions.rotate(
            session.session_id, user.role_version
        )
        logger.info(
            "权限变化触发会话轮换 user=%s old=%s new=%s role=%s",
            user.username,
            session.session_id[:8],
            new_session.session_id[:8],
            user.role.value,
        )
        return new_session

    def check_csrf(self, session: Session, token: str | None) -> None:
        """校验与当前会话绑定的 CSRF 令牌，失败原因可区分。"""
        if not token:
            logger.warning(
                "CSRF 缺失 session=%s reason=%s",
                session.session_id[:8],
                Reason.CSRF_MISSING.value,
            )
            raise AuthError(
                Reason.CSRF_MISSING, 403, "缺少 X-CSRF-Token 请求头"
            )
        if token == session.csrf_token:
            return
        owner = self._sessions.find_by_csrf(token)
        if owner is not None and owner.session_id != session.session_id:
            logger.warning(
                "CSRF 跨会话复用 presented_session=%s token_owner=%s reason=%s",
                session.session_id[:8],
                owner.session_id[:8],
                Reason.CSRF_CROSS_SESSION.value,
            )
            raise AuthError(
                Reason.CSRF_CROSS_SESSION,
                403,
                "令牌属于其他会话，不得跨会话复用",
            )
        logger.warning(
            "CSRF 无效 session=%s reason=%s",
            session.session_id[:8],
            Reason.CSRF_INVALID.value,
        )
        raise AuthError(Reason.CSRF_INVALID, 403, "CSRF 令牌无效")
