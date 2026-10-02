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
        # 判定顺序不变：先锁定检查（账号优先于来源），再验凭证。
        # 并发名额保证“进行中+已确认失败”不超阈值；失败只在凭证确认
        # 错误后计入，因此并发正确登录只会排队，不会被误伤。
        self._limiter.begin_attempt(username, source)
        try:
            user = self._users.get(username)
            if user is None or not verify_password(password, user.password_hash):
                self._limiter.record_failure(username, source)
                logger.warning(
                    "登录失败 user=%s source=%s reason=%s",
                    username,
                    source,
                    Reason.INVALID_CREDENTIALS.value,
                )
                raise AuthError(
                    Reason.INVALID_CREDENTIALS, 401, "用户名或口令错误"
                )
        except AuthError:
            raise
        except Exception:
            # 未走到成功/失败结论时归还名额，避免并发名额泄漏。
            self._limiter.release_slots(username, source)
            raise
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

    def touch(self, session: Session) -> Session:
        """受保护访问后续期（滑动空闲截止，不越过绝对上限）。"""
        renewed = self._sessions.touch(session.session_id)
        logger.debug(
            "会话续期 session=%s idle_until=%s absolute_until=%s",
            renewed.session_id[:8],
            renewed.expires_at,
            renewed.absolute_expires_at,
        )
        return renewed

    def list_sessions(self, user: User) -> list[tuple[Session, User]]:
        """列出本人当前有效会话，并附带该会话按当前用户记录看到的角色。

        授权结果不缓存：列表中每条展示的都是用户当前角色，
        因此权限调整后无需等待即按新角色显示。
        """
        sessions = self._sessions.list_for_user(user.username)
        logger.info(
            "列出有效会话 user=%s count=%s", user.username, len(sessions)
        )
        return [(session, user) for session in sessions]

    def revoke_session(self, user: User, session_id: str) -> None:
        """撤销本人名下指定的单条会话；不属于本人则按不存在处理。"""
        if not self._sessions.revoke_one(user.username, session_id):
            logger.warning(
                "单条撤销未命中 user=%s session=%s",
                user.username,
                session_id[:8] if session_id else "-",
            )
            raise AuthError(
                Reason.UNAUTHENTICATED, 404, "会话不存在或不属于当前账号"
            )
        logger.info(
            "单条会话已撤销 user=%s session=%s",
            user.username,
            session_id[:8],
        )

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
