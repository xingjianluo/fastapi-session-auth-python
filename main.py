"""FastAPI 入口：会话认证 / 授权 / 防护 演示服务。"""
from __future__ import annotations

import logging
import time

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.deps import (
    _PENDING_COOKIE_STATE,
    CSRF_HEADER,
    SESSION_COOKIE,
    require_admin_csrf,
    require_auth,
    require_csrf,
    require_role,
)
from app.errors import AuthError
from app.models import Role, Session, User
from app.ratelimit import RateLimiter
from app.security import hash_password
from app.service import AuthService
from app.store import SessionStore, UserStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("auth.api")


class LoginBody(BaseModel):
    username: str
    password: str


class RoleBody(BaseModel):
    username: str
    role: Role


class RevokeBody(BaseModel):
    username: str


class SessionRevokeBody(BaseModel):
    session_id: str


def _source(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_app(
    *,
    session_ttl: float = 1800.0,
    absolute_session_ttl: float = 14400.0,
    max_failures: int = 5,
    lock_seconds: float = 60.0,
    clock=None,
) -> FastAPI:
    clock = clock or time.time
    app = FastAPI(title="session-auth-demo")

    users = UserStore()
    for name, password, role in (
        ("admin", "admin-pass", Role.ADMIN),
        ("alice", "alice-pass", Role.USER),
        ("bob", "bob-pass", Role.USER),
    ):
        users.add(User(name, hash_password(password), role))
    sessions = SessionStore(
        ttl_seconds=session_ttl,
        absolute_ttl_seconds=absolute_session_ttl,
        clock=clock,
    )
    limiter = RateLimiter(
        max_failures=max_failures,
        lock_seconds=lock_seconds,
        clock=clock,
    )
    service = AuthService(users, sessions, limiter)
    app.state.auth_service = service
    app.state.user_store = users

    @app.exception_handler(AuthError)
    async def on_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        # 所有入口共享同一结论结构：HTTP 状态 + reason 码 + 可读 detail。
        logger.warning(
            "拒绝访问 method=%s path=%s status=%s reason=%s detail=%s",
            request.method,
            request.url.path,
            exc.status_code,
            exc.reason.value,
            exc.detail,
        )
        response = JSONResponse(
            status_code=exc.status_code,
            content={"reason": exc.reason.value, "detail": exc.detail},
        )
        # 权限变化引发的轮换可能发生在随后被 403 拒绝的请求里；
        # 错误响应也必须下发新标识，否则客户端持旧标识会被当成已撤销，
        # 等同于一次越权被拒就把整条会话踢掉。
        pending = getattr(request.state, _PENDING_COOKIE_STATE, None)
        if pending is not None:
            new_session_id, new_csrf = pending
            response.set_cookie(
                SESSION_COOKIE,
                new_session_id,
                httponly=True,
                samesite="lax",
            )
            response.headers[CSRF_HEADER] = new_csrf
        return response

    @app.get("/")
    def read_root() -> dict[str, str]:
        return {"Hello": "World"}

    @app.post("/auth/login")
    def login(body: LoginBody, request: Request):
        session = service.login(body.username, body.password, _source(request))
        logger.info(
            "签发会话 user=%s session=%s",
            body.username,
            session.session_id[:8],
        )
        response = JSONResponse(
            {"username": session.username, "csrf_token": session.csrf_token}
        )
        response.set_cookie(
            SESSION_COOKIE, session.session_id, httponly=True, samesite="lax"
        )
        return response

    @app.post("/auth/logout")
    def logout(principal: tuple[Session, User] = Depends(require_csrf)):
        session, _ = principal
        service.logout(session.session_id)
        response = JSONResponse({"detail": "已登出"})
        response.delete_cookie(SESSION_COOKIE)
        return response

    @app.get("/auth/me")
    def me(principal: tuple[Session, User] = Depends(require_auth)):
        session, user = principal
        return {
            "username": user.username,
            "role": user.role.value,
            "session_id": session.session_id[:8],
        }

    @app.get("/auth/csrf")
    def get_csrf(
        principal: tuple[Session, User] = Depends(require_auth),
    ):
        session, _ = principal
        return {"csrf_token": session.csrf_token}

    @app.get("/auth/sessions")
    def list_sessions(
        principal: tuple[Session, User] = Depends(require_auth),
    ):
        """列出本人当前有效会话（手机/平板/电脑等多端）。

        仅返回本人名下会话；每条展示登录时间、最近活动时间与该会话
        当前看到的角色（按用户实时记录，权限调整后立即体现）。
        """
        _, user = principal
        now = clock()
        items = []
        for session, owner in service.list_sessions(user):
            items.append(
                {
                    "session_id": session.session_id,
                    "current": session.session_id
                    == principal[0].session_id,
                    "created_at": session.created_at,
                    "last_seen_at": session.last_seen_at,
                    "idle_expires_at": session.expires_at,
                    "absolute_expires_at": session.absolute_expires_at,
                    "role": owner.role.value,
                    "age_seconds": now - session.created_at,
                    "idle_seconds_remaining": max(
                        0.0, session.expires_at - now
                    ),
                }
            )
        items.sort(key=lambda item: item["created_at"])
        logger.info("会话列表 user=%s 返回 %s 条", user.username, len(items))
        return {"username": user.username, "sessions": items}

    @app.post("/auth/sessions/revoke")
    def revoke_session(
        body: SessionRevokeBody,
        principal: tuple[Session, User] = Depends(require_csrf),
    ):
        """撤销本人名下指定的单条会话，其余会话不受影响。

        被撤销的标识此后一律返回 401 session_revoked，与自然过期区分。
        撤销的若是当前会话，则本次响应同时清除自身 Cookie。
        """
        session, user = principal
        target = body.session_id
        service.revoke_session(user, target)
        response = JSONResponse(
            {"detail": "会话已撤销", "session_id": target}
        )
        if target == session.session_id:
            response.delete_cookie(SESSION_COOKIE)
        logger.info(
            "单条撤销完成 user=%s target=%s self=%s",
            user.username,
            target[:8],
            target == session.session_id,
        )
        return response

    @app.get("/admin/users")
    def admin_users(
        principal: tuple[Session, User] = Depends(require_role(Role.ADMIN)),
    ):
        # 默认拒绝：未认证 -> 401 unauthenticated；普通用户 -> 403 forbidden，
        # 两种结论均不泄露用户列表是否存在。
        return {"users": [name for name in ("admin", "alice", "bob")
                         if users.get(name) is not None]}

    @app.post("/admin/roles")
    def change_role(
        body: RoleBody,
        principal: tuple[Session, User] = Depends(require_admin_csrf),
    ):
        _, actor = principal
        target = users.get(body.username)
        if target is None:
            return JSONResponse({"detail": "用户不存在"}, status_code=404)
        version = users.set_role(body.username, body.role)
        logger.info(
            "角色变更 actor=%s target=%s new_role=%s role_version=%s",
            actor.username,
            body.username,
            body.role.value,
            version,
        )
        return {
            "username": body.username,
            "role": body.role.value,
            "role_version": version,
        }

    @app.post("/admin/revoke")
    def revoke_user(
        body: RevokeBody,
        principal: tuple[Session, User] = Depends(require_admin_csrf),
    ):
        _, actor = principal
        count = sessions.revoke_all_for_user(body.username)
        logger.info(
            "管理员撤销会话 actor=%s target=%s count=%s",
            actor.username,
            body.username,
            count,
        )
        return {"username": body.username, "revoked": count}

    return app


app = create_app()
