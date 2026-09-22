"""FastAPI 入口：会话认证 / 授权 / 防护 演示服务。"""
from __future__ import annotations

import logging
import time

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.deps import (
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


def _source(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_app(
    *,
    session_ttl: float = 1800.0,
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
    sessions = SessionStore(ttl_seconds=session_ttl, clock=clock)
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
        return JSONResponse(
            status_code=exc.status_code,
            content={"reason": exc.reason.value, "detail": exc.detail},
        )

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
