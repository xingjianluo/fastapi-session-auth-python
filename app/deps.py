"""FastAPI 依赖：认证、角色授权、CSRF 校验。

判定顺序：会话解析（未认证/过期/撤销）→ 权限变化时原子轮换会话标识
→ 状态变更请求的 CSRF 校验 → 角色判定（默认拒绝）。
"""
from __future__ import annotations

import logging

from fastapi import Depends, Request, Response

from .errors import AuthError, Reason
from .models import Role, Session, User
from .service import AuthService

SESSION_COOKIE = "session"
CSRF_HEADER = "x-csrf-token"
# 轮换当次请求临时携带的"上一代令牌"，仅在本次请求内有效。
_PRED_STATE = "csrf_predecessor_token"
# 本次请求内发生的会话轮换结果（新标识、新 CSRF 令牌）：
# 即使后续判定（如角色不足）以错误响应告终，也要把新标识带给客户端，
# 避免“被拒一次操作”把本来仍然有效的会话弄丢。
_ROTATION_STATE = "session_rotation"

logger = logging.getLogger("auth.deps")


def get_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def require_auth(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_service),
) -> tuple[Session, User]:
    session, user = service.resolve(request.cookies.get(SESSION_COOKIE))
    if service.needs_rotation(session, user):
        # 权限已变化：原子轮换会话标识，旧标识立即失效；
        # 新标识与新 CSRF 令牌随响应下发，上一代令牌仅本次请求可沿用。
        old_csrf = session.csrf_token
        session = service.rotate(session, user)
        setattr(request.state, _PRED_STATE, old_csrf)
        setattr(
            request.state,
            _ROTATION_STATE,
            (session.session_id, session.csrf_token),
        )
        response.set_cookie(
            SESSION_COOKIE,
            session.session_id,
            httponly=True,
            samesite="lax",
        )
        response.headers[CSRF_HEADER] = session.csrf_token
    return session, user


def require_role(role: Role):
    """角色守卫工厂：默认拒绝，仅匹配角色放行；未认证与权限不足原因可区分。"""

    def guard(
        principal: tuple[Session, User] = Depends(require_auth),
    ) -> tuple[Session, User]:
        session, user = principal
        if user.role != role:
            logger.warning(
                "授权拒绝 user=%s required=%s actual=%s session=%s reason=%s",
                user.username,
                role.value,
                user.role.value,
                session.session_id[:8],
                Reason.FORBIDDEN.value,
            )
            raise AuthError(
                Reason.FORBIDDEN, 403, "权限不足，禁止访问该资源"
            )
        return principal

    return guard


def require_csrf(
    request: Request,
    service: AuthService = Depends(get_service),
    principal: tuple[Session, User] = Depends(require_auth),
) -> tuple[Session, User]:
    """校验与当前会话绑定的 CSRF 令牌（状态变更请求专用）。"""
    session, _ = principal
    token = request.headers.get(CSRF_HEADER)
    if not token:
        service.check_csrf(session, None)  # 抛出 CSRF_MISSING
    if token == session.csrf_token:
        return principal
    predecessor = getattr(request.state, _PRED_STATE, None)
    if predecessor is not None and token == predecessor:
        # 权限变化轮换当次请求：客户端持有的上一代令牌仍与会话同属一条沿袭链，
        # 允许通过本次请求；旧会话已立墓碑，该令牌重放时将无法通过。
        logger.info(
            "CSRF 沿用上一代令牌（轮换当次请求）session=%s",
            session.session_id[:8],
        )
        return principal
    service.check_csrf(session, token)  # 抛出 CSRF_CROSS_SESSION / CSRF_INVALID
    return principal


def require_admin_csrf(
    principal: tuple[Session, User] = Depends(require_csrf),
) -> tuple[Session, User]:
    """管理端状态变更：先过 CSRF，再默认拒绝地判定管理员角色。"""
    session, user = principal
    if user.role != Role.ADMIN:
        logger.warning(
            "授权拒绝 user=%s required=%s actual=%s session=%s reason=%s",
            user.username,
            Role.ADMIN.value,
            user.role.value,
            session.session_id[:8],
            Reason.FORBIDDEN.value,
        )
        raise AuthError(Reason.FORBIDDEN, 403, "权限不足，禁止该管理操作")
    return principal
