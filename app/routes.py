"""HTTP 路由入口。

统一判定顺序（受保护入口）：
1. 会话解析（缺失/撤销/过期 -> not_authenticated / session_invalid）
2. 状态变更请求的 CSRF 校验（缺失/无效可区分，且与会话绑定）
3. 权限判定（从账号最新角色即时推导，默认拒绝 -> forbidden）
4. 资源访问（先授权后取资源，越权不暴露资源是否存在）

登录入口的判定顺序：来源/账号锁定检查 -> 凭证校验 -> 失败计数/成功建会话。
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.auth.csrf import CSRF_HEADER, require_csrf
from app.auth.rbac import has_permission, permissions_of
from app.auth.security import verify_password
from app.deps import get_container
from app.errors import (
    AuthError,
    bad_request,
    forbidden,
    not_found,
)
from app.models import Role, SessionRecord

logger = logging.getLogger("session_auth")

router = APIRouter()

SESSION_COOKIE = "sid"

#: 合法角色名（请求体校验）。
_ROLE_NAMES = {role.value for role in Role}


class LoginBody(BaseModel):
    username: str
    password: str


class RolesBody(BaseModel):
    roles: list[str]


class ResourceBody(BaseModel):
    content: str


class RevokeBody(BaseModel):
    sid: str | None = None
    username: str | None = None


def _client_source(request: Request) -> str:
    # 本地演示：以对端主机作为“来源”；反向代理后可取 X-Forwarded-For 首段。
    return request.client.host if request.client else "unknown"


def _session_cookie(sid: str, ttl: int) -> str:
    return (
        f"{SESSION_COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}"
    )


def _clear_cookie() -> str:
    return f"{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"


def _current_session(request: Request) -> SessionRecord:
    """解析当前请求会话；无标识 -> not_authenticated，失效 -> session_invalid。"""
    container = get_container()
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        logger.info("authz: no session cookie presented -> not_authenticated")
        from app.errors import not_authenticated

        raise not_authenticated()
    record = container.sessions.resolve(sid)
    logger.info(
        "authz: session resolved sid=%s user=%s", record.sid, record.username
    )
    return record


def _guard_csrf(request: Request, session: SessionRecord) -> None:
    presented = request.headers.get(CSRF_HEADER)
    logger.info(
        "csrf: method=%s sid=%s token_present=%s",
        request.method,
        session.sid,
        presented is not None,
    )
    require_csrf(session, presented)


def _authorize(
    request: Request, permission: str | None, *, csrf: bool
) -> SessionRecord:
    """受保护入口的统一判定流水线，返回当前会话。

    permission 为 None 表示“仅需认证”，不做权限判定。
    """
    session = _current_session(request)
    if csrf:
        _guard_csrf(request, session)
    if permission is None:
        return session
    container = get_container()
    account = container.store.get_account(session.username)
    if account is None:
        logger.info("authz: account vanished sid=%s -> forbidden", session.sid)
        raise forbidden()
    perms = permissions_of(account)
    logger.info(
        "authz: sid=%s user=%s roles=%s perms=%s requires=%s decision=%s",
        session.sid,
        account.username,
        sorted(r.value for r in account.roles),
        sorted(perms),
        permission,
        "allow" if permission in perms else "deny",
    )
    if not has_permission(account, permission):
        raise forbidden()
    return session


# ---------------------------------------------------------------- 登录/登出


@router.post("/auth/login")
def login(request: Request, body: LoginBody) -> JSONResponse:
    container = get_container()
    source = _client_source(request)

    # 1) 锁定检查（账号优先于来源，原因可区分）
    try:
        container.guard.check_locked(body.username, source)
    except AuthError:
        snap = container.guard.snapshot(body.username, source)
        logger.warning(
            "login: locked user=%s source=%s snapshot=%s",
            body.username,
            source,
            snap,
        )
        raise

    # 2) 凭证校验（用户不存在与密码错误给出同一结论，避免账号枚举）
    account = container.store.get_account(body.username)
    valid = account is not None and verify_password(
        body.password, account, container.settings
    )
    if not valid:
        container.guard.record_failure(body.username, source)
        snap = container.guard.snapshot(body.username, source)
        logger.warning(
            "login: invalid credentials user=%s source=%s failures=%s",
            body.username,
            source,
            snap,
        )
        from app.errors import invalid_credentials

        raise invalid_credentials()

    # 3) 成功：计数清零并创建全新会话（登录即轮换，杜绝会话固定）
    container.guard.record_success(body.username, source)
    sid, csrf_token = container.sessions.create(body.username)
    logger.info(
        "login: success user=%s source=%s new_sid=%s csrf_issued=true",
        body.username,
        source,
        sid,
    )
    response = JSONResponse(
        {"username": body.username, "csrf_token": csrf_token}
    )
    response.headers["set-cookie"] = _session_cookie(
        sid, container.settings.session_ttl_seconds
    )
    return response


@router.post("/auth/logout")
def logout(request: Request) -> JSONResponse:
    session = _authorize(request, permission=None, csrf=True)
    get_container().sessions.revoke(session.sid)
    logger.info("logout: session revoked sid=%s user=%s", session.sid, session.username)
    response = JSONResponse({"status": "logged_out"})
    response.headers["set-cookie"] = _clear_cookie()
    return response


@router.get("/auth/me")
def me(request: Request) -> JSONResponse:
    session = _authorize(request, permission=None, csrf=False)
    account = get_container().store.get_account(session.username)
    return JSONResponse(
        {
            "username": session.username,
            "roles": sorted(r.value for r in account.roles),
            "permissions": sorted(permissions_of(account)),
            "sid": session.sid,
        }
    )


# ---------------------------------------------------------------- 管理操作


@router.post("/admin/roles")
def update_roles(request: Request, body: RolesBody) -> JSONResponse:
    """修改账号角色（需 admin:users）。

    - 目标用户的既有会话立即失效（撤销），新权限即时生效，不沿用旧授权。
    - 若管理员修改的是自身角色，则当前会话就地轮换（新标识+新 CSRF），
      覆盖“权限变化时会话标识轮换”的要求。
    """
    session = _authorize(request, permission="admin:users", csrf=True)
    invalid = [name for name in body.roles if name not in _ROLE_NAMES]
    if invalid:
        raise bad_request(f"unknown roles: {invalid}")

    container = get_container()
    # 目标用户来自查询参数 ?username=；缺省为操作者自己。
    target_name = request.query_params.get("username", session.username)
    if container.store.get_account(target_name) is None:
        # 先授权后判断存在性：未授权调用方同样拿不到存在性信息。
        raise not_found()

    new_roles = {Role(name) for name in body.roles}
    container.store.set_roles(target_name, new_roles)
    logger.info(
        "roles: changed user=%s new_roles=%s by=%s",
        target_name,
        sorted(r.value for r in new_roles),
        session.username,
    )

    if target_name == session.username:
        new_sid, new_token = container.sessions.rotate(session.sid)
        logger.info(
            "roles: self change -> session rotated old=%s new=%s",
            session.sid,
            new_sid,
        )
        response = JSONResponse(
            {"username": target_name, "roles": body.roles, "csrf_token": new_token}
        )
        response.headers["set-cookie"] = _session_cookie(
            new_sid, container.settings.session_ttl_seconds
        )
        return response

    revoked = container.store.revoke_user_sessions(target_name)
    logger.info(
        "roles: target sessions revoked user=%s count=%d", target_name, len(revoked)
    )
    return JSONResponse({"username": target_name, "roles": body.roles, "revoked": revoked})


@router.post("/admin/sessions/revoke")
def admin_revoke_session(request: Request, body: RevokeBody) -> JSONResponse:
    """主动撤销会话：按 sid 撤销单个，或按 username 批量撤销。"""
    session = _authorize(request, permission="admin:users", csrf=True)
    container = get_container()
    if not body.sid and not body.username:
        raise bad_request("either sid or username is required")

    revoked: list[str] = []
    if body.sid:
        target = container.store.get_session(body.sid)
        if target is None or target.revoked:
            raise not_found()
        container.sessions.revoke(body.sid)
        revoked.append(body.sid)
    if body.username:
        revoked.extend(container.store.revoke_user_sessions(body.username))
    logger.info(
        "admin: sessions revoked by=%s targets=%s", session.username, revoked
    )
    return JSONResponse({"revoked": sorted(set(revoked))})


# ---------------------------------------------------------------- 受保护资源


@router.get("/resources/{name}")
def read_resource(request: Request, name: str) -> JSONResponse:
    # 先授权（read），再取资源：无权限一律 403，不暴露资源是否存在。
    _authorize(request, permission="resource:read", csrf=False)
    content = get_container().store.resources.get(name)
    if content is None:
        logger.info("resource: miss name=%s -> not_found (after authorization)", name)
        raise not_found()
    return JSONResponse({"name": name, "content": content})


@router.put("/resources/{name}")
def write_resource(request: Request, name: str, body: ResourceBody) -> JSONResponse:
    session = _authorize(request, permission="resource:write", csrf=True)
    get_container().store.resources[name] = body.content
    logger.info("resource: written name=%s by=%s", name, session.username)
    return JSONResponse({"name": name, "status": "saved"})
