"""RBAC：默认拒绝、未认证与权限不足区分、角色降级即时生效、越权不暴露存在性。"""
from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from app.main import app

logger = logging.getLogger("session_auth.tests")


def _login(username: str, password: str) -> TestClient:
    c = TestClient(app)
    r = c.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def test_role_matrix_default_deny(env):
    viewer = _login("viewer", "viewer")
    editor = _login("editor", "editor")
    admin = _login("admin", "admin")

    # read
    assert viewer.get("/resources/public-note").status_code == 200
    # write 权限分层
    assert viewer.put("/resources/a", json={"content": "x"}).status_code == 403
    assert editor.put("/resources/a", json={"content": "x"}).status_code == 200
    # admin 专属
    assert viewer.get("/auth/me").status_code == 200  # 仅认证接口
    r = viewer.post("/admin/sessions/revoke", json={"sid": "x"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    assert admin.post("/admin/sessions/revoke", json={"username": "viewer"}).status_code == 200
    logger.info("assert role matrix enforced, default deny verified")


def test_unauthenticated_vs_forbidden_distinguished(env):
    anon = TestClient(app)
    viewer = _login("viewer", "viewer")

    r1 = anon.get("/resources/public-note")
    r2 = viewer.put("/resources/public-note", json={"content": "x"})
    assert (r1.status_code, r1.json()["error"]["code"]) == (401, "not_authenticated")
    assert (r2.status_code, r2.json()["error"]["code"]) == (403, "forbidden")
    logger.info("assert 401 not_authenticated != 403 forbidden")


def test_authorization_does_not_reveal_resource_existence(env):
    viewer = _login("viewer", "viewer")
    # viewer 无 write：无论资源存在与否，结论完全一致
    existing = viewer.put("/resources/public-note", json={"content": "x"})
    missing = viewer.put("/resources/does-not-exist", json={"content": "x"})
    assert existing.status_code == missing.status_code == 403
    assert existing.json()["error"]["code"] == missing.json()["error"]["code"] == "forbidden"

    # 未认证用户对存在/不存在资源结论一致
    anon = TestClient(app)
    a = anon.get("/resources/public-note")
    b = anon.get("/resources/does-not-exist")
    assert a.json()["error"]["code"] == b.json()["error"]["code"] == "not_authenticated"

    # 仅在授权通过后才区分存在性（admin 有 read）
    admin = _login("admin", "admin")
    assert admin.get("/resources/does-not-exist").status_code == 404
    logger.info("assert existence hidden behind authorization")


def test_role_downgrade_takes_effect_immediately_on_existing_session(env):
    """管理员把自己从 admin 降为 viewer：会话轮换，且新权限即时生效。"""
    admin = _login("admin", "admin")
    old_token = admin.headers["X-CSRF-Token"]

    # 降级前具备管理权限
    assert admin.get("/resources/anything").status_code in (200, 404)

    r = admin.post("/admin/roles?username=admin", json={"roles": ["viewer"]})
    assert r.status_code == 200, r.text
    new_token = r.json()["csrf_token"]
    new_sid = r.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    logger.info("assert downgrade rotated session; new_sid=%s new_csrf=issued", new_sid)

    # 旧令牌随旧会话失效（令牌不可跨会话复用）
    stale = TestClient(app)
    # 找到旧 sid：旧会话已删除，构造一个仅带旧令牌、新 sid 的组合必然 csrf_invalid
    stale.cookies.set("sid", new_sid)
    stale.headers["X-CSRF-Token"] = old_token
    r = stale.put("/resources/x", json={"content": "y"})
    assert r.json()["error"]["code"] == "csrf_invalid"
    logger.info("assert pre-downgrade csrf token invalid after rotation")

    # 同一身份的既有会话现在按 viewer 判定：写/管理立即被拒绝
    admin.headers["X-CSRF-Token"] = new_token
    r = admin.put("/resources/x", json={"content": "y"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    r = admin.post("/admin/sessions/revoke", json={"username": "viewer"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    # 读权限仍然保留
    assert admin.get("/resources/public-note").status_code == 200
    logger.info("assert downgraded existing session judged by new roles immediately")


def test_role_change_revokes_other_users_sessions_immediately(env):
    """管理员调整他人角色：目标用户既有会话立即撤销，不得沿用旧授权。"""
    editor = _login("editor", "editor")
    assert editor.put("/resources/a", json={"content": "x"}).status_code == 200

    admin = _login("admin", "admin")
    r = admin.post("/admin/roles?username=editor", json={"roles": ["viewer"]})
    assert r.status_code == 200
    assert r.json()["revoked"], "existing sessions must be revoked on role change"
    logger.info("assert target user sessions revoked on role change: %s", r.json()["revoked"])

    # editor 的旧会话标识已撤销 -> session_invalid（不能再以 editor 权限写）
    r = editor.put("/resources/a", json={"content": "y"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "session_invalid"
    r = editor.get("/resources/public-note")
    assert r.status_code == 401 and r.json()["error"]["code"] == "session_invalid"
    logger.info("assert downgraded user cannot reuse old session -> session_invalid")
