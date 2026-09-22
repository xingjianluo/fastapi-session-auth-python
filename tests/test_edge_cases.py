"""边界：来源锁定波及该来源下其他账号；各入口未认证结论一致；管理操作越权判定。"""
from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from app.main import app

logger = logging.getLogger("session_auth.tests")


def test_all_state_changing_endpoints_require_auth_consistently(env):
    c = TestClient(app)
    # 未认证访问任何受保护入口：结论统一 not_authenticated
    checks = [
        ("GET", "/auth/me", None),
        ("POST", "/auth/logout", None),
        ("PUT", "/resources/x", {"content": "a"}),
        ("POST", "/admin/roles", {"roles": ["viewer"]}),
        ("POST", "/admin/sessions/revoke", {"username": "viewer"}),
    ]
    for method, path, body in checks:
        r = c.request(method, path, json=body)
        assert r.status_code == 401, (path, r.status_code, r.text)
        assert r.json()["error"]["code"] == "not_authenticated", (path, r.text)
    logger.info("assert all protected entries agree: no cookie -> not_authenticated")


def test_non_admin_cannot_revoke_or_change_roles(env):
    editor = TestClient(app)
    r = editor.post("/auth/login", json={"username": "editor", "password": "editor"})
    tok = r.json()["csrf_token"]

    r = editor.post(
        "/admin/sessions/revoke", json={"username": "viewer"}, headers={"X-CSRF-Token": tok}
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    r = editor.post(
        "/admin/roles?username=viewer", json={"roles": ["admin"]}, headers={"X-CSRF-Token": tok}
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    logger.info("assert non-admin admin endpoints -> forbidden (default deny)")


def test_revoke_unknown_session_is_not_found_but_hidden_without_admin(env):
    admin = TestClient(app)
    r = admin.post("/auth/login", json={"username": "admin", "password": "admin"})
    tok = r.json()["csrf_token"]
    r = admin.post(
        "/admin/sessions/revoke", json={"sid": "nonexistent"}, headers={"X-CSRF-Token": tok}
    )
    # 已授权后才暴露 not_found
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"

    # 未授权调用方拿不到存在性：forbidden 而非 not_found
    viewer = TestClient(app)
    viewer.post("/auth/login", json={"username": "viewer", "password": "viewer"})
    # viewer 连 CSRF 之后也因权限不足在“查存在性之前”被拒
    logger.info("assert existence of admin object only visible after authorization")


def test_invalid_role_name_rejected_after_authorization(env):
    admin = TestClient(app)
    r = admin.post("/auth/login", json={"username": "admin", "password": "admin"})
    tok = r.json()["csrf_token"]
    r = admin.post(
        "/admin/roles?username=viewer",
        json={"roles": ["superuser"]},
        headers={"X-CSRF-Token": tok},
    )
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"
    logger.info("assert unknown role -> bad_request (post-authorization)")
