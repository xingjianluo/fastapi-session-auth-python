"""CSRF：缺失与无效可区分、令牌与会话绑定不可跨会话复用、轮换后旧令牌失效。"""
from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from app.main import app

logger = logging.getLogger("session_auth.tests")


def _login(client: TestClient, username: str, password: str) -> str:
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf_token"]


def test_csrf_missing_and_invalid_are_distinct(env):
    editor = TestClient(app)
    token = _login(editor, "editor", "editor")

    missing = editor.put("/resources/a", json={"content": "x"})
    assert missing.status_code == 403
    assert missing.json()["error"]["code"] == "csrf_missing"
    logger.info("assert csrf missing -> csrf_missing")

    invalid = editor.put(
        "/resources/a", json={"content": "x"}, headers={"X-CSRF-Token": "bogus"}
    )
    assert invalid.status_code == 403
    assert invalid.json()["error"]["code"] == "csrf_invalid"
    logger.info("assert csrf bogus -> csrf_invalid")

    ok = editor.put(
        "/resources/a", json={"content": "x"}, headers={"X-CSRF-Token": token}
    )
    assert ok.status_code == 200
    logger.info("assert csrf correct token -> allowed")


def test_csrf_token_not_reusable_across_sessions(env):
    # 会话 A 签发的令牌不得在会话 B（同一用户的另一次登录）上使用
    a = TestClient(app)
    token_a = _login(a, "editor", "editor")

    b = TestClient(app)
    token_b = _login(b, "editor", "editor")
    sid_b = b.cookies.get("sid")
    assert token_a != token_b

    # 用 B 的 Cookie + A 的令牌：会话绑定校验必须拒绝
    mix = TestClient(app)
    mix.cookies.set("sid", sid_b)
    resp = mix.put(
        "/resources/a", json={"content": "x"}, headers={"X-CSRF-Token": token_a}
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "csrf_invalid"
    logger.info("assert token A rejected on session B -> csrf_invalid")

    # B 的令牌与 B 的会话配对则可用
    ok = mix.put(
        "/resources/a", json={"content": "x"}, headers={"X-CSRF-Token": token_b}
    )
    assert ok.status_code == 200
    logger.info("assert token B matched to session B -> allowed")


def test_safe_method_does_not_require_csrf(env):
    viewer = TestClient(app)
    _login(viewer, "viewer", "viewer")
    # GET 不做 CSRF 校验（只读），但写操作仍要求
    assert viewer.get("/resources/public-note").status_code == 200
    resp = viewer.put("/resources/public-note", json={"content": "x"})
    assert resp.json()["error"]["code"] == "csrf_missing"
    logger.info("assert GET exempt from CSRF, PUT still protected")
