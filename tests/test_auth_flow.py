"""认证流程：登录、登出、错误归类、登录轮换（防会话固定）。"""
from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from app.main import app

logger = logging.getLogger("session_auth.tests")


def login(client: TestClient, username: str, password: str):
    resp = client.post("/auth/login", json={"username": username, "password": password})
    logger.info("test login user=%s status=%s", username, resp.status_code)
    return resp


def test_unauthenticated_is_distinct_from_forbidden(env, client):
    # 未认证：无 Cookie -> 401 not_authenticated（与 403 forbidden 区分）
    resp = client.get("/resources/public-note")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "not_authenticated"
    logger.info("assert unauthenticated -> %s", resp.json())


def test_login_success_issues_session_and_csrf(env, client):
    resp = login(client, "viewer", "viewer")
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "viewer"
    assert body["csrf_token"]
    assert "sid=" in resp.headers.get("set-cookie", "")
    logger.info("assert issued csrf+cookie sid_cookie_present=true")


def test_invalid_password_is_invalid_credentials(env, client):
    resp = login(client, "viewer", "wrong")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_credentials"
    logger.info("assert bad password -> %s", resp.json())


def test_unknown_user_same_error_as_bad_password(env, client):
    # 用户不存在与密码错误结论一致，避免账号枚举
    r1 = login(client, "viewer", "wrong")
    r2 = login(client, "ghost", "ghost")
    assert r1.json()["error"]["code"] == r2.json()["error"]["code"] == "invalid_credentials"
    logger.info("assert enumeration-safe: both invalid_credentials")


def test_login_rotates_identifier_no_fixation(env, client):
    # 预置一个“攻击者已知”的会话标识：登录必须签发全新标识
    client.cookies.jar.clear_session_cookies()
    client.cookies.jar.clear()
    client.cookies.set("sid", "attacker-fixed-sid")
    resp = login(client, "viewer", "viewer")
    assert resp.status_code == 200
    # 登录响应中的 Set-Cookie 即新标识，且与预置值不同
    new_sid = resp.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    assert new_sid and new_sid != "attacker-fixed-sid"
    logger.info("assert login issued fresh sid different from attacker-fixed value")

    # 旧标识永远不可用：用只携带旧标识的独立客户端验证
    attacker = TestClient(app)
    attacker.cookies.jar.clear_session_cookies()
    attacker.cookies.jar.clear()
    attacker.cookies.set("sid", "attacker-fixed-sid")
    resp = attacker.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "session_invalid"
    logger.info("assert session fixation prevented: attacker sid rejected")


def test_logout_revokes_and_clears_cookie(env, client):
    resp = login(client, "viewer", "viewer")
    token = resp.json()["csrf_token"]
    sid = client.cookies.get("sid")

    resp = client.post("/auth/logout", headers={"X-CSRF-Token": token})
    assert resp.status_code == 200
    logger.info("assert logout ok; sid=%s revoked", sid)

    # 仍持有已撤销标识 -> session_invalid（与未认证可区分）
    reuser = TestClient(app)
    reuser.cookies.set("sid", sid)
    resp = reuser.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "session_invalid"
    logger.info("assert revoked sid reuse -> session_invalid")


def test_logout_requires_csrf(env, client):
    login(client, "viewer", "viewer")
    resp = client.post("/auth/logout")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "csrf_missing"
    logger.info("assert logout without csrf -> csrf_missing")
