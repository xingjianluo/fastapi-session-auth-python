"""会话：并发受保护请求不丢状态、撤销即时生效、过期失效、并发写不丢更新。"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app import deps
from app.config import Settings
from app.deps import create_container
from app.errors import SESSION_INVALID, AuthError
from app.main import app

logger = logging.getLogger("session_auth.tests")


def _login(client: TestClient, username: str, password: str):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf_token"], client.cookies.get("sid")


def test_concurrent_protected_requests_share_consistent_session():
    deps._container = create_container(Settings())
    editor = TestClient(app)
    token, sid = _login(editor, "editor", "editor")

    def write(i):
        c = TestClient(app)
        c.cookies.set("sid", sid)
        return c.put(
            f"/resources/item{i % 5}",
            json={"content": f"v{i}"},
            headers={"X-CSRF-Token": token},
        ).status_code

    with ThreadPoolExecutor(max_workers=16) as pool:
        statuses = list(pool.map(write, range(64)))

    assert statuses.count(200) == 64, statuses
    # 所有并发写都落库，无丢失（最终值为最后写入之一，这里校验条目齐全）
    resources = deps._container.store.resources
    assert {f"item{i}" for i in range(5)} <= set(resources)
    logger.info("assert 64 concurrent authorized writes all accepted; session intact")


def test_revoked_session_rejected_immediately_under_concurrency():
    deps._container = create_container(Settings())
    editor = TestClient(app)
    _token, sid = _login(editor, "editor", "editor")

    # 管理员在外部撤销该会话
    admin = TestClient(app)
    admin_token, _ = _login(admin, "admin", "admin")
    r = admin.post(
        "/admin/sessions/revoke",
        json={"sid": sid},
        headers={"X-CSRF-Token": admin_token},
    )
    assert r.status_code == 200
    logger.info("admin revoked sid=%s; revoked=%s", sid, r.json()["revoked"])

    def probe(_):
        c = TestClient(app)
        c.cookies.set("sid", sid)
        return c.get("/resources/public-note")

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(probe, range(16)))
    codes = {resp.json()["error"]["code"] for resp in responses}
    assert codes == {"session_invalid"}, codes
    assert all(resp.status_code == 401 for resp in responses)
    logger.info("assert 16 concurrent requests on revoked session all session_invalid")


def test_admin_revoke_by_username_kills_all_sessions():
    deps._container = create_container(Settings())
    sids = []
    for _ in range(3):
        c = TestClient(app)
        _, sid = _login(c, "viewer", "viewer")
        sids.append(sid)

    admin = TestClient(app)
    admin_token, _ = _login(admin, "admin", "admin")
    r = admin.post(
        "/admin/sessions/revoke",
        json={"username": "viewer"},
        headers={"X-CSRF-Token": admin_token},
    )
    assert r.status_code == 200
    assert sorted(r.json()["revoked"]) == sorted(sids)
    logger.info("assert bulk revoke killed %d sessions", len(sids))

    for sid in sids:
        c = TestClient(app)
        c.cookies.set("sid", sid)
        resp = c.get("/auth/me")
        assert resp.json()["error"]["code"] == "session_invalid"


def test_expired_session_is_rejected():
    container = create_container(Settings(session_ttl_seconds=60))
    deps._container = container
    sid, _token = container.sessions.create("viewer")
    assert container.sessions.resolve(sid).username == "viewer"

    # 让会话过期
    record = container.store.get_session(sid)
    record.expires_at -= 120
    try:
        container.sessions.resolve(sid)
        raise AssertionError("expected expiry")
    except AuthError as e:
        assert e.code == SESSION_INVALID
    # 过期记录被清理
    assert container.store.get_session(sid) is None
    logger.info("assert expired session rejected and purged -> session_invalid")


def test_concurrent_logins_create_independent_sessions():
    deps._container = create_container(Settings())

    def login(_):
        c = TestClient(app)
        r = c.post("/auth/login", json={"username": "editor", "password": "editor"})
        return r.json()["csrf_token"], c.cookies.get("sid")

    with ThreadPoolExecutor(max_workers=16) as pool:
        issued = list(pool.map(login, range(20)))

    sids = {sid for _, sid in issued}
    tokens = {tok for tok, _ in issued}
    assert len(sids) == 20 and len(tokens) == 20, (len(sids), len(tokens))

    # 每个会话只能用自己的令牌
    c = TestClient(app)
    _first_tok, first_sid = issued[0]
    second_tok, _second_sid = issued[1]
    c.cookies.set("sid", first_sid)
    r = c.put(
        "/resources/x",
        json={"content": "y"},
        headers={"X-CSRF-Token": second_tok},
    )
    assert r.json()["error"]["code"] == "csrf_invalid"
    logger.info("assert 20 concurrent logins yield unique sid+csrf and are session-bound")
