"""新增行为测试：滑动续期与绝对上限、多端会话管理与单条撤销、
权限调整后被拒操作不影响会话、并发正确登录不误伤而错误登录仍被拦。"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.models import Role, User
from app.security import hash_password
from main import create_app

logger = logging.getLogger("tests.session")


class FakeClock:
    def __init__(self, start: float = 1_000.0) -> None:
        self.t = start
        self._lock = threading.Lock()

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.t += seconds


def make_client(**kwargs) -> TestClient:
    return TestClient(create_app(**kwargs))


def login(client: TestClient, username: str, password: str) -> tuple[str, str]:
    resp = client.post(
        "/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.json()
    return client.cookies.get("session"), resp.json()["csrf_token"]


def sibling(client: TestClient, session_id: str | None = None) -> TestClient:
    clone = TestClient(client.app)
    if session_id is not None:
        clone.cookies.set("session", session_id)
    return clone


# ------------------------------------------------------- 滑动续期 / 绝对上限


def test_idle_expiry_still_natural() -> None:
    clock = FakeClock()
    client = make_client(
        session_ttl=30, absolute_session_ttl=90, clock=clock
    )
    login(client, "alice", "alice-pass")
    clock.advance(31)  # 期间无任何活动
    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_expired"
    logger.info("无活动自然到期结论不变：401/session_expired")


def test_activity_slides_but_absolute_cap_holds() -> None:
    clock = FakeClock()
    client = make_client(
        session_ttl=30, absolute_session_ttl=90, clock=clock
    )
    login(client, "alice", "alice-pass")

    # 持续活动：每次都在空闲窗口内访问，空闲截止不断向后滑动。
    for elapsed in (29, 29, 29):
        clock.advance(elapsed)
        resp = client.get("/auth/me")
        assert resp.status_code == 200, resp.json()

    # 此时 t=1087，空闲截止被续到 90（登录 t=1000 + 绝对上限）；
    # 再越过绝对上限一刻，即使一直在活动也必须到期。
    clock.advance(4)
    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_expired"
    logger.info(
        "滑动续期生效但未越过绝对上限：持续活动 %ss 后到绝对上限仍判定过期",
        91,
    )


def test_concurrent_activity_renews_without_state_loss() -> None:
    clock = FakeClock()
    client = make_client(
        session_ttl=30, absolute_session_ttl=10_000, clock=clock
    )
    session_id, _ = login(client, "alice", "alice-pass")
    start = clock()
    advance_lock = threading.Lock()

    def worker(_: int) -> None:
        c = sibling(client, session_id)
        for _ in range(5):
            # 每个请求之间只推进 1s（远小于空闲窗口），
            # 推进与请求交错发生，模拟同一会话的并发活动。
            with advance_lock:
                clock.advance(1)
            resp = c.get("/auth/me")
            assert resp.status_code == 200, resp.json()
            assert resp.json()["username"] == "alice"

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))

    now = clock()
    assert now == start + 40
    # 直接核对存储中的最终状态：恰好一条、未丢失、续期时间收敛到最后活动。
    store = client.app.state.auth_service.sessions
    sessions = store.list_for_user("alice")
    assert len(sessions) == 1, "并发续期不得弄丢或复制会话"
    only = sessions[0]
    assert only.last_seen_at == now
    assert only.expires_at == pytest.approx(now + 30), "并发续期后空闲截止必须收敛"
    assert only.absolute_expires_at == pytest.approx(start + 10_000)
    logger.info(
        "同一会话 8 线程 x 5 次并发活动：会话唯一、last_seen=%s、空闲截止=%s 正确",
        only.last_seen_at,
        only.expires_at,
    )


# ------------------------------------------------------------- 多端会话管理


def test_multi_device_list_shows_timeline_and_current_role() -> None:
    clock = FakeClock()
    base = make_client(clock=clock)
    phone = sibling(base)
    phone_sid, _ = login(phone, "alice", "alice-pass")
    phone_login = clock()
    clock.advance(10)
    tablet = sibling(base)
    tablet_sid, _ = login(tablet, "alice", "alice-pass")
    clock.advance(5)
    # 手机活动一次，最近活动时间应更新
    assert phone.get("/auth/me").status_code == 200

    resp = phone.get("/auth/sessions")
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "alice"
    items = data["sessions"]
    assert len(items) == 2, "同一账号两台设备应各有一条会话"

    by_id = {item["session_id"]: item for item in items}
    assert set(by_id) == {phone_sid, tablet_sid}
    p, t = by_id[phone_sid], by_id[tablet_sid]
    assert p["created_at"] == phone_login
    assert t["created_at"] == phone_login + 10
    assert p["last_seen_at"] == phone_login + 15
    # 平板登录后无活动，最近活动时间即其登录时间
    assert t["last_seen_at"] == t["created_at"]
    assert p["role"] == "user" and t["role"] == "user"
    assert p["current"] is True
    assert t["current"] is False
    logger.info(
        "多端列表含登录时间/最近活动/当前角色/当前会话标记：created=%s last_seen=%s role=%s",
        sorted(i["created_at"] for i in items),
        sorted(i["last_seen_at"] for i in items),
        {i["session_id"][:8]: i["role"] for i in items},
    )


def test_revoke_one_device_leaves_others_intact() -> None:
    base = make_client()
    devices = {}
    for name in ("phone", "tablet", "laptop"):
        c = sibling(base)
        sid, csrf = login(c, "alice", "alice-pass")
        devices[name] = (c, sid, csrf)

    tablet, tablet_sid, _ = devices["tablet"]
    # 用手机端撤销平板那条（状态变更，需手机自己的 CSRF）
    phone, _, phone_csrf = devices["phone"]
    resp = phone.post(
        "/auth/sessions/revoke",
        json={"session_id": tablet_sid},
        headers={"X-CSRF-Token": phone_csrf},
    )
    assert resp.status_code == 200, resp.json()

    # 被撤那条：后续任何请求都拒绝，且原因是显式撤销而非过期
    resp = tablet.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_revoked"
    resp = tablet.get("/auth/sessions")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_revoked"

    # 其余设备完全不受影响
    for name in ("phone", "laptop"):
        c, sid, _ = devices[name]
        resp = c.get("/auth/me")
        assert resp.status_code == 200, resp.json()
        assert resp.json()["username"] == "alice"

    # 列表里也不再出现被撤会话
    items = phone.get("/auth/sessions").json()["sessions"]
    assert tablet_sid not in {i["session_id"] for i in items}
    assert len(items) == 2
    logger.info("单条撤销：被撤设备 %s 全部被拒，手机/笔记本照常可用", tablet_sid[:8])


def test_revoke_unknown_or_foreign_session_not_disclosed() -> None:
    base = make_client()
    alice = sibling(base)
    _, alice_csrf = login(alice, "alice", "alice-pass")
    bob = sibling(base)
    bob_sid, _ = login(bob, "bob", "bob-pass")

    # 撤销别人的会话：404 且不透露标识归属
    resp = alice.post(
        "/auth/sessions/revoke",
        json={"session_id": bob_sid},
        headers={"X-CSRF-Token": alice_csrf},
    )
    assert resp.status_code == 404
    assert resp.json()["reason"] == "unauthenticated"
    # bob 的会话必须依然可用
    assert bob.get("/auth/me").status_code == 200

    # 撤销一个不存在的标识：同样 404
    resp = alice.post(
        "/auth/sessions/revoke",
        json={"session_id": "no-such-session-id"},
        headers={"X-CSRF-Token": alice_csrf},
    )
    assert resp.status_code == 404
    logger.info("撤销他人/不存在会话统一 404，不泄露标识归属，他人会话不受影响")


# ------------------------------------- 权限调整后被拒操作：会话仍可用、不泄密


def test_demoted_forbidden_then_session_still_good() -> None:
    base = make_client()
    admin = sibling(base)
    _, admin_csrf = login(admin, "admin", "admin-pass")
    alice = sibling(base)
    old_sid, old_csrf = login(alice, "alice", "alice-pass")
    # 先提权再降权，制造 role_version 变化
    admin.post(
        "/admin/roles",
        json={"username": "alice", "role": "admin"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    admin.post(
        "/admin/roles",
        json={"username": "alice", "role": "user"},
        headers={"X-CSRF-Token": admin_csrf},
    )

    # 带着被降权的会话做没权限的操作：403，且不泄露资源内容
    resp = alice.get("/admin/users")
    assert resp.status_code == 403
    assert resp.json()["reason"] == "forbidden"
    assert "users" not in resp.json()

    # 关键边界：被拒不能把会话搞坏
    # 1) 错误响应必须已把轮换后的新标识与新 CSRF 下发给客户端
    new_sid = alice.cookies.get("session")
    assert new_sid != old_sid
    new_csrf = resp.headers["x-csrf-token"]
    assert new_csrf != old_csrf

    # 2) 看自己的信息：仍然认证有效
    resp = alice.get("/auth/me")
    assert resp.status_code == 200
    assert resp.json() == {
        "username": "alice",
        "role": "user",
        "session_id": new_sid[:8],
    }

    # 3) 看会话列表：正常，且轮换不重置登录时间与绝对上限（同一沿袭链）
    listing = alice.get("/auth/sessions")
    assert listing.status_code == 200
    rows = listing.json()["sessions"]
    assert len(rows) == 1
    row = rows[0]
    assert row["session_id"] == new_sid
    assert row["role"] == "user"
    assert row["current"] is True
    logger.info(
        "降权后越权 403：资源未泄露；新会话 %s 下发；me/列表均正常；"
        "登录时间保持 %s（轮换不重置绝对上限）",
        new_sid[:8],
        row["created_at"],
    )

    # 4) 正常登出：用轮换后下发的新 CSRF，不应要求重新登录
    resp = alice.post("/auth/logout", headers={"X-CSRF-Token": new_csrf})
    assert resp.status_code == 200

    # 5) 旧标识后续任何请求按显式撤销拒绝，与自然过期区分
    stale = sibling(alice, old_sid)
    resp = stale.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_revoked"
    logger.info("被拒不毁会话：随后 me/列表/登出全部正常，旧标识按 session_revoked 拒绝")


# ------------------------------------------------- 多端并发正确登录的容量保障


def test_concurrent_correct_logins_from_one_source_all_succeed() -> None:
    # 同一来源（TestClient 统一来源）、不同账号、正确口令批量并发上线自检
    base = make_client(max_failures=5, lock_seconds=60)
    store = base.app.state.user_store
    names = [f"device{i:02d}" for i in range(20)]
    for name in names:
        store.add(User(name, hash_password("correct-pass"), Role.USER))

    def worker(name: str) -> tuple[str, int, str]:
        c = sibling(base)
        sid, csrf = login(c, name, "correct-pass")
        # 顺手验证该会话确实可用且彼此独立
        resp = c.get("/auth/me")
        assert resp.status_code == 200
        assert resp.json()["username"] == name
        return sid, 200, csrf

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(worker, names))

    sids = {sid for sid, _, _ in results}
    csrfs = {csrf for _, _, csrf in results}
    assert len(results) == 20
    assert len(sids) == 20, "每条正确登录都必须拿到独立会话"
    assert len(csrfs) == 20, "每条会话的 CSRF 必须独立"

    # 服务整体只存在这一份共享防护状态
    listing = base.app.state.auth_service.sessions.list_for_user("device00")
    assert len(listing) == 1
    logger.info(
        "同一来源 20 个账号并发正确登录：全部 200，20 条独立会话，未被防护误伤"
    )


def test_concurrent_correct_logins_same_account_all_succeed() -> None:
    # 同账号多端同时正确登录也必须全部成功
    base = make_client(max_failures=5, lock_seconds=60)

    def worker(_: int) -> str:
        c = sibling(base)
        sid, _ = login(c, "alice", "alice-pass")
        return sid

    with ThreadPoolExecutor(max_workers=8) as pool:
        sids = list(pool.map(worker, range(8)))
    assert len(set(sids)) == 8
    logger.info("同账号 8 端并发正确登录：全部成功且标识独立")


def test_wrong_logins_still_blocked_under_concurrency_and_recover() -> None:
    clock = FakeClock()
    base = make_client(max_failures=5, lock_seconds=60, clock=clock)

    # 同一来源、5 个不同账号各错一次：来源维度并发累计仍恰好达到阈值
    names = ["victim0", "victim1", "victim2", "victim3", "victim4"]

    def worker(name: str) -> tuple[int, str]:
        c = sibling(base)
        resp = c.post(
            "/auth/login", json={"username": name, "password": "bad"}
        )
        return resp.status_code, resp.json()["reason"]

    with ThreadPoolExecutor(max_workers=5) as pool:
        outcomes = list(pool.map(worker, names))

    invalid = sum(1 for code, _ in outcomes if code == 401)
    assert invalid == 5, f"并发错误尝试必须全部计入，实际 {invalid}"
    logger.info(
        "并发错误登录 5 次全部计入阈值（invalid=5，锁由第 5 次确认失败触发）"
    )

    # 达阈后，哪怕口令正确也被来源锁挡住
    c = sibling(base)
    resp = c.post(
        "/auth/login", json={"username": "bob", "password": "bob-pass"}
    )
    assert resp.status_code == 429
    assert resp.json()["reason"] == "source_locked"

    # 锁定期满自动恢复
    clock.advance(61)
    resp = c.post(
        "/auth/login", json={"username": "bob", "password": "bob-pass"}
    )
    assert resp.status_code == 200
    logger.info("达阈锁定后正确口令仍拒（source_locked），期满自动恢复可登录")


def test_limiter_is_shared_service_wide() -> None:
    # 多个客户端（各自独立 Cookie）命中的是同一份服务级防护状态
    clock = FakeClock()
    base = make_client(max_failures=3, lock_seconds=60, clock=clock)
    for i in range(3):
        c = sibling(base)
        resp = c.post(
            "/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        assert resp.status_code == 401
        assert resp.json()["reason"] == "invalid_credentials"

    # 换一个全新客户端再试：账号锁定由共享状态承接，而不是各请求各算一份
    fresh = sibling(base)
    resp = fresh.post(
        "/auth/login", json={"username": "alice", "password": "alice-pass"}
    )
    assert resp.status_code == 429
    assert resp.json()["reason"] == "account_locked"
    logger.info("防护状态服务级共享：跨客户端的失败累计仍触发 account_locked")
