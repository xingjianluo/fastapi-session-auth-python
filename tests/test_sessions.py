"""会话续期（滑动 + 绝对上限）与并发续期一致性的测试。"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from main import create_app

logger = logging.getLogger("tests.sessions")


class FakeClock:
    def __init__(self, start: float = 1_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_client(**kwargs) -> TestClient:
    return TestClient(create_app(**kwargs))


def login(client: TestClient, username: str, password: str) -> tuple[str, str]:
    resp = client.post(
        "/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.json()
    session_id = client.cookies.get("session")
    csrf = resp.json()["csrf_token"]
    logger.info(
        "登录成功 user=%s session=%s csrf=%s",
        username,
        session_id[:8],
        csrf[:8],
    )
    return session_id, csrf


def sibling(client: TestClient, session_id: str | None = None) -> TestClient:
    """在同一应用实例上另开客户端（独立 Cookie 罐），模拟另一台设备。"""
    clone = TestClient(client.app)
    if session_id is not None:
        clone.cookies.set("session", session_id)
    return clone


# ---------------------------------------------------------------- 滑动续期


def test_activity_renews_session_within_absolute_cap() -> None:
    """持续活动会续期，但续期不得越过从登录算起的绝对上限。"""
    clock = FakeClock()
    client = make_client(
        session_ttl=30, session_absolute_ttl=100, clock=clock
    )
    login(client, "alice", "alice-pass")
    # 登录时刻 t=1000：滑动到期 1030，绝对上限 1100。

    # 持续活动：每次访问都在上一个滑动窗口内，会话一直被续期，
    # 总存活远超一个 TTL（30s）。
    for t in (1020, 1040, 1060, 1080):
        clock.t = t
        resp = client.get("/auth/me")
        assert resp.status_code == 200, (t, resp.json())
    logger.info(
        "持续活动至 t=1080（已超 3 个 TTL）会话仍有效：滑动续期生效"
    )

    # 临近绝对上限：滑动顺延被 cap 在绝对上限上。
    clock.t = 1095
    resp = client.get("/auth/sessions")
    assert resp.status_code == 200
    entry = resp.json()["sessions"][0]
    assert entry["expires_at"] == entry["absolute_expires_at"] == 1100.0
    assert entry["last_activity_at"] == 1095
    logger.info(
        "t=1095 续期被绝对上限截断：expires_at=%s absolute=%s",
        entry["expires_at"],
        entry["absolute_expires_at"],
    )

    # 越过绝对上限：即使刚刚还在活动，会话也按绝对上限到期。
    clock.t = 1100.001
    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_expired"
    logger.info(
        "越过绝对上限 t=1100：活动中的会话仍到期，结论 401/session_expired"
    )


def test_idle_session_expires_naturally() -> None:
    """续期只发生在受保护访问时：停止活动后按原方式自然到期。"""
    clock = FakeClock()
    client = make_client(
        session_ttl=30, session_absolute_ttl=1000, clock=clock
    )
    login(client, "alice", "alice-pass")

    clock.advance(25)
    resp = client.get("/auth/me")  # 续期一次：到期顺延至 t+30
    assert resp.status_code == 200

    clock.advance(31)  # 之后不再活动：超过滑动窗口
    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_expired"
    logger.info(
        "续期一次后停止活动 31s：会话自然到期 401/session_expired，"
        "与绝对上限无关"
    )


# ---------------------------------------------------------------- 并发续期


def test_concurrent_access_renewal_consistent() -> None:
    """同一会话的并发访问：续期算术正确，会话状态不丢、不复制。"""
    clock = FakeClock()
    client = make_client(
        session_ttl=30, session_absolute_ttl=300, clock=clock
    )
    session_id, _ = login(client, "alice", "alice-pass")

    def wave(at: float) -> None:
        clock.t = at

        def worker(_: int) -> None:
            c = sibling(client, session_id)
            for _ in range(5):
                resp = c.get("/auth/me")
                assert resp.status_code == 200, resp.json()

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(8)))

    wave(1020)
    resp = client.get("/auth/sessions")
    sessions = resp.json()["sessions"]
    assert len(sessions) == 1, "并发访问不得复制或弄丢会话"
    entry = sessions[0]
    assert entry["last_activity_at"] == 1020
    assert entry["expires_at"] == 1050  # 1020 + TTL，续期算术正确
    logger.info(
        "8 线程 x 5 次并发访问后：会话唯一，last_activity=%s expires=%s",
        entry["last_activity_at"],
        entry["expires_at"],
    )

    # 临近滑动到期再来一波并发：会话仍有效并再次顺延。
    wave(1049)
    resp = client.get("/auth/sessions")
    entry = resp.json()["sessions"][0]
    assert entry["last_activity_at"] == 1049
    assert entry["expires_at"] == 1079
    logger.info(
        "临近到期的并发访问后续期正确：expires=%s（=1049+30）",
        entry["expires_at"],
    )


# ---------------------------------------------------------------- 多端会话管理


def test_multi_device_list_and_revoke_single() -> None:
    """多端登录可见会话列表；只撤指定一条，其余完全不受影响。"""
    base = make_client()
    d1 = sibling(base)
    sid1, csrf1 = login(d1, "alice", "alice-pass")
    d2 = sibling(base)
    sid2, _ = login(d2, "alice", "alice-pass")
    d3 = sibling(base)
    sid3, _ = login(d3, "alice", "alice-pass")
    assert len({sid1, sid2, sid3}) == 3, "每台设备必须拿到独立会话"

    resp = d1.get("/auth/sessions")
    assert resp.status_code == 200
    entries = resp.json()["sessions"]
    assert {e["session_id"] for e in entries} == {sid1, sid2, sid3}
    for e in entries:
        # 每条能看出大致登录时间、最近活动时间与当前权限。
        assert e["created_at"] > 0
        assert e["last_activity_at"] >= e["created_at"]
        assert e["role"] == "user"
    current = [e for e in entries if e["current"]]
    assert len(current) == 1 and current[0]["session_id"] == sid1
    logger.info(
        "多端列表：3 条会话可见（登录时间/最近活动/权限/current 标记齐全）"
    )

    # 只撤掉 d2 那一条。
    resp = d1.delete(
        f"/auth/sessions/{sid2}", headers={"X-CSRF-Token": csrf1}
    )
    assert resp.status_code == 200

    # 被撤掉的那条：后续任何请求被拒，且与自然过期可区分。
    resp = d2.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_revoked"
    assert resp.json()["reason"] != "session_expired"

    # 其余两条照常可用、完全不受影响。
    assert d1.get("/auth/me").status_code == 200
    assert d3.get("/auth/me").status_code == 200

    resp = d1.get("/auth/sessions")
    assert {e["session_id"] for e in resp.json()["sessions"]} == {sid1, sid3}
    logger.info(
        "单条撤销：被撤会话 401/session_revoked（与自然过期可区分），"
        "其余两条不受影响"
    )


def test_revoke_requires_ownership_and_csrf() -> None:
    """撤销语义：只能撤自己的会话；缺失 CSRF 被拒；目标不存在不泄露。"""
    base = make_client()
    alice = sibling(base)
    _, alice_csrf = login(alice, "alice", "alice-pass")
    bob = sibling(base)
    bob_sid, _ = login(bob, "bob", "bob-pass")

    # 缺 CSRF：状态变更必须先过 CSRF 校验。
    resp = alice.delete(f"/auth/sessions/{bob_sid}")
    assert resp.status_code == 403
    assert resp.json()["reason"] == "csrf_missing"

    # 他人的会话：按“不存在”处理，不泄露其存在性，且目标不受影响。
    resp = alice.delete(
        f"/auth/sessions/{bob_sid}", headers={"X-CSRF-Token": alice_csrf}
    )
    assert resp.status_code == 404
    assert resp.json()["reason"] == "session_not_found"
    assert bob.get("/auth/me").status_code == 200

    # 不存在的标识：同样 404。
    resp = alice.delete(
        "/auth/sessions/no-such-session",
        headers={"X-CSRF-Token": alice_csrf},
    )
    assert resp.status_code == 404
    assert resp.json()["reason"] == "session_not_found"
    logger.info(
        "撤销边界：缺 CSRF=403/csrf_missing，他人或不存在=404/"
        "session_not_found，目标会话不受影响"
    )


# ---------------------------------------------------------------- 降权后被拒操作会话仍可用


def test_forbidden_after_downgrade_session_survives() -> None:
    """降权后越权操作被拒（不泄露资源），但会话本身仍然有效。"""
    base = make_client()
    admin = sibling(base)
    _, admin_csrf = login(admin, "admin", "admin-pass")
    alice = sibling(base)
    old_sid, _ = login(alice, "alice", "alice-pass")

    # 先提权再降权，制造“权限刚被调低”的场景。
    for role in ("admin", "user"):
        resp = admin.post(
            "/admin/roles",
            json={"username": "alice", "role": role},
            headers={"X-CSRF-Token": admin_csrf},
        )
        assert resp.status_code == 200

    # alice 带着既有会话去做没权限的操作：立即按新权限被拒。
    resp = alice.get("/admin/users")
    assert resp.status_code == 403
    assert resp.json()["reason"] == "forbidden"
    assert "users" not in resp.json(), "越权不得泄露资源内容"
    # 被拒的响应也要把轮换后的新会话标识与 CSRF 令牌带给客户端。
    new_sid = alice.cookies.get("session")
    assert new_sid != old_sid, "权限变化已轮换会话标识"
    new_csrf = resp.headers["x-csrf-token"]
    logger.info(
        "降权后越权被拒：403/forbidden 且未泄露资源；"
        "新会话标识随错误响应下发 old=%s new=%s",
        old_sid[:8],
        new_sid[:8],
    )

    # 关键：那次被拒之后，会话本身还得是好的。
    resp = alice.get("/auth/me")
    assert resp.status_code == 200, resp.json()
    resp = alice.get("/auth/sessions")
    assert resp.status_code == 200, resp.json()
    resp = alice.post("/auth/logout", headers={"X-CSRF-Token": new_csrf})
    assert resp.status_code == 200, resp.json()
    logger.info(
        "被拒操作之后：看自己的信息、看会话列表、正常登出全部可用，"
        "无需重新登录"
    )

    # 登出后会话才真正失效：本端 Cookie 已清除；
    # 拿着登出前的标识重放则命中墓碑，与自然过期可区分。
    resp = alice.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "unauthenticated"
    stale = sibling(alice, new_sid)
    resp = stale.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_revoked"
