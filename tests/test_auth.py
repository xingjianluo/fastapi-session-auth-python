"""会话认证与授权测试：并发、撤销、CSRF、锁定、角色变更即时生效。"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from main import create_app

logger = logging.getLogger("tests.auth")


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
    """在同一应用实例上另开客户端（独立 Cookie 罐），模拟另一浏览器。"""
    clone = TestClient(client.app)
    if session_id is not None:
        clone.cookies.set("session", session_id)
    return clone


# ---------------------------------------------------------------- 基础结论


def test_unauthenticated_vs_forbidden() -> None:
    client = make_client()
    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "unauthenticated"

    login(client, "alice", "alice-pass")
    resp = client.get("/admin/users")
    assert resp.status_code == 403
    assert resp.json()["reason"] == "forbidden"
    logger.info("未认证=401/unauthenticated，权限不足=403/forbidden，可区分")


def test_admin_can_list_users() -> None:
    client = make_client()
    login(client, "admin", "admin-pass")
    resp = client.get("/admin/users")
    assert resp.status_code == 200
    assert "alice" in resp.json()["users"]


# ---------------------------------------------------------------- 并发


def test_concurrent_logins_unique_sessions() -> None:
    results: list[tuple[str, str]] = []

    def worker(_: int) -> tuple[str, str]:
        client = make_client()
        return login(client, "alice", "alice-pass")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(8)))

    session_ids = {sid for sid, _ in results}
    csrf_tokens = {token for _, token in results}
    assert len(session_ids) == 8, "并发登录不得复用同一会话标识"
    assert len(csrf_tokens) == 8, "每个会话的 CSRF 令牌必须独立"
    logger.info("并发登录 8 次，会话标识与 CSRF 令牌全部唯一")


def test_concurrent_protected_requests_no_state_loss() -> None:
    client = make_client()
    session_id, _ = login(client, "alice", "alice-pass")

    def worker(_: int) -> int:
        c = sibling(client, session_id)
        for _ in range(5):
            resp = c.get("/auth/me")
            assert resp.status_code == 200, resp.json()
            assert resp.json()["username"] == "alice"
        return 200

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(worker, range(8)))
    assert codes == [200] * 8
    logger.info("同一会话 8 线程 x 5 次受保护请求全部成功，无状态丢失")


def test_concurrent_failures_count_not_lost() -> None:
    clock = FakeClock()
    client = make_client(max_failures=5, lock_seconds=60, clock=clock)

    def worker(_: int) -> tuple[int, str]:
        resp = client.post(
            "/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        return resp.status_code, resp.json()["reason"]

    with ThreadPoolExecutor(max_workers=10) as pool:
        outcomes = list(pool.map(worker, range(10)))

    invalid = sum(1 for _, r in outcomes if r == "invalid_credentials")
    locked = sum(1 for _, r in outcomes if r == "account_locked")
    logger.info("并发失败结果分布 invalid=%s locked=%s", invalid, locked)
    assert invalid == 5, "计数不丢失：恰好 5 次计入阈值"
    assert locked == 5, "达到阈值后其余请求必须被锁定拦截，不得超额放行"


# ---------------------------------------------------------------- 撤销与过期


def test_revoked_session_reuse_rejected() -> None:
    client = make_client()
    session_id, csrf = login(client, "alice", "alice-pass")
    resp = client.post("/auth/logout", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200

    stale = sibling(client, session_id)
    resp = stale.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_revoked"
    logger.info("已撤销会话复用被拒：401/session_revoked")


def test_admin_revoke_user_sessions() -> None:
    base = make_client()
    admin = sibling(base)
    _, admin_csrf = login(admin, "admin", "admin-pass")

    alice = sibling(base)
    alice_session, _ = login(alice, "alice", "alice-pass")

    resp = admin.post(
        "/admin/revoke",
        json={"username": "alice"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert resp.status_code == 200
    assert resp.json()["revoked"] >= 1

    resp = alice.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_revoked"
    logger.info("管理员主动撤销后，会话 %s 立即失效", alice_session[:8])


def test_session_expired() -> None:
    clock = FakeClock()
    client = make_client(session_ttl=30, clock=clock)
    login(client, "alice", "alice-pass")
    clock.advance(31)
    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_expired"
    logger.info("会话过期结论：401/session_expired")


# ---------------------------------------------------------------- CSRF


def test_csrf_missing_invalid_cross_session() -> None:
    base = make_client()
    alice = sibling(base)
    _, alice_csrf = login(alice, "alice", "alice-pass")
    bob = sibling(base)
    _, bob_csrf = login(bob, "bob", "bob-pass")

    resp = alice.post("/auth/logout")
    assert resp.status_code == 403
    assert resp.json()["reason"] == "csrf_missing"

    resp = alice.post("/auth/logout", headers={"X-CSRF-Token": "garbage"})
    assert resp.status_code == 403
    assert resp.json()["reason"] == "csrf_invalid"

    resp = alice.post("/auth/logout", headers={"X-CSRF-Token": bob_csrf})
    assert resp.status_code == 403
    assert resp.json()["reason"] == "csrf_cross_session"
    logger.info(
        "CSRF 三类失败可区分：missing=%s invalid=%s cross=%s",
        "csrf_missing",
        "csrf_invalid",
        "csrf_cross_session",
    )

    resp = alice.post("/auth/logout", headers={"X-CSRF-Token": alice_csrf})
    assert resp.status_code == 200


# ---------------------------------------------------------------- 暴力破解防护


def test_account_lock_and_auto_recovery() -> None:
    clock = FakeClock()
    client = make_client(max_failures=5, lock_seconds=60, clock=clock)

    for i in range(5):
        resp = client.post(
            "/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        assert resp.status_code == 401
        assert resp.json()["reason"] == "invalid_credentials"

    resp = client.post(
        "/auth/login", json={"username": "alice", "password": "wrong"}
    )
    assert resp.status_code == 429
    assert resp.json()["reason"] == "account_locked"

    # 锁定期间即使口令正确也拒绝，原因可区分。
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice-pass"},
    )
    assert resp.status_code == 429
    assert resp.json()["reason"] == "account_locked"

    clock.advance(61)
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice-pass"},
    )
    assert resp.status_code == 200
    logger.info("锁定期满自动恢复，正常请求不再被拒")


def test_source_lock_independent_of_account() -> None:
    clock = FakeClock()
    client = make_client(max_failures=3, lock_seconds=60, clock=clock)
    # 同一来源对不同账号各失败一次，累计触发来源锁定。
    for name in ("alice", "bob", "carol"):
        resp = client.post(
            "/auth/login", json={"username": name, "password": "wrong"}
        )
        assert resp.status_code == 401
    resp = client.post(
        "/auth/login", json={"username": "dave", "password": "wrong"}
    )
    assert resp.status_code == 429
    assert resp.json()["reason"] == "source_locked"
    logger.info("来源维度独立锁定：429/source_locked")


# ---------------------------------------------------------------- 角色变更即时生效


def test_role_change_immediate_and_rotation(caplog) -> None:
    caplog.set_level(logging.INFO)
    base = make_client()
    admin = sibling(base)
    _, admin_csrf = login(admin, "admin", "admin-pass")
    alice = sibling(base)
    old_session, old_csrf = login(alice, "alice", "alice-pass")

    resp = alice.get("/admin/users")
    assert resp.status_code == 403
    assert resp.json()["reason"] == "forbidden"

    # 提升为 admin：既有会话立即按新权限放行，且会话标识被轮换。
    resp = admin.post(
        "/admin/roles",
        json={"username": "alice", "role": "admin"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert resp.status_code == 200

    resp = alice.get("/admin/users")
    assert resp.status_code == 200
    new_session = alice.cookies.get("session")
    assert new_session != old_session, "权限变化必须轮换会话标识"
    new_csrf = resp.headers["x-csrf-token"]
    assert new_csrf != old_csrf, "轮换后 CSRF 令牌同步更换"
    logger.info(
        "提权后轮换 old=%s new=%s，既有会话立即获得新权限",
        old_session[:8],
        new_session[:8],
    )

    # 旧标识已立墓碑，复用被拒。
    stale = sibling(alice, old_session)
    resp = stale.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_revoked"

    # 降级为 user：既有会话立即失去权限，越权结论为 403/forbidden。
    resp = admin.post(
        "/admin/roles",
        json={"username": "alice", "role": "user"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert resp.status_code == 200
    resp = alice.get("/admin/users")
    assert resp.status_code == 403
    assert resp.json()["reason"] == "forbidden"
    assert "users" not in resp.json(), "越权不得暴露受保护资源内容"
    logger.info("降级后即时越权被拒：403/forbidden，未泄露资源内容")

    assert any("授权拒绝" in r.message for r in caplog.records)
    assert any("会话轮换" in r.message for r in caplog.records)


def test_rotation_predecessor_csrf_single_use() -> None:
    base = make_client()
    admin = sibling(base)
    _, admin_csrf = login(admin, "admin", "admin-pass")
    alice = sibling(base)
    old_session, old_csrf = login(alice, "alice", "alice-pass")

    admin.post(
        "/admin/roles",
        json={"username": "alice", "role": "admin"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    # 轮换当次请求：客户端尚未拿到新令牌，上一代令牌允许沿用一次。
    resp = alice.post("/auth/logout", headers={"X-CSRF-Token": old_csrf})
    assert resp.status_code == 200
    logger.info("轮换当次请求沿用上一代 CSRF 令牌通过")

    # 重放上一代令牌：会话已撤销，拒绝且原因可区分。
    stale = sibling(alice, old_session)
    resp = stale.post("/auth/logout", headers={"X-CSRF-Token": old_csrf})
    assert resp.status_code == 401
    assert resp.json()["reason"] == "session_revoked"


def test_predecessor_token_replay_after_rotation_rejected() -> None:
    base = make_client()
    admin = sibling(base)
    _, admin_csrf = login(admin, "admin", "admin-pass")
    alice = sibling(base)
    _, old_csrf = login(alice, "alice", "alice-pass")

    admin.post(
        "/admin/roles",
        json={"username": "alice", "role": "admin"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    # 先做一次普通请求触发轮换，拿到新会话与新令牌。
    resp = alice.get("/auth/me")
    assert resp.status_code == 200
    new_session = alice.cookies.get("session")

    # 用新会话 + 上一代令牌重放：上一代令牌仅在轮换当次请求有效。
    replay = sibling(alice, new_session)
    resp = replay.post("/auth/logout", headers={"X-CSRF-Token": old_csrf})
    assert resp.status_code == 403
    assert resp.json()["reason"] == "csrf_invalid"
    logger.info("轮换完成后重放上一代令牌被拒：403/csrf_invalid")
