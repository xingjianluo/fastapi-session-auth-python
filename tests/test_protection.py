"""暴力破解防护在并发正确登录下的容量保障与共享状态测试。"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.models import Role, User
from app.security import hash_password
from main import create_app

logger = logging.getLogger("tests.protection")


class FakeClock:
    def __init__(self, start: float = 1_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_client(**kwargs) -> TestClient:
    return TestClient(create_app(**kwargs))


def sibling(client: TestClient) -> TestClient:
    """同一应用实例上的另一个客户端（同一来源、独立 Cookie 罐）。"""
    return TestClient(client.app)


def add_user(client: TestClient, username: str, password: str) -> None:
    client.app.state.user_store.add(
        User(username, hash_password(password), Role.USER)
    )


def test_concurrent_correct_logins_all_succeed() -> None:
    """批量上线自检：一批设备并发拿各自账号的正确口令登录，全部成功。"""
    clock = FakeClock()
    client = make_client(max_failures=5, lock_seconds=60, clock=clock)
    devices = [f"dev{i:02d}" for i in range(12)]
    for name in devices:
        add_user(client, name, "right-pass")

    def worker(username: str) -> tuple[str, str, str]:
        c = sibling(client)
        resp = c.post(
            "/auth/login",
            json={"username": username, "password": "right-pass"},
        )
        assert resp.status_code == 200, (username, resp.json())
        return username, c.cookies.get("session"), resp.json()["csrf_token"]

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(worker, devices))

    session_ids = {sid for _, sid, _ in results}
    csrf_tokens = {token for _, _, token in results}
    assert len(session_ids) == 12, "每条都必须拿到独立会话"
    assert len(csrf_tokens) == 12
    logger.info(
        "并发正确登录 12/12 全部成功（同一来源、阈值 5）："
        "会话与 CSRF 令牌各自独立，防护未误伤"
    )


def test_concurrent_mixed_correct_and_wrong() -> None:
    """正确登录不消耗失败额度；真错口令仍累计到阈值并被拦，期满恢复。"""
    clock = FakeClock()
    client = make_client(max_failures=5, lock_seconds=60, clock=clock)
    for i in range(8):
        add_user(client, f"ok{i}", "right-pass")

    def correct(i: int) -> int:
        c = sibling(client)
        resp = c.post(
            "/auth/login",
            json={"username": f"ok{i}", "password": "right-pass"},
        )
        return resp.status_code

    def wrong(_: int) -> tuple[int, str]:
        c = sibling(client)
        resp = c.post(
            "/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        return resp.status_code, resp.json()["reason"]

    with ThreadPoolExecutor(max_workers=12) as pool:
        ok_codes = list(pool.map(correct, range(8)))
        wrong_outcomes = list(pool.map(wrong, range(4)))

    assert ok_codes == [200] * 8, "正确口令的并发登录必须全部成功"
    assert wrong_outcomes == [(401, "invalid_credentials")] * 4, (
        "未达阈值的错误口令只判凭证错误，不误锁"
    )
    logger.info(
        "混合并发：8 条正确登录全部 200；4 次错误口令=401/"
        "invalid_credentials，未误锁"
    )

    # 错误口令继续累计到阈值：第 5 次计入并触发锁定。
    resp = sibling(client).post(
        "/auth/login", json={"username": "alice", "password": "wrong"}
    )
    assert resp.status_code == 401
    assert resp.json()["reason"] == "invalid_credentials"
    resp = sibling(client).post(
        "/auth/login", json={"username": "alice", "password": "wrong"}
    )
    assert resp.status_code == 429
    assert resp.json()["reason"] == "account_locked"
    logger.info("错误口令累计到阈值 5：后续尝试 429/account_locked")

    # 锁定期到点后自动恢复。
    clock.advance(61)
    resp = sibling(client).post(
        "/auth/login", json={"username": "alice", "password": "alice-pass"}
    )
    assert resp.status_code == 200
    logger.info("锁定期满自动恢复：正确口令登录 200")


def test_limiter_state_shared_service_wide() -> None:
    """防护状态服务整体共享：不同客户端的失败累计到同一份计数上。"""
    clock = FakeClock()
    client = make_client(max_failures=5, lock_seconds=60, clock=clock)
    a, b = sibling(client), sibling(client)

    # 客户端 A 失败 3 次 + 客户端 B 失败 2 次，累计到同一账号的阈值。
    for c, n in ((a, 3), (b, 2)):
        for _ in range(n):
            resp = c.post(
                "/auth/login",
                json={"username": "alice", "password": "wrong"},
            )
            assert resp.status_code == 401
            assert resp.json()["reason"] == "invalid_credentials"

    # 任一端再尝试都命中共享的锁定状态。
    for c in (a, b):
        resp = c.post(
            "/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        assert resp.status_code == 429
        assert resp.json()["reason"] == "account_locked"
    logger.info(
        "A 失败 3 次 + B 失败 2 次即共同触发锁定：防护状态服务整体共享，"
        "无法靠每个请求各起一份绕过"
    )
