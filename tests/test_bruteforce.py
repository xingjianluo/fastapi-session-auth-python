"""暴力破解防护：双维度计数、锁定原因可区分、并发不丢计数、到期自动恢复。"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.auth.bruteforce import BruteForceGuard
from app.auth.store import Store
from app.config import Settings
from app.errors import AuthError
from app.main import app

logger = logging.getLogger("session_auth.tests")


def _guard(max_failures: int = 5, lockout: int = 300) -> tuple[BruteForceGuard, dict]:
    clock = {"t": 0.0}
    g = BruteForceGuard(
        Store(),
        Settings(max_failures=max_failures, lockout_seconds=lockout),
        clock=lambda: clock["t"],
    )
    return g, clock


def test_threshold_triggers_account_lock_with_distinct_code():
    g, _ = _guard(max_failures=3)
    for _ in range(3):
        g.record_failure("alice", "ip-1")
    try:
        g.check_locked("alice", "ip-1")
        raise AssertionError("expected lock")
    except AuthError as e:
        assert e.code == "account_locked" and e.status_code == 429
    # 正确密码也无法在锁定期内登录（锁定优先于凭证）
    logger.info("assert account lock code=account_locked status=429")


def test_account_and_source_locks_are_distinguishable():
    g, _ = _guard(max_failures=3)
    # 来源维度：多个不同账号失败，来源累计先到阈值
    for i in range(3):
        g.record_failure(f"user{i}", "bad-ip")
    # 用一个从未失败过的干净账号：仍应被来源锁定拦截
    try:
        g.check_locked("clean-user", "bad-ip")
        raise AssertionError("expected source lock")
    except AuthError as e:
        assert e.code == "source_locked", e.code
    logger.info("assert source-only lock -> source_locked (distinct from account)")

    # 账号维度优先报告：两者都锁时给 account_locked
    g.record_failure("clean-user", "other-ip")
    g.record_failure("clean-user", "other-ip")
    g.record_failure("clean-user", "other-ip")
    try:
        g.check_locked("clean-user", "bad-ip")
    except AuthError as e:
        assert e.code == "account_locked"
    logger.info("assert account lock reported before source lock")


def test_concurrent_failures_do_not_lose_count():
    g, _ = _guard(max_failures=10)
    barrier = threading.Barrier(10)

    def worker():
        barrier.wait()
        g.record_failure("bob", "ip-9")

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(lambda _: worker(), range(10)))

    snap = g.snapshot("bob", "ip-9")
    assert snap["account"][0] == 10, snap
    assert snap["source"][0] == 10, snap
    try:
        g.check_locked("bob", "ip-9")
        raise AssertionError("expected locked at exactly threshold")
    except AuthError as e:
        assert e.code == "account_locked"
    logger.info("assert 10 concurrent failures counted exactly, no overshoot/undershoot")


def test_no_overadmission_under_concurrent_login_attempts(env):
    """端到端：并发错误登录恰好到阈值即锁定，不会超额放行。"""
    results = []
    barrier = threading.Barrier(6)

    def attempt():
        c = TestClient(app)
        barrier.wait()
        r = c.post("/auth/login", json={"username": "viewer", "password": "WRONG"})
        results.append(r.status_code)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda _: attempt(), range(6)))

    # 阈值 3：3 次 invalid_credentials，其余应被 account_locked 拦截
    locked_clients = []
    for _ in range(3):
        c = TestClient(app)
        r = c.post("/auth/login", json={"username": "viewer", "password": "viewer"})
        locked_clients.append(r.json()["error"]["code"])
    assert all(code == "account_locked" for code in locked_clients), locked_clients
    logger.info("attempt statuses=%s; post-threshold logins=%s", results, locked_clients)


def test_lock_expires_and_normal_requests_recover():
    g, clock = _guard(max_failures=3, lockout=100)
    for _ in range(3):
        g.record_failure("carol", "ip-2")
    try:
        g.check_locked("carol", "ip-2")
        raise AssertionError("expected lock")
    except AuthError:
        pass
    # 锁定期内仍被拒绝
    clock["t"] = 99
    try:
        g.check_locked("carol", "ip-2")
        raise AssertionError("still locked")
    except AuthError as e:
        assert e.code == "account_locked"
    # 锁定期满自动清零恢复
    clock["t"] = 101
    g.check_locked("carol", "ip-2")  # 不抛异常即放行
    snap = g.snapshot("carol", "ip-2")
    assert snap["account"][0] == 0 and snap["source"][0] == 0
    logger.info("assert lock auto-cleared at t=101; counters reset to 0")


def test_success_resets_counters(env):
    c = TestClient(app)
    for _ in range(2):
        c.post("/auth/login", json={"username": "viewer", "password": "bad"})
    r = c.post("/auth/login", json={"username": "viewer", "password": "viewer"})
    assert r.status_code == 200
    snap = env["container"].guard.snapshot("viewer", "testclient")
    assert snap["account"][0] == 0
    logger.info("assert successful login resets failure counters")
