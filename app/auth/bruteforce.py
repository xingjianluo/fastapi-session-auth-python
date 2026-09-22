"""基于账号与来源双维度的暴力破解防护。

规则：
- 任一维度失败次数达到阈值即进入锁定期；锁定期滑动续期。
- 锁定期内的登录请求直接拒绝，并给出可区分原因（账号/来源）。
- 锁定期满后计数自动清零，正常请求不会被长期拒绝。
- 所有计数与锁定判定在同一把锁内完成，并发失败不会丢计数或超额放行。
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable

from app.auth.store import Store
from app.config import Settings
from app.errors import account_locked, source_locked
from app.models import FailureRecord

ACCOUNT_SCOPE = "account"
SOURCE_SCOPE = "source"


class BruteForceGuard:
    def __init__(
        self,
        store: Store,
        settings: Settings,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.settings = settings
        self.clock = clock
        # 单独的防护锁，与存储锁分离但不嵌套死锁（始终 guard 锁 -> store 锁）。
        self._lock = threading.Lock()

    def _expired(self, record: FailureRecord, now: float) -> bool:
        """锁定期满则清零，返回是否处于可计数状态。"""
        if record.locked_until and now >= record.locked_until:
            record.failures = 0
            record.locked_until = 0.0
        return record.locked_until == 0.0

    def _retry_after(self, record: FailureRecord, now: float) -> int:
        return max(1, int(record.locked_until - now + 0.999))

    def check_locked(self, username: str, source: str) -> None:
        """登录前判定。任一维度锁定即拒绝：账号维度优先报告。"""
        now = self.clock()
        with self._lock:
            account = self.store.failure_record(username, ACCOUNT_SCOPE)
            source_rec = self.store.failure_record(source, SOURCE_SCOPE)
            self._expired(account, now)
            self._expired(source_rec, now)
            if account.locked_until:
                raise account_locked(self._retry_after(account, now))
            if source_rec.locked_until:
                raise source_locked(self._retry_after(source_rec, now))

    def record_failure(self, username: str, source: str) -> None:
        """记录一次失败；两个维度各自累计，达阈值即锁定。"""
        now = self.clock()
        with self._lock:
            for record in (
                self.store.failure_record(username, ACCOUNT_SCOPE),
                self.store.failure_record(source, SOURCE_SCOPE),
            ):
                self._expired(record, now)
                record.failures += 1
                if record.failures >= self.settings.max_failures:
                    record.locked_until = now + self.settings.lockout_seconds

    def record_success(self, username: str, source: str) -> None:
        """登录成功：两维度计数清零（仅在未锁定时会被调用）。"""
        with self._lock:
            for record in (
                self.store.failure_record(username, ACCOUNT_SCOPE),
                self.store.failure_record(source, SOURCE_SCOPE),
            ):
                record.failures = 0
                record.locked_until = 0.0

    def snapshot(self, username: str, source: str) -> dict[str, tuple[int, float]]:
        """供日志/测试观察当前计数状态。"""
        now = self.clock()
        with self._lock:
            a = self.store.failure_record(username, ACCOUNT_SCOPE)
            s = self.store.failure_record(source, SOURCE_SCOPE)
            self._expired(a, now)
            self._expired(s, now)
            return {
                "account": (a.failures, a.locked_until),
                "source": (s.failures, s.locked_until),
            }
