"""暴力破解防护：按账号与来源分别累计失败次数并锁定。

- 只累计“确认失败”（口令校验不通过）的次数：开始尝试时在同一把锁内
  原子完成锁定检查，校验失败后再在同一把锁内原子计数并达阈锁定。
  并发失败不丢计数、不超阈放行；并发的一批“正确口令”登录
  （如多设备批量上线自检）不产生任何失败计数，不会被防护误伤。
- 账号与来源两个维度独立计数、独立锁定，失败原因可区分；
- 登录成功即清零该账号与来源的计数与锁定；
- 锁定期满后计数与锁定状态自动清除，不会长期拒绝正常请求。
- 本组件的实例由服务整体共享（挂在应用状态上），
  所有请求命中同一份计数与锁定状态，无法靠每个请求各起一份绕过。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .errors import AuthError, Reason


@dataclass
class _Counter:
    failures: list[float] = field(default_factory=list)
    locked_until: float = 0.0

    def prune(self, now: float, window: float) -> None:
        cutoff = now - window
        self.failures = [t for t in self.failures if t > cutoff]


class RateLimiter:
    def __init__(
        self,
        max_failures: int = 5,
        lock_seconds: float = 60.0,
        *,
        clock=time.time,
    ) -> None:
        self._lock = threading.Lock()
        self._max_failures = max_failures
        self._lock_seconds = lock_seconds
        self._clock = clock
        self._accounts: dict[str, _Counter] = {}
        self._sources: dict[str, _Counter] = {}

    def _raise_if_locked(self, username: str, source: str, now: float) -> None:
        """锁内判定：任一维度处于锁定期即拒绝，账号维度优先，原因可区分。"""
        account = self._accounts.setdefault(username, _Counter())
        source_c = self._sources.setdefault(source, _Counter())
        for counter, reason, prefix in (
            (account, Reason.ACCOUNT_LOCKED, f"账号 {username} 已锁定"),
            (source_c, Reason.SOURCE_LOCKED, f"来源 {source} 已锁定"),
        ):
            counter.prune(now, self._lock_seconds)
            if counter.locked_until > now:
                remain = counter.locked_until - now
                raise AuthError(
                    reason,
                    429,
                    f"{prefix}，剩余 {remain:.1f}s"
                    f"（阈值 {self._max_failures} 次）",
                )
            if counter.locked_until:
                # 锁定期满：自动解除并清零，恢复正常判定。
                counter.locked_until = 0.0
                counter.failures.clear()

    def begin_attempt(self, username: str, source: str) -> None:
        """开始一次登录尝试：原子完成锁定检查（锁定期间直接拒绝）。

        此处不计数：正确口令的并发登录不消耗失败额度；
        失败计数由 record_failure 在口令确认错误后原子完成。
        """
        now = self._clock()
        with self._lock:
            self._raise_if_locked(username, source, now)

    def record_failure(self, username: str, source: str) -> None:
        """口令确认错误后原子计数：追加一次确认失败，达阈即锁定。

        若并发的其他失败已抢先触发锁定，本次直接以锁定结论拒绝
        （原因可区分），不再重复计数。
        """
        now = self._clock()
        with self._lock:
            self._raise_if_locked(username, source, now)
            for counter in (
                self._accounts[username],
                self._sources[source],
            ):
                counter.failures.append(now)
                if len(counter.failures) >= self._max_failures:
                    counter.locked_until = now + self._lock_seconds
                    counter.failures.clear()

    def record_success(self, username: str, source: str) -> None:
        """登录成功：清零该账号与来源的计数与锁定状态。"""
        with self._lock:
            self._accounts.pop(username, None)
            self._sources.pop(source, None)
