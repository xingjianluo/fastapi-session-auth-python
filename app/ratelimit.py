"""暴力破解防护：按账号与来源分别累计失败次数并锁定。

- 采用悲观计数：开始一次登录尝试时，在同一把锁内原子地完成
  “锁定检查 + 失败计数 + 达阈锁定”，并发请求不会丢计数或超额放行；
- 账号与来源两个维度独立计数、独立锁定，失败原因可区分；
- 登录成功即清零该账号与来源的计数与锁定；
- 锁定期满后计数与锁定状态自动清除，不会长期拒绝正常请求。
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

    def begin_attempt(self, username: str, source: str) -> None:
        """原子地完成：锁定检查 → 计入一次失败 → 达阈即锁定。

        在口令校验之前调用（悲观计数）；若随后校验成功，
        由 record_success 清零。任一维度处于锁定期即拒绝，
        账号维度优先于来源维度，原因可区分。
        """
        now = self._clock()
        with self._lock:
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
            for counter in (account, source_c):
                counter.failures.append(now)
                if len(counter.failures) >= self._max_failures:
                    counter.locked_until = now + self._lock_seconds
                    counter.failures.clear()

    def record_success(self, username: str, source: str) -> None:
        """登录成功：清零该账号与来源的计数与锁定状态。"""
        with self._lock:
            self._accounts.pop(username, None)
            self._sources.pop(source, None)
