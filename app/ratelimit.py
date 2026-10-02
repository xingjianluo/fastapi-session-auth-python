"""暴力破解防护：按账号与来源分别累计失败次数并锁定。

- 失败次数只在凭证被**确认错误**后计入，并用条件变量把同一维度上
  “进行中 + 已确认失败”的尝试数限制在阈值以内：
  并发的正确登录会排队拿名额、全部成功，不会被当成失败误伤；
  并发的错误尝试仍恰好计入阈值，达阈即锁，不丢计数、不超额放行；
- 账号与来源两个维度独立计数、独立锁定，失败原因可区分
  （账号维度优先于来源维度判定）；
- 登录成功即清零该账号与来源的计数与锁定；
- 锁定期满后计数与锁定状态自动清除，不会长期拒绝正常请求。

防护状态集中在同一个 RateLimiter 实例的锁/条件变量内，服务整体共享，
不会因为每个请求各持一份状态而绕过阈值。
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
    # 已占名额、尚在凭证校验中的尝试数。
    in_flight: int = 0

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
        self._cond = threading.Condition()
        self._max_failures = max_failures
        self._lock_seconds = lock_seconds
        self._clock = clock
        self._accounts: dict[str, _Counter] = {}
        self._sources: dict[str, _Counter] = {}

    def _refresh(self, counter: _Counter, now: float) -> bool:
        """清理窗口外计数；返回该维度当前是否处于锁定期。期满自动清零。"""
        counter.prune(now, self._lock_seconds)
        if counter.locked_until > now:
            return True
        if counter.locked_until:
            # 锁定期满：自动解除并清零，恢复正常判定。
            counter.locked_until = 0.0
            counter.failures.clear()
        return False

    def begin_attempt(self, username: str, source: str) -> None:
        """开始一次登录尝试：锁定检查 → 申请并发名额。

        任一维度处于锁定期即拒绝（账号维度优先于来源维度，原因可区分）；
        未锁定时，等待至“进行中尝试 + 窗口内已确认失败”低于阈值后占下名额。
        正确尝试不计数，因此并发正确登录只会排队、不会被误伤。
        """
        with self._cond:
            while True:
                now = self._clock()
                account = self._accounts.setdefault(username, _Counter())
                source_c = self._sources.setdefault(source, _Counter())
                for counter, reason, prefix in (
                    (account, Reason.ACCOUNT_LOCKED, f"账号 {username} 已锁定"),
                    (source_c, Reason.SOURCE_LOCKED, f"来源 {source} 已锁定"),
                ):
                    if self._refresh(counter, now):
                        remain = counter.locked_until - now
                        raise AuthError(
                            reason,
                            429,
                            f"{prefix}，剩余 {remain:.1f}s"
                            f"（阈值 {self._max_failures} 次）",
                        )
                if (
                    account.in_flight + len(account.failures)
                    < self._max_failures
                    and source_c.in_flight + len(source_c.failures)
                    < self._max_failures
                ):
                    account.in_flight += 1
                    source_c.in_flight += 1
                    return
                self._cond.wait()

    def record_failure(self, username: str, source: str) -> None:
        """凭证确认错误：释放名额并在两个维度各计入一次失败，达阈即锁。"""
        now = self._clock()
        with self._cond:
            for counter in (
                self._accounts.get(username),
                self._sources.get(source),
            ):
                if counter is None:
                    continue
                counter.in_flight = max(0, counter.in_flight - 1)
                self._refresh(counter, now)
                counter.failures.append(now)
                if len(counter.failures) >= self._max_failures:
                    counter.locked_until = now + self._lock_seconds
                    counter.failures.clear()
            self._cond.notify_all()

    def record_success(self, username: str, source: str) -> None:
        """登录成功：释放名额，并清零该账号与来源的失败计数与锁定。

        注意不能整体删除计数器：同账号/同来源可能还有其他进行中的尝试
        共享同一计数器，删除会销毁其名额并让容量限制失效。
        """
        with self._cond:
            for counter in (
                self._accounts.get(username),
                self._sources.get(source),
            ):
                if counter is None:
                    continue
                counter.in_flight = max(0, counter.in_flight - 1)
                counter.failures.clear()
                counter.locked_until = 0.0
            self._cond.notify_all()

    def release_slots(self, username: str, source: str) -> None:
        """异常退出（未走到成功/失败结论）时仅释放名额，不计失败。"""
        with self._cond:
            for counter in (
                self._accounts.get(username),
                self._sources.get(source),
            ):
                if counter is not None and counter.in_flight > 0:
                    counter.in_flight -= 1
            self._cond.notify_all()
