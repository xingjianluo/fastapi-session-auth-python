"""线程安全的内存存储：账号、会话、双维度失败计数。

所有变更都在同一把可重入锁内完成，保证并发下状态不丢失。
"""
from __future__ import annotations

import threading

from app.models import Account, FailureRecord, Role, SessionRecord


class Store:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.accounts: dict[str, Account] = {}
        self.sessions: dict[str, SessionRecord] = {}
        self.account_failures: dict[str, FailureRecord] = {}
        self.source_failures: dict[str, FailureRecord] = {}
        self.resources: dict[str, str] = {}

    # ---- 账号 ----
    def get_account(self, username: str) -> Account | None:
        with self.lock:
            return self.accounts.get(username)

    def set_roles(self, username: str, roles: set[Role]) -> None:
        with self.lock:
            account = self.accounts.get(username)
            if account is not None:
                account.roles = set(roles)

    # ---- 会话 ----
    def get_session(self, sid: str) -> SessionRecord | None:
        with self.lock:
            return self.sessions.get(sid)

    def put_session(self, record: SessionRecord) -> None:
        with self.lock:
            self.sessions[record.sid] = record

    def remove_session(self, sid: str) -> None:
        with self.lock:
            self.sessions.pop(sid, None)

    def revoke_session(self, sid: str) -> None:
        with self.lock:
            record = self.sessions.get(sid)
            if record is not None:
                record.revoked = True

    def revoke_user_sessions(self, username: str) -> list[str]:
        """撤销指定用户的全部有效会话，返回被撤销的会话标识。"""
        with self.lock:
            revoked = [
                record.sid
                for record in self.sessions.values()
                if record.username == username and not record.revoked
            ]
            for sid in revoked:
                self.sessions[sid].revoked = True
            return revoked

    # ---- 失败计数 ----
    def failure_record(self, key: str, scope: str) -> FailureRecord:
        bucket = (
            self.account_failures if scope == "account" else self.source_failures
        )
        with self.lock:
            record = bucket.get(key)
            if record is None:
                record = FailureRecord()
                bucket[key] = record
            return record
