"""管理会话与“退出等待写操作收尾（drain）”机制。

设计要点：

1. 会话令牌使用 ``secrets.token_urlsafe`` 生成随机不透明串，仅保存在本进程
   内存中；进程重启后全部会话失效（不持久化、不签发等价令牌）。
2. 管理 Cookie 名称固定为 :data:`ADMIN_COOKIE_NAME`，Path=/proxy、HttpOnly、
   SameSite=Strict；业务路径（/notices/...）浏览器本就不会携带，代理在转发
   上游前还会显式剥离该 Cookie，杜绝身份绕过与泄露到上游。
3. 每个被批准的管理写操作登记到所属会话的 ``active_ops`` 中，在独立
   ``asyncio.Task`` 里执行；客户端断连只取消路由处理，不会取消写任务，
   收尾仍会继续（见 proxy.app._run_tracked）。
4. 退出（logout）立即把会话置为 draining：该会话的新管理请求一律拒绝；
   drain 任务等待所有在途写操作进入终态后才把会话置为 closed 并产出结果。
   重复退出共享同一个 drain 任务/结果。
5. 写操作终态：
   - completed：明确成功或明确失败（含上游明确回执的非 2xx）；
   - ambiguous：超时 / 传输异常 / 客户端断连等“回执不明”。
   只要存在 ambiguous 操作，退出结果即为 incomplete，且会话保持禁用，
   绝不报告成功。
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable

ADMIN_COOKIE_NAME = "proxy_admin_sid"


class OpStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    AMBIGUOUS = "ambiguous"


class SessionState(str, Enum):
    ACTIVE = "active"
    DRAINING = "draining"
    CLOSED = "closed"


class SessionDisabled(Exception):
    """会话已退出（draining/closed），拒绝新管理请求。"""


@dataclass(eq=False)
class AdminOp:
    """一次被批准的管理写操作。"""

    op_id: int
    kind: str
    status: OpStatus = OpStatus.PENDING
    note: str = ""
    task: asyncio.Task | None = None
    outcome: object | None = None

    def summary(self) -> dict:
        return {
            "id": self.op_id,
            "kind": self.kind,
            "status": self.status.value,
            "note": self.note,
        }


@dataclass
class AdminSession:
    token: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    state: SessionState = SessionState.ACTIVE
    active_ops: set[AdminOp] = field(default_factory=set)
    history: list[AdminOp] = field(default_factory=list)
    _next_op_id: int = 0
    drain_task: asyncio.Task | None = None
    drain_future: asyncio.Future | None = None
    drain_result: dict | None = None

    @property
    def public_id(self) -> str:
        # 仅展示令牌前缀，避免完整会话标识出现在页面/日志里
        return self.token[:10]

    def public_view(self) -> dict:
        return {
            "id": self.public_id,
            "state": self.state.value,
            "active_operations": len(self.active_ops),
            "total_operations": len(self.history) + len(self.active_ops),
        }


def parse_cookies(cookie_header: str | None) -> dict[str, str]:
    """解析 Cookie 头为字典（不去重语义，演示环境足够；同名取首个）。"""
    out: dict[str, str] = {}
    if not cookie_header:
        return out
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name and name not in out:
            out[name] = value.strip()
    return out


def strip_admin_cookie(cookie_header: str | None) -> str:
    """从 Cookie 头中剔除管理会话 Cookie，返回可转发给上游的值。"""
    if not cookie_header:
        return ""
    kept = [
        part.strip()
        for part in cookie_header.split(";")
        if "=" in part
        and part.split("=", 1)[0].strip() != ADMIN_COOKIE_NAME
    ]
    return "; ".join(kept)


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, AdminSession] = {}

    def create_session(self) -> AdminSession:
        token = secrets.token_urlsafe(32)
        session = AdminSession(token=token)
        self._sessions[token] = session
        return session

    def get(self, token: str | None) -> AdminSession | None:
        if not token:
            return None
        return self._sessions.get(token)

    async def begin_op(self, session: AdminSession, kind: str) -> AdminOp:
        """登记一个被批准的写操作；会话已退出则拒绝。"""
        async with session.lock:
            if session.state != SessionState.ACTIVE:
                raise SessionDisabled(session.state.value)
            session._next_op_id += 1
            op = AdminOp(op_id=session._next_op_id, kind=kind)
            session.active_ops.add(op)
            return op

    def spawn(
        self,
        session: AdminSession,
        op: AdminOp,
        work: Callable[[], Awaitable[object]],
    ) -> asyncio.Task:
        """在独立任务中执行写操作；任务不被客户端断连取消。"""
        task = asyncio.create_task(self._run_op(session, op, work()))
        op.task = task
        return task

    async def _run_op(
        self,
        session: AdminSession,
        op: AdminOp,
        coro: Awaitable[object],
    ) -> object | None:
        try:
            outcome = await coro
            op.outcome = outcome
            # 终态由 work 内部通过 outcome.terminal 给出（completed/ambiguous）
            terminal = getattr(outcome, "terminal", OpStatus.COMPLETED.value)
            op.status = (
                OpStatus.AMBIGUOUS
                if terminal == OpStatus.AMBIGUOUS.value
                else OpStatus.COMPLETED
            )
            op.note = getattr(outcome, "note", "") or ""
        except asyncio.CancelledError:
            # 正常流程不会取消该任务；若被取消，按“回执不明”处理
            op.status = OpStatus.AMBIGUOUS
            op.note = "write task cancelled before completion"
            raise
        except BaseException as exc:  # noqa: BLE001 - 任何异常都视为回执不明
            op.status = OpStatus.AMBIGUOUS
            op.note = f"unexpected error: {exc!r}"
        finally:
            async with session.lock:
                session.active_ops.discard(op)
                session.history.append(op)
        return op.outcome

    async def logout(self, session: AdminSession) -> dict:
        """开始或共享退出流程，等待全部在途写操作收尾。"""
        async with session.lock:
            if session.state == SessionState.CLOSED:
                assert session.drain_result is not None
                return session.drain_result
            if session.state == SessionState.DRAINING:
                assert session.drain_future is not None
                future = session.drain_future
            else:
                session.state = SessionState.DRAINING
                future = asyncio.get_running_loop().create_future()
                session.drain_future = future
                session.drain_task = asyncio.create_task(self._drain(session))
        return await future

    async def _drain(self, session: AdminSession) -> None:
        try:
            async with session.lock:
                tasks = [op.task for op in session.active_ops if op.task is not None]
            # draining 状态下 begin_op 被拒绝，active_ops 只会减少不会增加
            if tasks:
                await asyncio.gather(*tasks)
            async with session.lock:
                all_ops = list(session.history)
                incomplete = [
                    op.summary()
                    for op in all_ops
                    if op.status == OpStatus.AMBIGUOUS
                ]
                result = {
                    "ok": True,
                    "status": "incomplete" if incomplete else "completed",
                    "session_id": session.public_id,
                    "waited_operations": [op.summary() for op in all_ops],
                    "incomplete_operations": incomplete,
                    "detail": (
                        "all tracked write operations reached a known terminal state"
                        if not incomplete
                        else "one or more write operations have unknown upstream "
                        "receipt (timeout/transport error); session stays disabled"
                    ),
                }
                session.drain_result = result
                session.state = SessionState.CLOSED
                if session.drain_future is not None and not session.drain_future.done():
                    session.drain_future.set_result(result)
        except BaseException as exc:  # noqa: BLE001 - 保证等待者一定被唤醒
            async with session.lock:
                session.state = SessionState.CLOSED
                result = {
                    "ok": False,
                    "status": "incomplete",
                    "session_id": session.public_id,
                    "detail": f"drain failed: {exc!r}",
                    "incomplete_operations": [
                        op.summary()
                        for op in session.active_ops | set(session.history)
                        if op.status != OpStatus.COMPLETED
                    ],
                    "waited_operations": [
                        op.summary()
                        for op in session.active_ops | set(session.history)
                    ],
                }
                session.drain_result = result
                if session.drain_future is not None and not session.drain_future.done():
                    session.drain_future.set_result(result)
