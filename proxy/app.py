"""FastAPI 单进程 HTTP 缓存代理（含管理登录与退出收尾）。

规则摘要：
- 仅代理 GET /notices/{notice_id}，上游地址固定（环境变量 UPSTREAM_BASE）。
- 带 Cookie 或 Authorization 的请求直连上游：不读、不写缓存，也不参与
  匿名请求合并。管理会话 Cookie（proxy_admin_sid）在转发前会被剥离，
  既不会发往上游，也不会触发直连绕过。
- 匿名响应仅在 200 + Cache-Control 含 public 且含合法非负整数 max-age、
  无 private/no-store、无 Set-Cookie 时缓存；过期不复用。
- 同键并发未命中只请求上游一次；单个等待者断开不影响其他等待者；
  上游失败不缓存并结束所有等待。
- 按公告清除会删除该公告全部语言缓存，并使清除前的在途响应无法回填、
  清除后的新请求无法复用旧在途结果。

管理安全：
- 管理口令来自启动配置 ADMIN_PASSWORD（必填，缺失则拒绝启动）。
- POST /proxy/login 校验口令后签发随机 HttpOnly 会话 Cookie，Path=/proxy，
  SameSite=Strict，仅存内存，进程重启即失效。
- 除登录外，所有 /proxy 接口都要求有效会话；退出中的会话拒绝一切新请求。
- 所有管理 POST 必须携带与 ADMIN_ALLOWED_ORIGIN 完全一致的 Origin 头，
  缺失或不符一律 403。
- 退出（POST /proxy/logout）先禁用会话，再等待该会话先前获准的写操作
  全部进入终态；重复退出共享同一等待；写操作的客户端断连不影响收尾。
- 写操作超时 / 回执不明时退出结果为 incomplete，会话保持禁用，绝不报成功。
"""

from __future__ import annotations

import asyncio
import hmac
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse

from .cachestore import (
    CachedResponse,
    CacheHit,
    CacheLeader,
    CacheStore,
    CacheWait,
    InFlight,
)
from .policy import cache_eligibility
from .sessions import (
    ADMIN_COOKIE_NAME,
    AdminSession,
    SessionDisabled,
    SessionRegistry,
    SessionState,
    parse_cookies,
    strip_admin_cookie,
)

UPSTREAM_BASE = os.environ.get("UPSTREAM_BASE", "http://upstream:8001").rstrip("/")
HTTP_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT_SECONDS", "15"))
# 管理类上游写操作单独的超时配置：超出即判定“回执不明”
ADMIN_UPSTREAM_TIMEOUT = float(os.environ.get("ADMIN_TIMEOUT_SECONDS", "8"))
# 启动配置的管理口令；未配置时拒绝启动，避免默认弱口令
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
# 管理 POST 允许的固定 Origin（浏览器对 fetch POST 总会带 Origin）
ADMIN_ALLOWED_ORIGIN = os.environ.get(
    "ADMIN_ALLOWED_ORIGIN", "http://localhost:8000"
).rstrip("/")

# 转发给上游的请求头白名单（逐跳头、Host 等不带）
FORWARD_REQUEST_HEADERS = {
    "accept",
    "accept-language",
    "user-agent",
    "cookie",
    "authorization",
    "x-request-id",
}

# 回传给客户端 / 写入缓存的响应头白名单。
# content-length / transfer-encoding / content-encoding 由框架按解码后的
# body 重新处理；Set-Cookie 仅直连（带身份）响应可能出现。
PASS_RESPONSE_HEADERS = {
    "content-type",
    "content-language",
    "cache-control",
    "etag",
    "last-modified",
    "set-cookie",
    "x-upstream-request-id",
    "x-notice-id",
    "x-notice-kind",
}

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "content-encoding",
}

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Notice Cache Proxy", version="2.0.0")
store = CacheStore()
sessions = SessionRegistry()
_client: httpx.AsyncClient | None = None
_admin_client: httpx.AsyncClient | None = None


@app.on_event("startup")
async def _startup() -> None:
    global _client, _admin_client
    if not ADMIN_PASSWORD:
        raise RuntimeError(
            "ADMIN_PASSWORD is required but not set; refusing to start without "
            "an admin password"
        )
    _client = httpx.AsyncClient(
        base_url=UPSTREAM_BASE,
        timeout=httpx.Timeout(HTTP_TIMEOUT),
        follow_redirects=False,
    )
    _admin_client = httpx.AsyncClient(
        base_url=UPSTREAM_BASE,
        timeout=httpx.Timeout(ADMIN_UPSTREAM_TIMEOUT),
        follow_redirects=False,
    )


@app.on_event("shutdown")
async def _shutdown() -> None:
    for client in (_client, _admin_client):
        if client is not None:
            await client.aclose()


@dataclass
class FetchResult:
    status_code: int
    body: bytes
    headers: list[tuple[str, str]]
    request_id: str | None


@dataclass
class WriteOutcome:
    """管理写操作的可序列化结果与终态标记。"""

    terminal: str  # completed | ambiguous
    status_code: int
    payload: object
    note: str = ""


# ---------------- 认证 / CSRF 防护 ----------------


async def require_origin(request: Request) -> None:
    """管理 POST 固定 Origin 校验：缺失或不符即拒绝。"""
    origin = request.headers.get("origin")
    if not origin or origin.rstrip("/") != ADMIN_ALLOWED_ORIGIN:
        raise _http_403(
            "origin check failed: missing or non-matching Origin header",
            error_code="bad_origin",
        )


def _http_401(message: str, *, error_code: str = "unauthorized") -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=message,
        headers={"Cache-Control": "no-store", "X-Admin-Error": error_code},
    )


def _http_403(message: str, *, error_code: str = "forbidden") -> HTTPException:
    return HTTPException(
        status_code=403,
        detail=message,
        headers={"Cache-Control": "no-store", "X-Admin-Error": error_code},
    )


@app.exception_handler(HTTPException)
async def _http_exception_handler(
    request: Request, exc: HTTPException
) -> JSONResponse:
    error_code = "error"
    headers = getattr(exc, "headers", None) or {}
    if "X-Admin-Error" in headers:
        error_code = headers["X-Admin-Error"]
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error": error_code},
        headers={"Cache-Control": "no-store"},
    )


async def require_session(request: Request) -> AdminSession:
    """除登录外全部 /proxy 接口的会话认证依赖。"""
    token = parse_cookies(request.headers.get("cookie")).get(ADMIN_COOKIE_NAME)
    session = sessions.get(token)
    if session is None:
        raise _http_401("admin session missing or invalid")
    if session.state != SessionState.ACTIVE:
        # draining / closed：退出已生效，拒绝该会话的一切新管理请求
        raise _http_401(
            f"session is {session.state.value}; admin requests are disabled",
            error_code="session_disabled",
        )
    return session


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=ADMIN_COOKIE_NAME,
        value=token,
        path="/proxy",
        httponly=True,
        samesite="strict",
        secure=False,  # 本地 http 演示；生产置于 https 反代后应开启
        max_age=None,  # 会话 Cookie：浏览器关闭即失效；进程重启同样失效
    )


# ---------------- 上游请求与缓存 ----------------


def _is_personal(request: Request) -> bool:
    cookies = parse_cookies(request.headers.get("cookie"))
    # 管理 Cookie 不属于业务身份，既不触发绕过也不会转发上游
    cookies.pop(ADMIN_COOKIE_NAME, None)
    has_cookie = bool("; ".join(f"{k}={v}" for k, v in cookies.items()).strip())
    auth = request.headers.get("authorization", "").strip()
    return has_cookie or bool(auth)


def _forward_headers(request: Request) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in FORWARD_REQUEST_HEADERS and lk not in HOP_BY_HOP:
            if lk == "cookie":
                v = strip_admin_cookie(v)  # 管理 Cookie 绝不发往上游
                if not v:
                    continue
            out[k] = v
    return out


def _filter_response_headers(
    headers, *, include_set_cookie: bool
) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for k, v in headers:
        lk = k.lower()
        if lk in HOP_BY_HOP:
            continue
        if lk == "set-cookie" and not include_set_cookie:
            continue
        if lk in PASS_RESPONSE_HEADERS:
            result.append((k, v))
    return result


async def _fetch_upstream(request: Request, notice_id: str) -> FetchResult:
    assert _client is not None
    resp = await _client.get(
        f"/notices/{notice_id}", headers=_forward_headers(request)
    )
    body = resp.content  # 读取完整 body，连接即可释放
    return FetchResult(
        status_code=resp.status_code,
        body=body,
        headers=list(resp.headers.multi_items()),
        request_id=resp.headers.get("x-upstream-request-id"),
    )


def _build_cached_entry(
    result: FetchResult, generation: int
) -> CachedResponse | None:
    ok, _reason, max_age = cache_eligibility(result.status_code, result.headers)
    if not ok or max_age is None:
        return None
    safe_headers = [
        (k.encode("latin-1"), v.encode("latin-1"))
        for k, v in _filter_response_headers(
            result.headers, include_set_cookie=False
        )
    ]
    now = time.monotonic()
    return CachedResponse(
        status_code=result.status_code,
        body=result.body,
        headers=safe_headers,
        cached_at=now,
        expires_at=now + max_age,
        max_age=max_age,
        generation=generation,
    )


class UpstreamFailure(Exception):
    """上游返回 5xx：视为失败，不缓存并结束所有等待者。"""

    def __init__(self, result: "FetchResult") -> None:
        super().__init__(f"upstream responded {result.status_code}")
        self.result = result


async def _leader_work(
    inflight: InFlight, request: Request, notice_id: str
) -> None:
    """独立任务执行上游请求；任何等待者（含 leader 客户端）断开都不会取消它。

    成功且可缓存：仅在仍是当前代际时回填，再交付全部等待者。
    传输异常 / 上游 5xx：不缓存，以异常结束所有等待者。
    """
    try:
        result = await _fetch_upstream(request, notice_id)
        if result.status_code >= 500:
            raise UpstreamFailure(result)
    except BaseException as exc:  # noqa: BLE001 - 需传播给全部等待者
        await store.fail_all(inflight, exc)
        if not inflight.future.done():
            inflight.future.set_exception(exc)
        return
    try:
        entry = _build_cached_entry(result, inflight.generation)
        await store.store_if_current(inflight, entry)
    finally:
        if not inflight.future.done():
            inflight.future.set_result(result)


def _live_response(
    result: FetchResult, *, cache_status: str, reason: str
) -> Response:
    # raw_headers 支持重复的 Set-Cookie；与缓存条目一样使用 latin-1 字节
    raw = [
        (k.encode("latin-1"), v.encode("latin-1"))
        for k, v in _filter_response_headers(
            result.headers, include_set_cookie=True
        )
    ]
    raw.append((b"x-cache", cache_status.encode("latin-1")))
    raw.append((b"x-cache-reason", reason.encode("latin-1")))
    response = Response(content=result.body, status_code=result.status_code)
    response.raw_headers = raw
    return response


def _error_response(message: str, status: int = 502) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"detail": message, "upstream": UPSTREAM_BASE},
        headers={"X-Cache": "ERROR"},
    )


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/notices/{notice_id}")
async def proxy_notice(notice_id: str, request: Request) -> Response:
    # ---- 带身份的请求：直连，不碰缓存、不参与合并 ----
    if _is_personal(request):
        try:
            result = await _fetch_upstream(request, notice_id)
        except httpx.HTTPError as exc:
            return _error_response(f"upstream error (bypass): {exc}")
        if result.status_code >= 500:
            return _error_response(
                f"upstream responded {result.status_code} (bypass)"
            )
        return _live_response(
            result, cache_status="BYPASS", reason="authenticated"
        )

    accept_language = request.headers.get("accept-language", "")
    key = store.make_key(notice_id, accept_language)
    decision = await store.lookup(key, notice_id)

    # ---- 1) 缓存命中（过期条目在 lookup 阶段已被剔除，绝不复用）----
    if isinstance(decision, CacheHit):
        entry = decision.entry
        raw = list(entry.headers)
        age = int(time.monotonic() - entry.cached_at)
        raw.append((b"x-cache", b"HIT"))
        raw.append((
            b"x-cache-key",
            f"notice={notice_id};lang={accept_language or '<none>'}".encode("latin-1"),
        ))
        raw.append((b"age", str(age).encode("latin-1")))
        response = Response(content=entry.body, status_code=entry.status_code)
        response.raw_headers = raw
        return response

    # ---- 2) 已有同键在途：加入等待，不发新的上游请求 ----
    if isinstance(decision, CacheWait):
        try:
            result = await decision.inflight.future
        except UpstreamFailure as exc:
            return _error_response(
                f"upstream responded {exc.result.status_code} (shared)"
            )
        except httpx.HTTPError as exc:
            return _error_response(f"upstream error (shared): {exc}")
        except Exception as exc:  # noqa: BLE001
            return _error_response(f"shared request failed: {exc}")
        return _live_response(
            result,
            cache_status="MISS-WAIT",
            reason="coalesced with in-flight request",
        )

    # ---- 3) leader：发起唯一的上游请求 ----
    # 独立任务 + 等待 future：leader 客户端断开只会取消路由处理任务，
    # 不会取消 leader_work，其他等待者照常得到结果。
    assert isinstance(decision, CacheLeader)
    inflight = decision.inflight
    task = asyncio.create_task(_leader_work(inflight, request, notice_id))
    inflight.leader_task = task
    try:
        result = await inflight.future
    except UpstreamFailure as exc:
        return _error_response(
            f"upstream responded {exc.result.status_code}"
        )
    except httpx.HTTPError as exc:
        return _error_response(f"upstream error: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _error_response(f"upstream request failed: {exc}")

    ok, reason, _ = cache_eligibility(result.status_code, result.headers)
    return _live_response(
        result,
        cache_status="MISS" if ok else "MISS-NO-CACHE",
        reason=reason,
    )


# ---------------- 管理：登录 / 退出 / 会话 ----------------


@app.post("/proxy/login", dependencies=[Depends(require_origin)])
async def admin_login(request: Request) -> Response:
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse(
            status_code=400, content={"detail": "invalid JSON body"}
        )
    password = str(payload.get("password", "")) if isinstance(payload, dict) else ""
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        # 固定延时，降低口令时序侧信道（对比本身也用了恒定时间函数）
        await asyncio.sleep(0.2)
        raise _http_401("invalid admin password", error_code="bad_password")
    session = sessions.create_session()
    response = JSONResponse(
        status_code=200,
        content={
            "ok": True,
            "session": session.public_view(),
            "allowed_origin": ADMIN_ALLOWED_ORIGIN,
        },
    )
    _set_session_cookie(response, session.token)
    return response


@app.post(
    "/proxy/logout",
    dependencies=[Depends(require_origin)],
)
async def admin_logout(request: Request) -> Response:
    token = parse_cookies(request.headers.get("cookie")).get(ADMIN_COOKIE_NAME)
    session = sessions.get(token)
    if session is None:
        # 无有效会话：幂等拒绝，但不泄露令牌是否存在过
        raise _http_401("no active admin session")
    # 立即禁用会话（drain 内部先置 draining），随后等待在途写操作收尾。
    # 重复退出共享同一个 drain future；客户端断连后 drain 仍在后台继续。
    result = await sessions.logout(session)
    response = JSONResponse(status_code=200, content=result)
    response.delete_cookie(
        key=ADMIN_COOKIE_NAME,
        path="/proxy",
        httponly=True,
        samesite="strict",
    )
    return response


@app.get("/proxy/session")
async def admin_session(
    session: AdminSession = Depends(require_session),
) -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "session": session.public_view(),
            "allowed_origin": ADMIN_ALLOWED_ORIGIN,
        }
    )


# ---------------- 管理写操作（受会话 + Origin 保护，可被退出等待） ----------------


def _outcome_response(outcome: WriteOutcome) -> Response:
    if outcome.terminal == "ambiguous":
        # 回执不明：客户端看到 504，但操作仍在后台跑/可能已生效
        return JSONResponse(
            status_code=504,
            content={
                "detail": outcome.note,
                "upstream": UPSTREAM_BASE,
                "receipt": "ambiguous",
                "upstream_response": outcome.payload,
            },
            headers={"X-Admin-Write": "ambiguous", "Cache-Control": "no-store"},
        )
    return JSONResponse(
        status_code=outcome.status_code,
        content=outcome.payload,
        headers={"Cache-Control": "no-store"},
    )


async def _run_tracked(
    session: AdminSession,
    kind: str,
    work: Callable[[], Awaitable[WriteOutcome]],
) -> Response:
    """登记并在独立任务中执行写操作。

    - 会话已退出：拒绝（401），不登记新操作；
    - 客户端断连只取消路由处理，后台写任务继续直到终态；
    - 超时/传输异常标记 ambiguous，退出时因此不能报成功。
    """
    try:
        op = await sessions.begin_op(session, kind)
    except SessionDisabled as exc:
        raise _http_401(
            f"session disabled ({exc}); write rejected",
            error_code="session_disabled",
        ) from exc
    sessions.spawn(session, op, work)
    assert op.task is not None
    try:
        outcome: WriteOutcome = await op.task
    except asyncio.CancelledError:
        # 路由任务被取消（客户端断连）：写任务不受影响，仍可由退出等待。
        # 重新等待以拿到终态，仅用于兜底返回。
        outcome = await op.task
    return _outcome_response(outcome)


@app.post("/proxy/purge/{notice_id}")
async def purge_notice(
    notice_id: str,
    request: Request,
    session: AdminSession = Depends(require_session),
    _origin: None = Depends(require_origin),
) -> Response:
    async def work() -> WriteOutcome:
        info = await store.purge_notice(notice_id)
        return WriteOutcome(
            terminal="completed",
            status_code=200,
            payload={"purged": notice_id, **info},
            note="local cache purge completed",
        )

    return await _run_tracked(session, "proxy.purge", work)


@app.post("/proxy/reset")
async def proxy_reset(
    request: Request,
    session: AdminSession = Depends(require_session),
    _origin: None = Depends(require_origin),
) -> Response:
    async def work() -> WriteOutcome:
        return WriteOutcome(
            terminal="completed",
            status_code=200,
            payload=await store.reset(),
            note="local cache reset completed",
        )

    return await _run_tracked(session, "proxy.reset", work)


# ---------------- 管理只读接口 ----------------


def _passthrough(r: httpx.Response) -> Response:
    return Response(
        content=r.content,
        status_code=r.status_code,
        media_type=r.headers.get("content-type"),
        headers={"Cache-Control": "no-store"},
    )


@app.get("/proxy/state")
async def proxy_state(
    session: AdminSession = Depends(require_session),
) -> JSONResponse:
    return JSONResponse(await store.snapshot())


@app.get("/proxy/upstream/state")
async def upstream_state(
    session: AdminSession = Depends(require_session),
) -> Response:
    assert _admin_client is not None
    try:
        return _passthrough(await _admin_client.get("/admin/state"))
    except httpx.HTTPError as exc:
        return _error_response(f"upstream admin unreachable: {exc}")


@app.get("/proxy/upstream/requests")
async def upstream_requests(
    session: AdminSession = Depends(require_session),
) -> Response:
    assert _admin_client is not None
    try:
        return _passthrough(await _admin_client.get("/admin/requests"))
    except httpx.HTTPError as exc:
        return _error_response(f"upstream admin unreachable: {exc}")


# ---------------- 管理写：上游配置（慢操作 / 回执不明的来源） ----------------


async def _upstream_admin_post(path: str, payload: bytes, kind: str):
    """执行一次上游管理写，返回带终态的 WriteOutcome。"""
    assert _admin_client is not None
    try:
        r = await _admin_client.post(
            path,
            content=payload,
            headers={"content-type": "application/json"},
        )
    except httpx.TimeoutException as exc:
        # 超时：上游可能已收到且稍后生效 —— 回执不明
        return WriteOutcome(
            terminal="ambiguous",
            status_code=504,
            payload=None,
            note=f"upstream admin write timed out after {ADMIN_UPSTREAM_TIMEOUT}s: {exc}",
        )
    except httpx.HTTPError as exc:
        # 连接失败/响应未读完等：同样回执不明
        return WriteOutcome(
            terminal="ambiguous",
            status_code=504,
            payload=None,
            note=f"upstream admin write transport error: {exc}",
        )
    body = r.content
    try:
        parsed = r.json()
    except Exception:  # noqa: BLE001
        parsed = body.decode("utf-8", "replace")
    # 拿到明确 HTTP 回执（含 4xx/5xx）即视为已知终态；不成功但不“不明”
    return WriteOutcome(
        terminal="completed",
        status_code=r.status_code,
        payload=parsed,
        note=f"upstream acknowledged with HTTP {r.status_code}",
    )


@app.post("/proxy/upstream/config")
async def upstream_config(
    request: Request,
    session: AdminSession = Depends(require_session),
    _origin: None = Depends(require_origin),
) -> Response:
    payload = await request.body()

    async def work() -> WriteOutcome:
        return await _upstream_admin_post("/admin/config", payload, "upstream.config")

    return await _run_tracked(session, "upstream.config", work)


@app.post("/proxy/upstream/reset")
async def upstream_reset(
    request: Request,
    session: AdminSession = Depends(require_session),
    _origin: None = Depends(require_origin),
) -> Response:
    async def work() -> WriteOutcome:
        return await _upstream_admin_post(
            "/admin/reset", b"{}", "upstream.reset"
        )

    return await _run_tracked(session, "upstream.reset", work)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
