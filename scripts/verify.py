#!/usr/bin/env python3
"""端到端行为验证（stdlib 实现）。

前置：代理与上游已启动（scripts/run-local.sh 或 compose）。
本地默认 PROXY=127.0.0.1:8000 / UPSTREAM=127.0.0.1:8001；
compose 内可执行：docker compose exec proxy python3 -I scripts/verify.py
（此时上游不发布宿主端口，UPSTREAM 仅用于健康检查兜底，管理写均走代理）。

覆盖：
  1. 匿名 MISS -> HIT，且上游只收到一次请求
  2. 缓存键按 Accept-Language 区分
  3. 业务 Cookie / Authorization 直连绕过缓存、不参与合并
  4. personal（Set-Cookie + private,no-store）不缓存
  5. 500 失败不缓存且结束所有在途等待
  6. 同键并发未命中只打一次上游；等待者断开不影响其他人
  7. 过期不复用
  8. 按公告清除全部语言；旧在途不回填；清除后不复用旧在途
  9. 各种非法 Cache-Control 不缓存
 10. 认证矩阵：未登录 401 / 缺/错 Origin 403 / 错口令 401 / 登录成功
 11. 管理 Cookie：Path=/proxy、HttpOnly、SameSite=Strict；不绕过、不外泄
 12. 慢配置期间退出：先禁用会话、等待在途写完成；重复退出共享等待；
     其他会话与公告访问不受影响
 13. 写超时/回执不明：504 -> 退出 incomplete，会话保持禁用；上游最终生效
 14. 写请求客户端断连：后台收尾继续，退出仍等待到完成
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROXY = os.environ.get("PROXY_ADDR", "127.0.0.1:8000")
UPSTREAM = os.environ.get("UPSTREAM_ADDR", "127.0.0.1:8001")
PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
ORIGIN = os.environ.get(
    "ADMIN_ALLOWED_ORIGIN", f"http://{PROXY}"
).rstrip("/")

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {detail}")


def section(t: str) -> None:
    print(f"\n=== {t} ===")


def _split(host_port: str) -> tuple[str, int]:
    host, port = host_port.split(":")
    return host, int(port)


def raw_request(host_port: str, method: str, path: str, headers=None,
                body=None, timeout=20):
    conn = http.client.HTTPConnection(host_port, timeout=timeout)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    hs = {k.lower(): v for k, v in resp.getheaders()}
    return resp.status, hs, data, conn


def proxy_get(path, headers=None, timeout=20):
    status, hs, body, conn = raw_request(PROXY, "GET", path, headers, timeout=timeout)
    conn.close()
    return status, hs, body


def proxy_call(method: str, path: str, token: str | None = None,
               payload: dict | None = None, with_origin: bool = True,
               timeout: int = 20):
    """通过代理调用管理接口；token=None 表示不带会话 Cookie。"""
    headers = {}
    if token is not None:
        headers["Cookie"] = f"proxy_admin_sid={token}"
    if with_origin:
        headers["Origin"] = ORIGIN
    body = None
    if payload is not None:
        headers["content-type"] = "application/json"
        body = json.dumps(payload).encode()
    status, hs, data, conn = raw_request(
        PROXY, method, path, headers, body=body, timeout=timeout
    )
    conn.close()
    return status, hs, data


def login(password: str = PASSWORD, origin: str | None = ORIGIN):
    headers = {"content-type": "application/json"}
    if origin is not None:
        headers["Origin"] = origin
    status, hs, body, conn = raw_request(
        PROXY, "POST", "/proxy/login", headers,
        body=json.dumps({"password": password}).encode(),
    )
    conn.close()
    set_cookie = hs.get("set-cookie", "")
    token = None
    if "proxy_admin_sid=" in set_cookie:
        token = set_cookie.split("proxy_admin_sid=", 1)[1].split(";", 1)[0]
    return status, hs, body, token, set_cookie


def admin_post_via_proxy(token: str, path: str, payload: dict, timeout: int = 20):
    return proxy_call("POST", path, token, payload, True, timeout)


def admin_reset(token: str) -> None:
    admin_post_via_proxy(token, "/proxy/upstream/reset", {})
    admin_post_via_proxy(token, "/proxy/reset", {})


def upstream_state(token: str) -> dict:
    status, _, body = proxy_call("GET", "/proxy/upstream/state", token)
    assert status == 200, status
    return json.loads(body)


def upstream_count(token: str) -> int:
    return upstream_state(token)["counters"]["total_requests"]


def main() -> int:
    section("0. 启动检查与登录")
    check("healthz", proxy_get("/healthz")[0] == 200)
    # 未登录管理接口一律 401
    s0, _, _ = proxy_call("GET", "/proxy/state", None)
    check("未登录 GET /proxy/state -> 401", s0 == 401, str(s0))
    s0b, _, _ = proxy_call("GET", "/proxy/upstream/requests", None)
    check("未登录 GET /proxy/upstream/requests -> 401", s0b == 401, str(s0b))
    # Origin 校验
    s_origin, _, _ = proxy_call("POST", "/proxy/login", None,
                                {"password": PASSWORD}, with_origin=False)
    check("登录缺失 Origin -> 403", s_origin == 403, str(s_origin))
    s_bad_origin = login(password=PASSWORD, origin="http://evil.example")[0]
    check("登录错误 Origin -> 403", s_bad_origin == 403, str(s_bad_origin))
    s_bad_pw = login(password="wrong-password")[0]
    check("错误口令 -> 401", s_bad_pw == 401, str(s_bad_pw))
    status, login_hs, login_body, token, set_cookie = login()
    check("正确口令登录 -> 200 且签发会话", status == 200 and bool(token),
          f"{status} {set_cookie[:60]}")
    check("Cookie HttpOnly", "httponly" in set_cookie.lower(), set_cookie)
    check("Cookie Path=/proxy", "path=/proxy" in set_cookie.lower(), set_cookie)
    check("Cookie SameSite=Strict", "samesite=strict" in set_cookie.lower(),
          set_cookie)
    check("Cookie 未带 Secure 之外的持久化属性（无 max-age/expires）",
          "max-age" not in set_cookie.lower()
          and "expires" not in set_cookie.lower(), set_cookie)
    # 伪造令牌
    s_forge, _, _ = proxy_call("GET", "/proxy/state", "forged-token-xyz")
    check("伪造会话 Cookie -> 401", s_forge == 401, str(s_forge))
    # 已认证 POST 缺 Origin
    s_no_origin, _, _ = proxy_call("POST", "/proxy/reset", token,
                                   {}, with_origin=False)
    check("已认证 POST 缺 Origin -> 403", s_no_origin == 403, str(s_no_origin))

    section("0.1 重置环境")
    admin_reset(token)
    admin_post_via_proxy(token, "/proxy/upstream/config",
                         {"profile": "public", "latency_ms": 100, "max_age": 30})
    check("登录后可访问 /proxy/state",
          proxy_call("GET", "/proxy/state", token)[0] == 200)

    section("1. 匿名 MISS -> HIT，上游仅一次请求")
    n0 = upstream_count(token)
    s1, h1, b1 = proxy_get("/notices/1", {"Accept-Language": "zh-CN"})
    s2, h2, _ = proxy_get("/notices/1", {"Accept-Language": "zh-CN"})
    check("首次 MISS", h1.get("x-cache") == "MISS", h1.get("x-cache"))
    check("二次 HIT", h2.get("x-cache") == "HIT", h2.get("x-cache"))
    check("两次仅一次上游请求", upstream_count(token) - n0 == 1)
    check("HIT 响应 Age 头存在", h2.get("age") is not None)

    section("2. 缓存键按 Accept-Language 区分")
    n0 = upstream_count(token)
    s3, h3, b3 = proxy_get("/notices/1", {"Accept-Language": "en-US"})
    check("新语言 MISS", h3.get("x-cache") == "MISS", h3.get("x-cache"))
    zh = json.loads(b1)["language"]
    en = json.loads(b3)["language"]
    check("语言内容不同", zh != en, f"{zh} vs {en}")
    s4, h4, _ = proxy_get("/notices/1", {"Accept-Language": "en-US"})
    check("新语言二次 HIT", h4.get("x-cache") == "HIT")
    check("两种语言各打一次上游", upstream_count(token) - n0 == 1)

    section("3. 业务 Cookie / Authorization 直连，绕过缓存且不污染缓存")
    n0 = upstream_count(token)
    s5, h5, _ = proxy_get("/notices/1",
                          {"Accept-Language": "zh-CN", "Cookie": "SID=u1"})
    check("业务 Cookie 请求 BYPASS", h5.get("x-cache") == "BYPASS",
          h5.get("x-cache"))
    s6, h6, _ = proxy_get(
        "/notices/1",
        {"Accept-Language": "zh-CN", "Authorization": "Bearer t"},
    )
    check("Auth 请求 BYPASS", h6.get("x-cache") == "BYPASS", h6.get("x-cache"))
    check("两次绕过都打了上游", upstream_count(token) - n0 == 2)
    s7, h7, _ = proxy_get("/notices/1", {"Accept-Language": "zh-CN"})
    check("绕过后匿名仍 HIT（缓存未被污染）", h7.get("x-cache") == "HIT",
          h7.get("x-cache"))

    section("3.1 管理 Cookie 不触发绕过、不发往上游")
    # 仅携带管理 Cookie 的公告请求必须走缓存
    n0 = upstream_count(token)
    sa, ha, _ = proxy_get(
        "/notices/2",
        {"Accept-Language": "ko-KR", "Cookie": f"proxy_admin_sid={token}"},
    )
    sb, hb, _ = proxy_get(
        "/notices/2",
        {"Accept-Language": "ko-KR", "Cookie": f"proxy_admin_sid={token}"},
    )
    check("仅管理 Cookie：首次 MISS（未 BYPASS）",
          ha.get("x-cache") == "MISS", ha.get("x-cache"))
    check("仅管理 Cookie：二次 HIT", hb.get("x-cache") == "HIT",
          hb.get("x-cache"))
    check("两次只打一次上游", upstream_count(token) - n0 == 1)
    _, _, req_body = proxy_call("GET", "/proxy/upstream/requests", token)
    recent = [r for r in json.loads(req_body)["requests"]
              if r["notice_id"] == "2"][:2]
    check("上游审计 has_cookie=false（管理 Cookie 已剥离）",
          all(r["has_cookie"] is False for r in recent), str(recent))
    # 管理 Cookie + 业务 Cookie 混合：业务 Cookie 仍生效、管理部分被剥离
    sc, hc, _ = proxy_get(
        "/notices/2",
        {"Accept-Language": "ko-KR",
         "Cookie": f"SID=emp; proxy_admin_sid={token}"},
    )
    check("混合 Cookie：业务身份仍触发 BYPASS",
          hc.get("x-cache") == "BYPASS", hc.get("x-cache"))
    _, _, req_body2 = proxy_call("GET", "/proxy/upstream/requests", token)
    mixed = json.loads(req_body2)["requests"][0]
    check("混合请求上游只见业务 Cookie、不见管理 Cookie",
          mixed["has_cookie"] is True, str(mixed))

    section("4. personal 响应（Set-Cookie + private,no-store）不缓存")
    admin_post_via_proxy(token, "/proxy/upstream/config",
                         {"notice_id": "2", "profile": "personal"})
    n0 = upstream_count(token)
    s8, h8, _ = proxy_get("/notices/2", {"Accept-Language": "zh-CN"})
    check("personal 首次 MISS-NO-CACHE",
          h8.get("x-cache") == "MISS-NO-CACHE", h8.get("x-cache"))
    check("personal 响应带回 Set-Cookie", "set-cookie" in h8)
    s9, h9, _ = proxy_get("/notices/2", {"Accept-Language": "zh-CN"})
    check("personal 再次仍是 MISS-NO-CACHE",
          h9.get("x-cache") == "MISS-NO-CACHE", h9.get("x-cache"))
    check("每次都打上游（无缓存）", upstream_count(token) - n0 == 2)

    section("5. 上游 500：不缓存，所有并发等待者都收到失败")
    admin_post_via_proxy(token, "/proxy/upstream/config",
                         {"notice_id": "3", "failure": "error500",
                          "latency_ms": 300})
    results = []
    threads = [
        threading.Thread(target=lambda: results.append(
            proxy_get("/notices/3", {"Accept-Language": "zh-CN"})))
        for _ in range(4)
    ]
    for t in threads: t.start()
    for t in threads: t.join()
    check("4 个并发全部 502", all(r[0] == 502 for r in results),
          str([r[0] for r in results]))
    check("全部标记 ERROR",
          all(r[1].get("x-cache") == "ERROR" for r in results))
    s10, h10, _ = proxy_get("/notices/3", {"Accept-Language": "zh-CN"})
    check("失败后再次请求仍重新打上游（未缓存失败）",
          h10.get("x-cache") == "ERROR")
    admin_post_via_proxy(token, "/proxy/upstream/config",
                         {"notice_id": "3", "failure": "none",
                          "latency_ms": 100})

    section("6. 同键并发未命中只请求上游一次")
    admin_post_via_proxy(token, "/proxy/upstream/config",
                         {"notice_id": "1", "latency_ms": 1500,
                          "profile": "public", "max_age": 30})
    admin_post_via_proxy(token, "/proxy/purge/1", {})
    n0 = upstream_count(token)
    conc: list = []
    threads = [
        threading.Thread(target=lambda: conc.append(
            proxy_get("/notices/1", {"Accept-Language": "fr-FR"}, timeout=20)))
        for _ in range(6)
    ]
    t0 = time.monotonic()
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.monotonic() - t0
    tags = [r[1].get("x-cache") for r in conc]
    check("6 个请求全部 200", all(r[0] == 200 for r in conc))
    check("恰好 1 个 MISS + 5 个 MISS-WAIT",
          sorted(tags).count("MISS") == 1 and tags.count("MISS-WAIT") == 5,
          str(tags))
    check("上游只收到 1 次请求", upstream_count(token) - n0 == 1)
    check("总耗时≈单次延迟而非 6 倍", elapsed < 3.5, f"{elapsed:.2f}s")
    rids = {r[1].get("x-upstream-request-id") for r in conc}
    check("所有等待者拿到同一上游响应", len(rids) == 1, str(rids))

    section("7. 等待者断开不影响其他等待者")
    admin_post_via_proxy(token, "/proxy/upstream/config",
                         {"notice_id": "1", "latency_ms": 2000})
    admin_post_via_proxy(token, "/proxy/purge/1", {})
    got: list = []

    def slow_waiter():
        try:
            got.append(proxy_get("/notices/1",
                                 {"Accept-Language": "de-DE"}, timeout=20))
        except Exception as e:  # noqa: BLE001
            got.append(("ERR", {}, str(e).encode()))

    def disconnecting_waiter():
        try:
            proxy_get("/notices/1", {"Accept-Language": "de-DE"}, timeout=0.4)
        except Exception:
            pass

    t_a = threading.Thread(target=slow_waiter)
    t_b = threading.Thread(target=disconnecting_waiter)
    t_a.start(); time.sleep(0.15); t_b.start()
    t_b.join(); t_a.join()
    check("断开发生后其他等待者仍拿到 200",
          len(got) == 1 and got[0][0] == 200, str(got[:1]))
    n0 = upstream_count(token)
    _, h_after, _ = proxy_get("/notices/1", {"Accept-Language": "de-DE"})
    check("leader 结果已正常回填（后续 HIT）",
          h_after.get("x-cache") == "HIT", h_after.get("x-cache"))
    check("回填验证未再打上游", upstream_count(token) - n0 == 0)

    section("8. 过期不复用")
    admin_post_via_proxy(token, "/proxy/upstream/config",
                         {"notice_id": "1", "latency_ms": 50,
                          "profile": "public", "max_age": 2})
    admin_post_via_proxy(token, "/proxy/purge/1", {})
    _, h_a, _ = proxy_get("/notices/1", {"Accept-Language": "it-IT"})
    check("短 max-age 首次 MISS", h_a.get("x-cache") == "MISS")
    _, h_b, _ = proxy_get("/notices/1", {"Accept-Language": "it-IT"})
    check("未过期 HIT", h_b.get("x-cache") == "HIT", h_b.get("x-cache"))
    time.sleep(2.3)
    n0 = upstream_count(token)
    _, h_c, _ = proxy_get("/notices/1", {"Accept-Language": "it-IT"})
    check("过期后重新 MISS（不复用）", h_c.get("x-cache") == "MISS",
          h_c.get("x-cache"))
    check("过期请求确实打了上游", upstream_count(token) - n0 == 1)

    section("9. 按公告清除：全语言失效 + 旧在途不回填 + 不复用旧在途")
    admin_post_via_proxy(token, "/proxy/upstream/config",
                         {"notice_id": "1", "latency_ms": 2500,
                          "profile": "public", "max_age": 30})
    proxy_get("/notices/1", {"Accept-Language": "zh-CN"})
    proxy_get("/notices/1", {"Accept-Language": "en-US"})
    st = json.loads(proxy_call("GET", "/proxy/state", token)[2])
    cached_langs = {c["accept_language"] for c in st["cache"]
                    if c["notice_id"] == "1"}
    check("清除前两种语言均已缓存",
          {"zh-CN", "en-US"}.issubset(cached_langs), str(cached_langs))
    box: list = []
    threads = [
        threading.Thread(target=lambda: box.append(
            proxy_get("/notices/1", {"Accept-Language": "ja-JP"}, timeout=20)))
        for _ in range(3)
    ]
    for t in threads: t.start()
    time.sleep(0.4)
    st_mid = json.loads(proxy_call("GET", "/proxy/state", token)[2])
    check("清除前存在 1 个在途单元",
          any(i["notice_id"] == "1" for i in st_mid["inflight"]))
    purge_status, _, purge_body = admin_post_via_proxy(
        token, "/proxy/purge/1", {})
    purge = json.loads(purge_body)
    check("清除接口 200 且报告全语言条目删除",
          purge_status == 200 and purge["purged_cache_entries"] >= 2, str(purge))
    check("清除接口标记了在途单元", purge["marked_inflight"] >= 1, str(purge))
    for t in threads: t.join()
    check("在途等待者均拿到当时响应（200）",
          all(r[0] == 200 for r in box), str([r[0] for r in box]))
    time.sleep(0.2)
    st_after = json.loads(proxy_call("GET", "/proxy/state", token)[2])
    check("旧在途完成后未回填缓存",
          all(c["notice_id"] != "1" for c in st_after["cache"]),
          str(st_after["cache"]))
    n0 = upstream_count(token)
    _, h_new, _ = proxy_get("/notices/1", {"Accept-Language": "ja-JP"})
    check("清除后新请求重新 MISS（不复用旧在途）",
          h_new.get("x-cache") == "MISS", h_new.get("x-cache"))
    check("新请求确实重新打了上游", upstream_count(token) - n0 == 1)
    _, h_zh, _ = proxy_get("/notices/1", {"Accept-Language": "zh-CN"})
    check("旧语言缓存同样已失效", h_zh.get("x-cache") == "MISS",
          h_zh.get("x-cache"))

    section("10. 非法 Cache-Control 不缓存（经上游自定义头）")
    bad_headers = [
        "max-age=30", "public", "public, max-age=-5",
        "public, max-age=1.5", "public, max-age=abc",
        "public, max-age=30, no-store", "public, max-age=30, private",
        "public, max-age=",
    ]
    for i, cc in enumerate(bad_headers):
        nid = str(100 + i)
        admin_post_via_proxy(token, "/proxy/upstream/config",
                             {"notice_id": nid, "cache_control": cc,
                              "latency_ms": 0})
        _, hh1, _ = proxy_get(f"/notices/{nid}", {"Accept-Language": "zh-CN"})
        _, hh2, _ = proxy_get(f"/notices/{nid}", {"Accept-Language": "zh-CN"})
        check(f"不缓存 [{cc}]",
              hh1.get("x-cache") == "MISS-NO-CACHE"
              and hh2.get("x-cache") == "MISS-NO-CACHE",
              f"{hh1.get('x-cache')} / {hh2.get('x-cache')}")
    _, h404, _ = proxy_get("/notices/404-missing",
                           {"Accept-Language": "zh-CN"})
    check("404 不缓存", h404.get("x-cache") == "MISS-NO-CACHE",
          h404.get("x-cache"))

    # ---------------- 会话与退出收尾 ----------------

    section("11. 慢配置期间退出：先禁用、再等待；重复退出共享；互不影响")
    admin_reset(token)
    # 另一个会话用于验证“其他会话不受等待影响”
    _, _, _, token_other, _ = login()
    drain_token_box: dict = {}
    _, _, _, drain_token, _ = login()

    t0 = time.monotonic()
    cfg_box: dict = {}

    def submit_slow_config():
        st, hs, body = admin_post_via_proxy(
            drain_token, "/proxy/upstream/config",
            {"latency_ms": 100, "max_age": 30, "delay_ms": 5000},
            timeout=15,
        )
        cfg_box.update(status=st, body=json.loads(body))

    cfg_thread = threading.Thread(target=submit_slow_config)
    cfg_thread.start()
    time.sleep(0.5)  # 确保写操作已在途

    logout_results: list = []

    def do_logout(label: str, delay: float = 0.0):
        time.sleep(delay)
        st, hs, body = proxy_call("POST", "/proxy/logout", drain_token,
                                  with_origin=True, timeout=15)
        logout_results.append((label, st, json.loads(body)))

    lg1 = threading.Thread(target=do_logout, args=("logout#1", 0.0))
    lg2 = threading.Thread(target=do_logout, args=("logout#2", 0.2))
    lg1.start(); lg2.start()
    time.sleep(0.9)
    # drain 期间：该会话新管理请求被拒
    s_drain, _, drain_err = proxy_call("GET", "/proxy/state", drain_token)
    err_json = json.loads(drain_err)
    check("drain 中该会话新管理请求 -> 401 session_disabled",
          s_drain == 401 and err_json.get("error") == "session_disabled",
          f"{s_drain} {drain_err[:80]}")
    # drain 期间：写请求同样被拒
    s_drain_post, _, _ = admin_post_via_proxy(
        drain_token, "/proxy/reset", {})
    check("drain 中该会话新写请求 -> 401", s_drain_post == 401,
          str(s_drain_post))
    # 公告访问全程不受影响
    s_notice, h_notice, _ = proxy_get("/notices/1",
                                      {"Accept-Language": "zh-CN"})
    check("drain 期间公告访问仍 200", s_notice == 200, str(s_notice))
    # 其他会话管理能力不受影响
    s_other, _, other_body = proxy_call(
        "GET", "/proxy/state", token_other)
    check("其他会话管理访问不受影响（200）", s_other == 200, str(s_other))
    lg1.join(); lg2.join(); cfg_thread.join()
    elapsed = time.monotonic() - t0
    check("慢配置写操作最终成功（200）",
          cfg_box.get("status") == 200 and cfg_box["body"].get("ok") is True,
          str(cfg_box)[:120])
    check("两个退出均 200 且 status=completed",
          len(logout_results) == 2
          and all(st == 200 and b["status"] == "completed"
                  for _, st, b in logout_results),
          str(logout_results)[:160])
    ids = {b["session_id"] for _, _, b in logout_results}
    check("重复退出共享同一会话的同一 drain 结果",
          len(ids) == 1 and logout_results[0][2] == logout_results[1][2],
          str(ids))
    waited = logout_results[0][2]["waited_operations"]
    check("退出结果包含被等待的 upstream.config 操作",
          any(op["kind"] == "upstream.config" and op["status"] == "completed"
              for op in waited), str(waited))
    check("整体耗时≈慢配置延迟（等待真实发生）",
          4.5 < elapsed < 9, f"{elapsed:.2f}s")
    # 退出后 Cookie 已失效
    s_after, _, _ = proxy_call("GET", "/proxy/session", drain_token)
    check("退出后原会话 Cookie 失效（401）", s_after == 401, str(s_after))
    # 其他会话仍可正常退出（互不影响）
    s_lo, _, lo_body = proxy_call("POST", "/proxy/logout", token_other,
                                  with_origin=True)
    check("其他会话可独立退出成功",
          s_lo == 200 and json.loads(lo_body)["status"] == "completed",
          f"{s_lo} {lo_body[:80]}")
    # 慢配置确实在上游生效
    st_live = upstream_state(token)
    check("慢配置实际生效（latency_ms=100 被上游记录）",
          st_live["defaults"]["latency_ms"] == 100,
          str(st_live["defaults"]))

    section("12. 写超时/回执不明：504 -> 退出 incomplete，会话保持禁用")
    _, _, _, tok_amb, _ = login()
    t0 = time.monotonic()
    s_to, _, body_to = admin_post_via_proxy(
        tok_amb, "/proxy/upstream/config",
        {"latency_ms": 120, "delay_ms": 12000}, timeout=15,
    )
    to_json = json.loads(body_to)
    check("超时写返回 504 且标记 ambiguous",
          s_to == 504 and to_json.get("receipt") == "ambiguous",
          f"{s_to} {body_to[:100]}")
    check("约在管理超时（8s）后返回",
          7.5 < time.monotonic() - t0 < 10,
          f"{time.monotonic() - t0:.2f}s")
    s_lo2, _, lo_body2 = proxy_call("POST", "/proxy/logout", tok_amb,
                                    with_origin=True, timeout=15)
    lo2 = json.loads(lo_body2)
    check("退出返回 200 但 status=incomplete",
          s_lo2 == 200 and lo2["status"] == "incomplete",
          f"{s_lo2} {lo_body2[:100]}")
    check("结果列出 ambiguous 操作",
          any(op["status"] == "ambiguous"
              for op in lo2["incomplete_operations"]),
          str(lo2.get("incomplete_operations")))
    s_disabled, _, _ = proxy_call("GET", "/proxy/session", tok_amb)
    check("incomplete 后会话仍禁用（401，不能报成功）",
          s_disabled == 401, str(s_disabled))
    # 等待上游把延迟提交实际处理完，核对真实生效结果
    time.sleep(6)
    st_final = upstream_state(token)
    check("回执不明的写最终在上游实际生效（latency_ms=120）",
          st_final["defaults"]["latency_ms"] == 120,
          str(st_final["defaults"]))

    section("13. 写请求客户端断连：后台收尾继续，退出仍等待到完成")
    _, _, _, tok_dc, _ = login()
    try:
        # 1s 客户端超时主动断连，上游 5s 后才完成提交
        admin_post_via_proxy(
            tok_dc, "/proxy/upstream/config",
            {"latency_ms": 250, "delay_ms": 5000}, timeout=1,
        )
        check("客户端按预期超时断连", False, "未触发断连")
    except (TimeoutError, OSError, http.client.HTTPException):
        check("客户端按预期超时断连", True)
    t0 = time.monotonic()
    s_dc, _, dc_body = proxy_call("POST", "/proxy/logout", tok_dc,
                                  with_origin=True, timeout=15)
    dc = json.loads(dc_body)
    waited_dc = dc.get("waited_operations", [])
    check("退出等待断连写任务真实收尾（耗时≈剩余延迟）",
          s_dc == 200 and 3.0 < time.monotonic() - t0 < 7,
          f"{s_dc} {time.monotonic() - t0:.2f}s")
    check("断连写任务终态为 completed（后台继续执行）",
          dc["status"] == "completed"
          and any(op["kind"] == "upstream.config"
                  and op["status"] == "completed" for op in waited_dc),
          str(waited_dc))
    check("断连的写操作实际生效（latency_ms=250）",
          upstream_state(token)["defaults"]["latency_ms"] == 250)

    section("14. 重启失效语义（单元层）与无状态令牌校验")
    # 随机令牌：两次登录令牌不同且无规律
    _, _, _, ta, _ = login()
    _, _, _, tb, _ = login()
    check("两次登录签发不同随机令牌", ta != tb and len(ta) >= 32,
          f"{ta[:8]} vs {tb[:8]}")
    # 清理这两个会话
    for tk in (ta, tb):
        proxy_call("POST", "/proxy/logout", tk, with_origin=True)

    print(f"\n========== 结果：{PASS} 通过 / {FAIL} 失败 ==========")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
