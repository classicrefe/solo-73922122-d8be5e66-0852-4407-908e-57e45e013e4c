#!/usr/bin/env python3
"""纯单元测试：Cache-Control 解析、缓存资格判定、CacheStore 代际/合并逻辑。

运行：python3 -I -m unittest scripts.test_units -v
（不依赖网络与第三方库，cachestore 仅用 stdlib）
"""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy.cachestore import (
    CachedResponse,
    CacheHit,
    CacheLeader,
    CacheStore,
    CacheWait,
)
from proxy.policy import cache_eligibility, parse_cache_control
from proxy.sessions import (
    ADMIN_COOKIE_NAME,
    SessionDisabled,
    SessionRegistry,
    SessionState,
    parse_cookies,
    strip_admin_cookie,
)


class PolicyParseTests(unittest.TestCase):
    def test_basic_directives(self):
        d = parse_cache_control("public, max-age=30, no-transform")
        self.assertEqual(d["public"], True)
        self.assertEqual(d["no-transform"], True)
        self.assertEqual(d["max-age"], "30")

    def test_case_insensitive_and_whitespace(self):
        d = parse_cache_control(" Public , MAX-AGE = 60 ")
        self.assertIn("public", d)
        self.assertEqual(d["max-age"], "60")

    def test_quoted_value(self):
        d = parse_cache_control('public, max-age="45"')
        self.assertEqual(d["max-age"], "45")

    def test_empty(self):
        self.assertEqual(parse_cache_control(None), {})
        self.assertEqual(parse_cache_control(""), {})


class EligibilityTests(unittest.TestCase):
    @staticmethod
    def _hdrs(cc=None, set_cookie=False):
        h = []
        if cc is not None:
            h.append(("Cache-Control", cc))
        if set_cookie:
            h.append(("Set-Cookie", "SID=x"))
        return h

    def test_eligible(self):
        ok, reason, age = cache_eligibility(200, self._hdrs("public, max-age=30"))
        self.assertTrue(ok)
        self.assertEqual(age, 30)

    def test_zero_max_age_allowed_but_immediately_stale(self):
        ok, _, age = cache_eligibility(200, self._hdrs("public, max-age=0"))
        self.assertTrue(ok)
        self.assertEqual(age, 0)

    def test_non_200(self):
        ok, _, age = cache_eligibility(404, self._hdrs("public, max-age=30"))
        self.assertFalse(ok)
        self.assertIsNone(age)

    def test_set_cookie_blocks(self):
        ok, reason, _ = cache_eligibility(
            200, self._hdrs("public, max-age=30", set_cookie=True)
        )
        self.assertFalse(ok)
        self.assertIn("Set-Cookie", reason)

    def test_missing_cc(self):
        ok, _, _ = cache_eligibility(200, self._hdrs(None))
        self.assertFalse(ok)

    def test_private_no_store(self):
        for cc in (
            "private, max-age=30",
            "public, max-age=30, no-store",
            "no-store",
            "public, private, max-age=30",
        ):
            ok, _, _ = cache_eligibility(200, self._hdrs(cc))
            self.assertFalse(ok, cc)

    def test_bad_max_age(self):
        for cc in (
            "public",
            "public, max-age",
            "public, max-age=-1",
            "public, max-age=1.0",
            "public, max-age=abc",
            "public, max-age=",
            "public, max-age=30, max-age=60",
        ):
            ok, _, _ = cache_eligibility(200, self._hdrs(cc))
            self.assertFalse(ok, cc)

    def test_multiple_cc_headers_merged(self):
        headers = [("Cache-Control", "public"), ("Cache-Control", "max-age=12")]
        ok, _, age = cache_eligibility(200, headers)
        self.assertTrue(ok)
        self.assertEqual(age, 12)
        headers2 = [
            ("Cache-Control", "public, max-age=12"),
            ("Cache-Control", "no-store"),
        ]
        ok2, _, _ = cache_eligibility(200, headers2)
        self.assertFalse(ok2)
        # 同一带值指令重复出现属非法，拒绝缓存
        headers3 = [
            ("Cache-Control", "public, max-age=12"),
            ("Cache-Control", "max-age=99"),
        ]
        ok3, reason, _ = cache_eligibility(200, headers3)
        self.assertFalse(ok3)
        self.assertIn("max-age", reason)


class CacheStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = CacheStore()

    @staticmethod
    def _entry(gen=0, ttl=30):
        import time

        now = time.monotonic()
        return CachedResponse(
            status_code=200,
            body=b"{}",
            headers=[(b"content-type", b"application/json")],
            cached_at=now,
            expires_at=now + ttl,
            max_age=ttl,
            generation=gen,
        )

    def _run(self, coro):
        return asyncio.run(coro)

    def test_first_lookup_is_leader_second_waits(self):
        async def scenario():
            key = self.store.make_key("1", "zh")
            d1 = await self.store.lookup(key, "1")
            d2 = await self.store.lookup(key, "1")
            self.assertIsInstance(d1, CacheLeader)
            self.assertIsInstance(d2, CacheWait)
            self.assertIs(d1.inflight, d2.inflight)
            return d1.inflight

        inflight = self._run(scenario())
        self.assertIsNotNone(inflight)

    def test_purge_blocks_backfill_and_new_lookup_is_new_generation(self):
        async def scenario():
            key = self.store.make_key("7", "zh")
            leader = await self.store.lookup(key, "7")
            inflight = leader.inflight
            info = await self.store.purge_notice("7")
            self.assertEqual(info["generation"], 1)
            self.assertEqual(info["marked_inflight"], 1)
            # 旧在途即使带了可缓存条目也禁止回填
            stored = await self.store.store_if_current(inflight, self._entry(0))
            self.assertFalse(stored)
            # 清除后的新 lookup 是新一代的 leader，不复用旧在途
            d2 = await self.store.lookup(key, "7")
            self.assertIsInstance(d2, CacheLeader)
            self.assertEqual(d2.inflight.generation, 1)
            self.assertIsNot(d2.inflight, inflight)

        self._run(scenario())

    def test_purge_removes_all_languages(self):
        async def scenario():
            for lang in ("zh", "en", "fr"):
                key = self.store.make_key("9", lang)
                leader = await self.store.lookup(key, "9")
                await self.store.store_if_current(
                    leader.inflight, self._entry()
                )
            # 另一个公告不应受影响
            other = self.store.make_key("10", "zh")
            lo = await self.store.lookup(other, "10")
            await self.store.store_if_current(lo.inflight, self._entry())
            info = await self.store.purge_notice("9")
            self.assertEqual(info["purged_cache_entries"], 3)
            snap = await self.store.snapshot()
            ids = {c["notice_id"] for c in snap["cache"]}
            self.assertEqual(ids, {"10"})

        self._run(scenario())

    def test_expired_entry_not_returned(self):
        import time

        async def scenario():
            key = self.store.make_key("5", "zh")
            leader = await self.store.lookup(key, "5")
            entry = self._entry(ttl=0)
            entry.cached_at = time.monotonic() - 1
            entry.expires_at = time.monotonic() - 0.01
            await self.store.store_if_current(leader.inflight, entry)
            decision = await self.store.lookup(key, "5")
            self.assertIsInstance(decision, CacheLeader)  # 过期 -> 新 leader

        self._run(scenario())

    def test_failure_drops_inflight_and_future_raises(self):
        async def scenario():
            key = self.store.make_key("6", "zh")
            leader = await self.store.lookup(key, "6")
            await self.store.fail_all(leader.inflight, RuntimeError("boom"))
            snap = await self.store.snapshot()
            self.assertEqual(snap["inflight"], [])
            with self.assertRaises(RuntimeError):
                await leader.inflight.future

        self._run(scenario())


class CookieHelperTests(unittest.TestCase):
    def test_parse_cookies(self):
        self.assertEqual(
            parse_cookies("SID=a; proxy_admin_sid=secret; role=x"),
            {"SID": "a", "proxy_admin_sid": "secret", "role": "x"},
        )
        self.assertEqual(parse_cookies(None), {})
        self.assertEqual(parse_cookies(""), {})
        self.assertEqual(parse_cookies("garbage"), {})

    def test_strip_admin_cookie(self):
        self.assertEqual(
            strip_admin_cookie("SID=a; proxy_admin_sid=secret; role=x"),
            "SID=a; role=x",
        )
        # 只剩管理 Cookie 时返回空串（代理将不转发 Cookie 头）
        self.assertEqual(strip_admin_cookie(f"{ADMIN_COOKIE_NAME}=secret"), "")
        self.assertEqual(strip_admin_cookie(None), "")
        # 无管理 Cookie 时原样保留
        self.assertEqual(strip_admin_cookie("SID=a; role=x"), "SID=a; role=x")


class SessionRegistryTests(unittest.TestCase):
    def _run(self, coro):
        return asyncio.run(coro)

    def test_create_session_random_tokens_and_restart_invalidation(self):
        async def scenario():
            reg = SessionRegistry()
            s1 = reg.create_session()
            s2 = reg.create_session()
            self.assertNotEqual(s1.token, s2.token)
            self.assertGreaterEqual(len(s1.token), 32)
            self.assertIs(reg.get(s1.token), s1)
            self.assertIsNone(reg.get("nope"))
            # 新 registry 模拟进程重启：旧令牌全部失效
            reg2 = SessionRegistry()
            self.assertIsNone(reg2.get(s1.token))

        self._run(scenario())

    def test_logout_waits_for_completed_write_and_disables_session(self):
        async def scenario():
            reg = SessionRegistry()
            s = reg.create_session()
            op = await reg.begin_op(s, "proxy.purge")

            async def slow_work():
                await asyncio.sleep(0.15)
                return type("O", (), {"terminal": "completed", "note": "ok"})()

            reg.spawn(s, op, slow_work)
            # 写操作在途时发起退出
            logout = asyncio.create_task(reg.logout(s))
            await asyncio.sleep(0.02)
            # 退出已禁用会话：新写操作必须被拒绝
            with self.assertRaises(SessionDisabled):
                await reg.begin_op(s, "proxy.purge")
            result = await logout
            self.assertEqual(result["status"], "completed")
            self.assertEqual(s.state, SessionState.CLOSED)
            # 关闭后仍拒绝新操作
            with self.assertRaises(SessionDisabled):
                await reg.begin_op(s, "proxy.purge")
            self.assertEqual(result["waited_operations"][0]["status"], "completed")

        self._run(scenario())

    def test_ambiguous_write_makes_logout_incomplete_and_session_stays_disabled(self):
        async def scenario():
            reg = SessionRegistry()
            s = reg.create_session()
            op1 = await reg.begin_op(s, "upstream.config")
            op2 = await reg.begin_op(s, "proxy.reset")

            async def ambiguous_work():
                await asyncio.sleep(0.05)
                return type("O", (), {
                    "terminal": "ambiguous", "note": "timed out"})()

            async def ok_work():
                return type("O", (), {"terminal": "completed", "note": "ok"})()

            reg.spawn(s, op1, ambiguous_work)
            reg.spawn(s, op2, ok_work)
            result = await reg.logout(s)
            self.assertEqual(result["status"], "incomplete")
            self.assertTrue(result["incomplete_operations"])
            self.assertEqual(s.state, SessionState.CLOSED)  # 终态但禁用
            with self.assertRaises(SessionDisabled):
                await reg.begin_op(s, "upstream.config")

        self._run(scenario())

    def test_duplicate_logout_shares_single_drain(self):
        async def scenario():
            reg = SessionRegistry()
            s = reg.create_session()
            op = await reg.begin_op(s, "upstream.config")

            async def slow_work():
                await asyncio.sleep(0.2)
                return type("O", (), {"terminal": "completed", "note": "ok"})()

            reg.spawn(s, op, slow_work)
            r1, r2 = await asyncio.gather(reg.logout(s), reg.logout(s))
            self.assertIs(r1, r2)  # 共享同一结果对象
            self.assertEqual(r1["status"], "completed")
            # 已关闭会话再次退出直接返回同一结果
            r3 = await reg.logout(s)
            self.assertIs(r3, r1)
            self.assertIsNotNone(s.drain_task)
            self.assertTrue(s.drain_task.done())

        self._run(scenario())

    def test_disconnecting_route_does_not_cancel_tracked_write(self):
        async def scenario():
            reg = SessionRegistry()
            s = reg.create_session()
            op = await reg.begin_op(s, "upstream.config")
            started = asyncio.Event()

            async def work():
                started.set()
                await asyncio.sleep(0.15)
                return type("O", (), {"terminal": "completed", "note": "ok"})()

            task = reg.spawn(s, op, work)
            await started.wait()
            # 模拟路由处理任务被取消（客户端断连）：写任务不受影响
            route = asyncio.create_task(asyncio.sleep(1))
            route.cancel()
            try:
                await route
            except asyncio.CancelledError:
                pass
            result = await reg.logout(s)
            self.assertEqual(result["status"], "completed")
            self.assertTrue(task.done())

        self._run(scenario())


if __name__ == "__main__":
    unittest.main(verbosity=2)
