# -*- coding: utf-8 -*-
"""Resin 粘性代理池接入单元测试。"""
from __future__ import annotations

import unittest

from backend.integrations import resin

BASE = {
    "resin_url": "http://127.0.0.1:2260/my-token",
    "resin_platform_name": "Default",
}


class ParseResinUrlTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(
            resin.parse_resin_url("http://127.0.0.1:2260/my-token"),
            ("http", "127.0.0.1:2260", "my-token"),
        )

    def test_https_with_port(self):
        self.assertEqual(
            resin.parse_resin_url("https://proxy.example.com:8443/abc123"),
            ("https", "proxy.example.com:8443", "abc123"),
        )

    def test_platform_default(self):
        self.assertEqual(resin.resin_platform(BASE), "Default")
        self.assertEqual(
            resin.resin_platform(
                {"resin_url": "http://x:1/t", "resin_platform_name": "GrokReg"}
            ),
            "GrokReg",
        )

    def test_missing_token(self):
        with self.assertRaises(ValueError):
            resin.parse_resin_url("http://127.0.0.1:2260")

    def test_invalid_scheme(self):
        with self.assertRaises(ValueError):
            resin.parse_resin_url("socks5://127.0.0.1:2260/tok")

    def test_token_with_slash(self):
        with self.assertRaises(ValueError):
            resin.parse_resin_url("http://127.0.0.1:2260/a/b")

    def test_validate_returns_trimmed(self):
        self.assertEqual(
            resin.validate_resin_url("  http://127.0.0.1:2260/my-token  "),
            "http://127.0.0.1:2260/my-token",
        )


class EnabledTests(unittest.TestCase):
    def test_enabled(self):
        self.assertTrue(resin.resin_enabled(BASE))

    def test_disabled_empty_url(self):
        self.assertFalse(
            resin.resin_enabled({"resin_url": "", "resin_platform_name": "Default"})
        )

    def test_disabled_bad_platform(self):
        self.assertFalse(
            resin.resin_enabled(
                {"resin_url": "http://127.0.0.1:2260/t", "resin_platform_name": "Bad.Name"}
            )
        )


class ForwardProxyTests(unittest.TestCase):
    def test_forward_url_encodes_account(self):
        # 邮箱统一小写（账号标识稳定）+ 特殊字符百分号编码
        url = resin.forward_proxy_url("Tom@example.com", config=BASE)
        self.assertEqual(
            url,
            "http://Default.tom%40example.com:my-token@127.0.0.1:2260",
        )

    def test_forward_url_account_with_specials(self):
        # Account 可包含 : . @ 等特殊字符（Resin 按第一个 . 与最后一个 : 分割）
        url = resin.forward_proxy_url("Tom:Sub.User+tag@example.com", config=BASE)
        self.assertTrue(url.startswith("http://Default."))
        self.assertTrue(url.endswith("@127.0.0.1:2260"))
        self.assertIn(":my-token@", url)
        # 用户名必须被百分号编码，避免破坏 URL 结构
        self.assertNotIn("Tom:Sub", url.split("://", 1)[1].split("@", 1)[0])

    def test_disabled(self):
        self.assertEqual(
            resin.forward_proxy_url(
                "Tom@example.com",
                config={"resin_url": "", "resin_platform_name": "Default"},
            ),
            "",
        )

    def test_no_account(self):
        self.assertEqual(resin.forward_proxy_url("", config=BASE), "")

    def test_forward_parts(self):
        parts = resin.forward_proxy_parts("Tom@Example.com", config=BASE)
        self.assertEqual(
            parts,
            {
                "server": "http://127.0.0.1:2260",
                "username": "Default.tom@example.com",
                "password": "my-token",
            },
        )

    def test_forward_parts_disabled(self):
        self.assertEqual(
            resin.forward_proxy_parts("Tom@example.com", config={"resin_url": ""}),
            {},
        )


class ReverseProxyTests(unittest.TestCase):
    def test_reverse_url(self):
        url = resin.reverse_proxy_url(
            "https://api.example.com/healthz?x=1&y=2", "Tom", config=BASE
        )
        self.assertEqual(
            url,
            "http://127.0.0.1:2260/my-token/Default/https/api.example.com/healthz?x=1&y=2",
        )

    def test_reverse_url_with_port(self):
        url = resin.reverse_proxy_url(
            "http://10.0.0.8:8080/api/ping", "Tom", config=BASE
        )
        self.assertEqual(
            url,
            "http://127.0.0.1:2260/my-token/Default/http/10.0.0.8:8080/api/ping",
        )

    def test_reverse_headers(self):
        self.assertEqual(
            resin.reverse_headers("Tom"), {"X-Resin-Account": "Tom"}
        )


class IdentityTests(unittest.TestCase):
    def tearDown(self):
        resin.clear_current_account()

    def test_email_lowercase(self):
        self.assertEqual(resin.normalize_account(" Tom@Example.COM "), "tom@example.com")

    def test_non_email_unchanged(self):
        self.assertEqual(resin.normalize_account("user-123"), "user-123")

    def test_temp_identity_unique(self):
        first = resin.new_temp_identity()
        second = resin.new_temp_identity()
        self.assertTrue(first.startswith("temp-"))
        self.assertNotEqual(first, second)

    def test_thread_local(self):
        resin.clear_current_account()
        self.assertEqual(resin.current_account(), "")
        resin.set_current_account("Tom@Example.com")
        self.assertEqual(resin.current_account(), "tom@example.com")
        resin.clear_current_account()
        self.assertEqual(resin.current_account(), "")

    def test_account_proxy_resolution(self):
        resin.clear_current_account()
        self.assertEqual(resin.current_account_proxy(config=BASE), "")
        self.assertEqual(
            resin.account_proxy("Tom@Example.com", config=BASE),
            resin.forward_proxy_url("tom@example.com", config=BASE),
        )
        resin.set_current_account("Tom@Example.com")
        self.assertEqual(
            resin.current_account_proxy(config=BASE),
            resin.forward_proxy_url("tom@example.com", config=BASE),
        )

    def test_flow_account_prefers_thread_local(self):
        # 继承失败时线程身份保持临时身份：显式稳定邮箱必须让位，保持出口一致
        resin.set_current_account("temp-abc123")
        self.assertEqual(
            resin.account_proxy("Tom@example.com", config=BASE),
            resin.forward_proxy_url("temp-abc123", config=BASE),
        )


class InheritLeaseTests(unittest.TestCase):
    def tearDown(self):
        resin.clear_current_account()

    def test_inherit_url(self):
        self.assertEqual(
            resin.inherit_lease_url(BASE),
            "http://127.0.0.1:2260/my-token/api/v1/Default/actions/inherit-lease",
        )

    def test_inherit_url_custom_platform(self):
        cfg = dict(BASE, resin_platform_name="GrokReg")
        self.assertEqual(
            resin.inherit_lease_url(cfg),
            "http://127.0.0.1:2260/my-token/api/v1/GrokReg/actions/inherit-lease",
        )

    def test_on_email_acquired_switches(self):
        calls = []

        def fake_inherit(parent, new, config=None, timeout=20.0):
            calls.append((parent, new))
            return {"inherited": True}

        original = resin.inherit_lease
        resin.inherit_lease = fake_inherit
        try:
            resin.set_current_account("temp-abc123")
            resin.on_email_acquired("temp-abc123", "Tom@Example.com", config=BASE)
            self.assertEqual(calls, [("temp-abc123", "tom@example.com")])
            self.assertEqual(resin.current_account(), "tom@example.com")
        finally:
            resin.inherit_lease = original

    def test_on_email_acquired_keeps_temp_on_failure(self):
        def failing(parent, new, config=None, timeout=20.0):
            raise RuntimeError("inherit boom")

        original = resin.inherit_lease
        resin.inherit_lease = failing
        try:
            resin.set_current_account("temp-abc123")
            resin.on_email_acquired("temp-abc123", "Tom@Example.com", config=BASE)
            # 继承失败：保持临时身份，浏览器与 API 仍共用同一出口
            self.assertEqual(resin.current_account(), "temp-abc123")
        finally:
            resin.inherit_lease = original

    def test_on_email_acquired_without_resin(self):
        resin.set_current_account("temp-abc123")
        resin.on_email_acquired(
            "temp-abc123",
            "Tom@Example.com",
            config={"resin_url": "", "resin_platform_name": "Default"},
        )
        self.assertEqual(resin.current_account(), "tom@example.com")


if __name__ == "__main__":
    unittest.main()
