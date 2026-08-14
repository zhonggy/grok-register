# -*- coding: utf-8 -*-
"""启动预检失败分类测试：区分「出口临时不可用（可重试）」与「被 CF 拦截（不可重试）」。"""
from __future__ import annotations

import unittest

from backend.integrations.network_checks import (
    XAI_SIGNUP_CHECK_NAME,
    failure_is_retryable,
)


class FailureIsRetryableTests(unittest.TestCase):
    def test_connect_tunnel_failed_502(self):
        # 本次线上日志：Resin 无可用出口时 curl_cffi 的典型报错
        detail = (
            "Failed to perform, curl: (56) CONNECT tunnel failed, response 502. "
            "See https://curl.se/libcurl/c/libcurl-errors.html first for more details."
        )
        self.assertTrue(failure_is_retryable(XAI_SIGNUP_CHECK_NAME, detail))

    def test_timeout(self):
        self.assertTrue(
            failure_is_retryable(XAI_SIGNUP_CHECK_NAME, "Failed to perform, curl: (28) timeout")
        )

    def test_connection_reset(self):
        self.assertTrue(
            failure_is_retryable(XAI_SIGNUP_CHECK_NAME, "curl: (56) connection reset by peer")
        )

    def test_proxy_502(self):
        self.assertTrue(
            failure_is_retryable("代理", "136.85.72.141:2260 可用，出站探测失败: ... 502 ...")
        )

    def test_cloudflare_blocked_403(self):
        self.assertFalse(
            failure_is_retryable(XAI_SIGNUP_CHECK_NAME, "Cloudflare 拦截 HTTP 403；请更换当前 proxy 后重试")
        )

    def test_cloudflare_challenge_page(self):
        self.assertFalse(
            failure_is_retryable(XAI_SIGNUP_CHECK_NAME, "仍停留在 Cloudflare 挑战页")
        )

    def test_just_a_moment(self):
        self.assertFalse(
            failure_is_retryable(XAI_SIGNUP_CHECK_NAME, "HTTP 403 just a moment ...")
        )

    def test_unknown_failure_not_retryable(self):
        self.assertFalse(
            failure_is_retryable(XAI_SIGNUP_CHECK_NAME, "HTTP 500 internal error")
        )

    def test_empty_detail(self):
        self.assertFalse(failure_is_retryable(XAI_SIGNUP_CHECK_NAME, ""))


if __name__ == "__main__":
    unittest.main()
