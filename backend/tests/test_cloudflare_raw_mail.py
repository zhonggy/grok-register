"""验证 Cloudflare /api/mails 原始 MIME 正文能正确解出验证码。

cloudflare_temp_email 的 /api/mails、/admin/mails 按设计只返回 raw RFC822，
不保证带 subject/text/html。若直接对原文跑验证码正则，base64 正文、
quoted-printable 软换行、RFC2047 编码主题这三种情况都会漏码。
"""

import base64
import quopri
import unittest

from backend.mailbox import cloudflare_worker as cf
from backend.mailbox.utilities import extract_verification_code, parse_raw_email

CODE = "I6R-B2W"


def _b64_body(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class CloudflareRawMailTests(unittest.TestCase):
    def _extract(self, payload: dict):
        combined, subject = cf.collect_mail_text(payload)
        return extract_verification_code(combined, subject)

    def test_base64_html_body(self):
        html = f"<html><body><p>Your verification code is {CODE}</p></body></html>"
        raw = (
            "From: no-reply@x.ai\r\n"
            "To: user@example.com\r\n"
            "Subject: Your X verification code\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n" + _b64_body(html)
        )
        self.assertEqual(self._extract({"id": 1, "raw": raw}), CODE)

    def test_quoted_printable_soft_line_break(self):
        # QP 软换行会把 I6R-B2W 劈成 "I6R=\r\n-B2W"，不解码就匹配不到。
        body = quopri.encodestring(
            f"Your verification code is {CODE} - do not share it.".encode("utf-8")
        ).decode("ascii")
        raw = (
            "From: no-reply@x.ai\r\n"
            "Subject: verification\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "Content-Transfer-Encoding: quoted-printable\r\n"
            "\r\n" + body
        )
        self.assertEqual(self._extract({"id": 2, "raw": raw}), CODE)

    def test_forced_soft_break_inside_code(self):
        raw = (
            "From: no-reply@x.ai\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "Content-Transfer-Encoding: quoted-printable\r\n"
            "\r\n"
            "Your verification code is I6R=\r\n-B2W thanks"
        )
        self.assertEqual(self._extract({"id": 3, "raw": raw}), CODE)

    def test_rfc2047_encoded_subject(self):
        encoded = "=?UTF-8?B?" + _b64_body(f"Your code {CODE}") + "?="
        raw = (
            "From: no-reply@x.ai\r\n"
            f"Subject: {encoded}\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "See subject."
        )
        self.assertEqual(self._extract({"id": 4, "raw": raw}), CODE)

    def test_multipart_alternative_prefers_decoded_parts(self):
        html = f"<html><body>code: {CODE}</body></html>"
        raw = (
            "From: no-reply@x.ai\r\n"
            "Subject: X\r\n"
            'Content-Type: multipart/alternative; boundary="BOUND"\r\n'
            "\r\n"
            "--BOUND\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n" + _b64_body("plain part without code") + "\r\n"
            "--BOUND\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n" + _b64_body(html) + "\r\n"
            "--BOUND--\r\n"
        )
        self.assertEqual(self._extract({"id": 5, "raw": raw}), CODE)

    def test_style_block_in_raw_html_does_not_false_match(self):
        # 邮件模板 <style> 里的类名（sm-w-per-100）曾被误判成验证码。
        html = (
            "<html><head><style>.sm-w-per-100{width:100%}.ABC-DEF{color:red}</style></head>"
            f"<body>Your verification code is {CODE}</body></html>"
        )
        raw = (
            "From: no-reply@x.ai\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n" + _b64_body(html)
        )
        self.assertEqual(self._extract({"id": 6, "raw": raw}), CODE)

    def test_parsed_mails_shape_still_works(self):
        # 新版 Worker 的 /api/parsed_mails 直接给 subject/text/html，不应被当成原文。
        payload = {
            "id": 7,
            "subject": "Your X verification code",
            "text": f"code is {CODE}",
            "html": f"<p>{CODE}</p>",
        }
        self.assertEqual(self._extract(payload), CODE)

    def test_plain_text_field_without_headers_is_untouched(self):
        payload = {"id": 8, "text": f"Your verification code is {CODE}"}
        self.assertEqual(self._extract(payload), CODE)

    def test_parse_raw_email_falls_back_to_original_on_bare_body(self):
        parsed = parse_raw_email("just a bare body with code I6R-B2W")
        self.assertIn("I6R-B2W", parsed["text"])

    def test_empty_payload_is_safe(self):
        combined, subject = cf.collect_mail_text({"id": 9})
        self.assertEqual(combined, "")
        self.assertEqual(subject, "")
        self.assertIsNone(extract_verification_code(combined, subject))

    def test_numeric_code_with_context(self):
        # xAI 会发送纯数字验证码（如 862-837），主题/正文带 code 关键字时
        # 应能提取，不再被「必须含字母」过滤掉。
        self.assertEqual(
            extract_verification_code(
                "", "SpaceXAI confirmation code: 862-837"
            ),
            "862-837",
        )
        self.assertEqual(
            extract_verification_code(
                "Your verification code is 862-837, do not share it.", ""
            ),
            "862-837",
        )

    def test_numeric_bare_token_still_rejected(self):
        # 无 code 上下文的裸纯数字（如正文里的数字范围 100-200）仍拒绝，
        # 避免误判。
        self.assertIsNone(extract_verification_code("offer range 100-200 today", ""))
        self.assertEqual(
            extract_verification_code("offer range 100-200 today", "Your code: 862-837"),
            "862-837",
        )
