# -*- coding: utf-8 -*-
"""Resin 粘性代理池接入。

Resin 是一个外部粘性代理池：通过 ``Platform + Account`` 组合识别业务身份，
为每个账号提供稳定的出口 IP。项目接入策略：

- **统一走正向代理**：本项目所有账号流量都需要保留客户端 TLS 指纹
  （curl_cffi ``impersonate=chrome`` 指纹 / Camoufox 引擎层伪装），
  正向代理通过 CONNECT 隧道由客户端自己完成 TLS 握手，指纹不被破坏；
  而反向代理会在 Resin 侧终止 TLS，指纹会丢失。浏览器也无法走反代。
  因此本项目按「按需使用正向代理」的策略接入。
- 反向代理（``<resin_url>/<Platform>/<protocol>/<host>/<path>?query`` +
  ``X-Resin-Account`` 头）的构建辅助函数也一并提供，便于未来接入
  不关心指纹的纯 Web API 调用方。
- **Account 必须稳定**：推荐使用登录前就存在的标识。本项目的注册邮箱
  在打开浏览器前即可获得，因此用邮箱（小写）作为 Account；对于登录前
  确实拿不到标识的场景，使用一次性临时身份（TempIdentity）发请求，
  拿到稳定标识后调用 ``inherit-lease`` 把临时身份的 IP 租约平滑继承过去。
  注意：临时身份必须每个账号槽位重新生成，不能固定复用。

线程模型：注册/重登/SSO 检查都在独立工作线程内处理单个账号，
因此使用 **thread-local** 保存「当前账号身份」。浏览器启动（Camoufox）
与 HTTP 包装（engine.http_get/http_post 等）都会读取该身份，
保证同一账号的所有请求走同一个 Resin Account。
"""

from __future__ import annotations

import re
import secrets
import threading
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import quote, urlsplit

try:
    from curl_cffi import requests
except ImportError:  # pragma: no cover - 数据/URL 构建函数仍可导入
    requests = None

# Platform 只能包含字母、数字、下划线、连字符（Resin 保证 Platform 无特殊字符）
_PLATFORM_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_DEFAULT_PLATFORM = "Default"
# 登录前无标识时使用的临时身份前缀
_TEMP_PREFIX = "temp-"
# inherit-lease 控制接口
_INHERIT_LEASE_PATH = "/api/v1/{platform}/actions/inherit-lease"

_tls = threading.local()


# --------------------------------------------------------------------------
# 配置解析
# --------------------------------------------------------------------------

def _engine_config() -> dict:
    """懒加载引擎配置，避免模块级循环导入。"""
    from backend.registration import engine as gr

    return dict(gr.config or {})


def _config(config: Optional[dict]) -> dict:
    return dict(config) if isinstance(config, dict) else _engine_config()


def parse_resin_url(resin_url: str) -> Tuple[str, str, str]:
    """把 ``resin_url`` 拆成 (scheme, server_netloc, token)。

    例如 ``http://127.0.0.1:2260/my-token`` →
    (``http``, ``127.0.0.1:2260``, ``my-token``)。
    Token 位于路径段，必须存在且不含 ``/``。
    """
    value = str(resin_url or "").strip()
    if not value:
        raise ValueError("resin_url 为空")
    if any(char.isspace() for char in value):
        raise ValueError("resin_url 不能包含空白字符")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ValueError(f"resin_url 无效: {exc}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("resin_url 必须使用 http:// 或 https://")
    host = parsed.hostname
    if not host:
        raise ValueError("resin_url 缺少主机名")
    if parsed.query or parsed.fragment:
        raise ValueError("resin_url 不能包含查询参数或片段")
    token = parsed.path.strip("/")
    if not token:
        raise ValueError("resin_url 缺少 Token 路径段（如 http://127.0.0.1:2260/my-token）")
    if "/" in token:
        raise ValueError("resin_url 的 Token 不能包含 /")
    host_display = f"[{host}]" if ":" in host and not host.startswith("[") else host
    port = f":{parsed.port}" if parsed.port is not None else ""
    return scheme, f"{host_display}{port}", token


def validate_resin_url(resin_url: str) -> str:
    """校验 resin_url 并返回去空白后的原始值（含 Token）。"""
    parse_resin_url(resin_url)
    return str(resin_url or "").strip()


def resin_platform(config: Optional[dict] = None) -> str:
    """返回 Platform 字段；未配置时使用默认值。"""
    value = str(_config(config).get("resin_platform_name", "") or "").strip()
    return value or _DEFAULT_PLATFORM


def resin_enabled(config: Optional[dict] = None) -> bool:
    """resin_url 与 Platform 均有效时才启用。"""
    cfg = _config(config)
    url = str(cfg.get("resin_url", "") or "").strip()
    if not url:
        return False
    try:
        parse_resin_url(url)
    except ValueError:
        return False
    return bool(_PLATFORM_RE.fullmatch(resin_platform(config)))


def resin_server(resin_url: str) -> str:
    """返回代理服务器地址（不含 Token）。"""
    scheme, netloc, _ = parse_resin_url(resin_url)
    return f"{scheme}://{netloc}"


# --------------------------------------------------------------------------
# 账号身份
# --------------------------------------------------------------------------

def normalize_account(account: Any) -> str:
    """规范化账号标识：去空白；邮箱统一小写（邮箱大小写不敏感，保证稳定）。"""
    value = str(account or "").strip()
    if not value:
        return ""
    if "@" in value:
        value = value.lower()
    return value


def new_temp_identity() -> str:
    """生成一次性临时身份。每个账号槽位必须重新生成，不能固定复用。"""
    return f"{_TEMP_PREFIX}{secrets.token_hex(6)}"


def set_current_account(account: Any) -> None:
    """设置当前线程的账号身份（空值表示无身份）。"""
    _tls.account = normalize_account(account)


def current_account() -> str:
    """读取当前线程的账号身份；未设置返回空串。"""
    return str(getattr(_tls, "account", "") or "").strip()


def clear_current_account() -> None:
    """清除当前线程的账号身份。"""
    _tls.account = ""


def resolve_account(account: Any = "") -> str:
    """显式传入的账号优先，否则回退线程身份。"""
    explicit = normalize_account(account)
    if explicit:
        return explicit
    return current_account()


def resolve_flow_account(account: Any = "") -> str:
    """账号流程内的身份解析：线程身份优先，其次显式传入。

    与 :func:`resolve_account` 的区别：租约继承失败时线程身份会保持
    临时身份（浏览器与 API 共用同一出口），此时显式传入的稳定邮箱
    必须让位于线程身份，否则 SSO 换 token / 上传会从新的出口发出，
    破坏粘性。
    """
    thread = current_account()
    if thread:
        return thread
    return normalize_account(account)


# --------------------------------------------------------------------------
# 正向代理（浏览器 / curl_cffi 统一使用）
# --------------------------------------------------------------------------

def forward_proxy_url(account: Any = "", config: Optional[dict] = None) -> str:
    """构建带身份认证的正向代理 URL（curl_cffi ``proxies`` / ``proxy`` 使用）。

    认证格式：``Platform.Account:RESIN_TOKEN``。
    Resin 按第一个 ``.`` 与最后一个 ``:`` 分割，因此 Account 可以包含特殊字符；
    这里对用户名与 Token 做百分号编码，curl 解码后写入 Proxy-Authorization。
    """
    if not resin_enabled(config):
        return ""
    acc = resolve_account(account)
    if not acc:
        return ""
    cfg = _config(config)
    scheme, netloc, token = parse_resin_url(str(cfg.get("resin_url", "") or ""))
    username = f"{resin_platform(config)}.{acc}"
    return (
        f"{scheme}://{quote(username, safe='')}:{quote(token, safe='')}@{netloc}"
    )


def forward_proxy_parts(account: Any = "", config: Optional[dict] = None) -> dict:
    """构建 Camoufox/Playwright 的 proxy dict：server / username / password。"""
    if not resin_enabled(config):
        return {}
    acc = resolve_account(account)
    if not acc:
        return {}
    cfg = _config(config)
    scheme, netloc, token = parse_resin_url(str(cfg.get("resin_url", "") or ""))
    return {
        "server": f"{scheme}://{netloc}",
        "username": f"{resin_platform(config)}.{acc}",
        "password": token,
    }


def account_proxy(account: Any = "", config: Optional[dict] = None) -> str:
    """账号流程内使用的 Resin 正向代理 URL；未启用或未设身份返回空串。

    优先线程身份（继承失败时保持临时身份出口一致），其次显式账号。
    """
    if not resin_enabled(config):
        return ""
    acc = resolve_flow_account(account)
    if not acc:
        return ""
    return forward_proxy_url(acc, config=config)


def current_account_proxy(config: Optional[dict] = None) -> str:
    """线程身份对应的 Resin 正向代理 URL。"""
    return account_proxy("", config=config)


# --------------------------------------------------------------------------
# 反向代理（预留；本项目统一走正向代理以保留客户端 TLS 指纹）
# --------------------------------------------------------------------------

def reverse_proxy_url(target_url: str, account: Any = "", config: Optional[dict] = None) -> str:
    """构建反向代理 URL：``<resin_url>/<Platform>/<protocol>/<host>/<path>?query``。

    仅用于不关心客户端指纹的纯 Web API 场景；本项目默认不使用。
    """
    if not resin_enabled(config):
        return str(target_url or "")
    cfg = _config(config)
    base = str(cfg.get("resin_url", "") or "").strip().rstrip("/")
    if not base:
        return str(target_url or "")
    parsed = urlsplit(str(target_url or "").strip())
    protocol = parsed.scheme.lower()
    if protocol not in ("http", "https"):
        raise ValueError(f"反向代理仅支持 http/https 目标: {target_url}")
    if not parsed.netloc:
        raise ValueError(f"目标 URL 缺少主机名: {target_url}")
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    acc = resolve_account(account)
    platform = resin_platform(config)
    return f"{base}/{platform}/{protocol}/{parsed.netloc}{path}{query}"


def reverse_headers(account: Any = "", config: Optional[dict] = None) -> dict:
    """反向代理请求头（``X-Resin-Account``）。"""
    acc = resolve_account(account)
    headers = {}
    if acc:
        headers["X-Resin-Account"] = acc
    return headers


# --------------------------------------------------------------------------
# 租约继承（TempIdentity → 稳定标识）
# --------------------------------------------------------------------------

def inherit_lease_url(config: Optional[dict] = None) -> str:
    """inherit-lease 控制接口地址（直连 Resin，不走代理）。"""
    if not resin_enabled(config):
        raise ValueError("Resin 未启用，无法调用 inherit-lease")
    cfg = _config(config)
    base = str(cfg.get("resin_url", "") or "").strip().rstrip("/")
    return f"{base}{_INHERIT_LEASE_PATH.format(platform=resin_platform(config))}"


def inherit_lease(
    parent_account: Any,
    new_account: Any,
    config: Optional[dict] = None,
    timeout: float = 20.0,
) -> dict:
    """把临时身份的 IP 租约平滑继承给新的稳定身份。

    ``POST <resin_url>/api/v1/<PLATFORM>/actions/inherit-lease``
    Body: ``{"parent_account": "<TempIdentity>", "new_account": "<StableIdentity>"}``
    """
    parent = normalize_account(parent_account)
    new = normalize_account(new_account)
    if not parent or not new:
        raise ValueError("inherit-lease 需要 parent_account 与 new_account")
    if parent == new:
        return {"inherited": False, "same": True}
    if requests is None:  # pragma: no cover
        raise RuntimeError("curl_cffi 未安装，无法调用 inherit-lease")
    url = inherit_lease_url(config)
    resp = requests.post(
        url,
        json={"parent_account": parent, "new_account": new},
        timeout=float(timeout or 20.0),
    )
    status = int(getattr(resp, "status_code", 0) or 0)
    if status >= 400:
        body = str(getattr(resp, "text", "") or "")[:200]
        raise RuntimeError(f"inherit-lease HTTP {status}: {body}")
    try:
        payload = resp.json()
        return payload if isinstance(payload, dict) else {"raw": payload}
    except Exception:
        return {"status_code": status}


def on_email_acquired(
    temp_identity: Any,
    stable_identity: Any,
    log_callback: Optional[Callable[[str], None]] = None,
    config: Optional[dict] = None,
) -> None:
    """账号拿到稳定标识（邮箱）后调用：继承临时租约并切换线程身份。

    继承失败时**保持临时身份**继续本账号流程——浏览器与后续 API 仍共用
    同一个身份/出口，粘性不被破坏（只是没有迁移到邮箱标识）。
    """
    stable = normalize_account(stable_identity)
    parent = normalize_account(temp_identity)
    if not stable:
        set_current_account("")
        return
    if parent and parent != stable and resin_enabled(config):
        try:
            inherit_lease(parent, stable, config=config)
            if log_callback:
                log_callback(
                    f"[Resin] 临时身份 {parent} 的 IP 租约已继承给稳定标识 {stable}"
                )
            set_current_account(stable)
            return
        except Exception as exc:
            if log_callback:
                log_callback(
                    f"[Resin] 租约继承失败（{exc}），本账号继续使用临时身份 {parent} "
                    "保持出口一致"
                )
            return
    set_current_account(stable)


# --------------------------------------------------------------------------
# 展示 / 脱敏
# --------------------------------------------------------------------------

def display_proxy(proxy_url: str) -> str:
    """代理展示：Resin 正向代理 URL 的 Token 位于 userinfo，直接按常规脱敏。"""
    from backend.integrations.proxy import redact_proxy_text

    return redact_proxy_text(proxy_url) if proxy_url else ""
