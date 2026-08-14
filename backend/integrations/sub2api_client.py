# -*- coding: utf-8 -*-
"""Sub2API 管理端客户端：将 SSO 直传 sso-to-oauth 接口入库。"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from curl_cffi import requests


class Sub2APIError(RuntimeError):
    """远程 Sub2API 配置或上传失败。"""


class Sub2APIClient:
    """封装 Admin API Key 鉴权与 SSO→OAuth 批量/单条上传。

    说明：
    - 固定直连（trust_env=False），不继承项目代理或环境代理。
    - 鉴权仅使用 x-api-key（Admin API Key），不做 JWT 登录。
    - 每个账号通常只传一条 SSO，由 Sub2API 服务端自行换 Build OAuth。
    """

    SSO_TO_OAUTH_PATH = "/api/v1/admin/grok/sso-to-oauth"
    CONFIG_KEYS = ("sub2api_remote_url", "sub2api_api_key")

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        session: Any = None,
        timeout: float = 30,
    ) -> None:
        self.base_url = self._normalize_base_url(base_url)
        self.api_key = str(api_key or "").strip()
        if not self.api_key:
            raise Sub2APIError("Sub2API Admin API Key 为空")
        self.timeout = float(timeout)
        self._owns_session = session is None
        # Sub2API 是独立管理服务，默认不继承项目代理或环境代理；
        # 但 SSO 上传属于账号流量：当前线程处于账号流程时走该账号的 Resin 正向代理。
        self.session = session or requests.Session(trust_env=False)
        from backend.integrations import resin as _resin

        _routed = _resin.current_account_proxy()
        if _routed:
            self.session.proxies = {"http": _routed, "https": _routed}

    @classmethod
    def from_config(
        cls,
        config: Mapping[str, Any],
        *,
        session: Any = None,
        timeout: float = 30,
    ) -> "Sub2APIClient":
        """从项目配置创建客户端，并统一校验必填字段。"""
        if not cls.is_configured(config):
            raise Sub2APIError("请先完整配置 Sub2API 站点地址与 Admin API Key")
        return cls(
            str(config.get("sub2api_remote_url") or ""),
            str(config.get("sub2api_api_key") or ""),
            session=session,
            timeout=timeout,
        )

    @classmethod
    def is_configured(cls, config: Mapping[str, Any]) -> bool:
        """地址与 API Key 均非空才视为已配置。"""
        return all(str(config.get(key, "") or "").strip() for key in cls.CONFIG_KEYS)

    @staticmethod
    def _normalize_base_url(value: str) -> str:
        base = str(value or "").strip().rstrip("/")
        if not base:
            raise Sub2APIError("Sub2API 站点地址为空")
        if not base.startswith(("http://", "https://")):
            raise Sub2APIError("Sub2API 站点地址必须以 http:// 或 https:// 开头")
        return base

    @staticmethod
    def parse_group_ids(raw: Any) -> List[int]:
        """将逗号分隔的分组 ID 清洗为 int 列表；非法项丢弃。"""
        text = str(raw or "").strip()
        if not text:
            return []
        groups: List[int] = []
        for part in text.split(","):
            item = part.strip()
            if not item:
                continue
            if not item.isdigit():
                continue
            try:
                groups.append(int(item))
            except (TypeError, ValueError):
                continue
        return groups

    @staticmethod
    def _truncate_body(text: str, limit: int = 300) -> str:
        body = str(text or "").strip()
        if len(body) <= limit:
            return body
        return body[:limit] + "..."

    def sso_to_oauth(
        self,
        sso_tokens: Sequence[str],
        *,
        name: str = "",
        proxy_id: int = 0,
        group_ids: Optional[Sequence[int]] = None,
        concurrency: int = 1,
        priority: int = 0,
    ) -> Dict[str, Any]:
        """POST /api/v1/admin/grok/sso-to-oauth，返回 created/failed 摘要。"""
        tokens = [str(item or "").strip() for item in (sso_tokens or []) if str(item or "").strip()]
        if not tokens:
            raise Sub2APIError("sso_tokens 为空")

        # 仅携带有效可选字段，避免把 0 / 空列表污染请求体
        body: Dict[str, Any] = {"sso_tokens": tokens}
        name_text = str(name or "").strip()
        if name_text:
            body["name"] = name_text
        try:
            proxy_value = int(proxy_id or 0)
        except (TypeError, ValueError):
            proxy_value = 0
        if proxy_value > 0:
            body["proxy_id"] = proxy_value
        groups = [value for value in map(int, group_ids or []) if value > 0]
        if groups:
            body["group_ids"] = groups
        try:
            concurrency_value = max(1, min(int(concurrency or 1), 32))
        except (TypeError, ValueError):
            concurrency_value = 1
        body["concurrency"] = concurrency_value
        try:
            priority_value = max(-100, min(int(priority or 0), 100))
        except (TypeError, ValueError):
            priority_value = 0
        body["priority"] = priority_value

        url = f"{self.base_url}{self.SSO_TO_OAUTH_PATH}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
        }
        try:
            response = self.session.post(
                url,
                json=body,
                headers=headers,
                timeout=self.timeout,
            )
        except Exception as exc:
            raise Sub2APIError(f"连接 Sub2API sso-to-oauth 失败: {exc}") from exc

        status = int(getattr(response, "status_code", 0) or 0)
        raw_text = ""
        try:
            raw_text = str(getattr(response, "text", "") or "")
        except Exception:
            raw_text = ""
        if status >= 400:
            raise Sub2APIError(
                f"Sub2API sso-to-oauth 失败 (HTTP {status}): {self._truncate_body(raw_text)}"
            )

        payload: Any
        try:
            payload = response.json()
        except Exception:
            payload = None
        if not isinstance(payload, dict):
            # 部分实现可能直接返回数组；统一包一层便于上层记录
            return {"created": payload if isinstance(payload, list) else [], "failed": [], "raw": payload}

        # 兼容 data 包裹或顶层 created/failed
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        created = data.get("created")
        failed = data.get("failed")
        return {
            "created": created if isinstance(created, list) else (created or []),
            "failed": failed if isinstance(failed, list) else (failed or []),
            "raw": payload,
        }

    def close(self) -> None:
        """释放客户端自行创建的 HTTP 会话。"""
        if not self._owns_session:
            return
        try:
            self.session.close()
        except Exception:
            pass

    def __enter__(self) -> "Sub2APIClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
