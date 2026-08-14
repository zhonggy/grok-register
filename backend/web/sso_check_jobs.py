# -*- coding: utf-8 -*-
"""批量 SSO 详细检查后台任务。"""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from backend.web.account_exports import read_sso_token


class SsoCheckJobCoordinator:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._running = False
        self._account_id = 0
        self._email = ""
        self._stage = "等待启动"
        self._error = ""
        self._started_at: Optional[float] = None
        self._finished_at: Optional[float] = None
        self._total_count = 0
        self._completed_count = 0
        self._clean_count = 0
        self._flagged_count = 0
        self._unknown_count = 0
        self._failed_count = 0
        self._run_id = ""
        self._items: List[Dict[str, Any]] = []
        self._thread: Optional[threading.Thread] = None

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "account_id": self._account_id,
                "email": self._email,
                "stage": self._stage,
                "error": self._error,
                "started_at": self._started_at,
                "finished_at": self._finished_at,
                "total_count": self._total_count,
                "completed_count": self._completed_count,
                "clean_count": self._clean_count,
                "flagged_count": self._flagged_count,
                "unknown_count": self._unknown_count,
                "failed_count": self._failed_count,
                "run_id": self._run_id,
                "items": [dict(item) for item in self._items],
            }

    def _set(self, **values: Any) -> None:
        with self._lock:
            for key, value in values.items():
                setattr(self, f"_{key}", value)

    @staticmethod
    def _normalize_ids(account_ids: Iterable[int]) -> List[int]:
        normalized: List[int] = []
        seen = set()
        for raw_id in account_ids or []:
            try:
                account_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            if account_id <= 0 or account_id in seen:
                continue
            seen.add(account_id)
            normalized.append(account_id)
        return normalized

    def start_many(self, account_ids: Iterable[int]) -> Dict[str, Any]:
        from backend.registration import engine as gr

        normalized_ids = self._normalize_ids(account_ids)
        if not normalized_ids:
            raise ValueError("请选择要检查的账号")
        with self._lock:
            if self._running:
                raise RuntimeError("SSO 详细检查任务正在运行")

        store = gr.get_registration_repository()
        records = store.get_results_by_ids(normalized_ids)
        records_by_id = {int(record.get("id") or 0): record for record in records}
        runnable: List[Dict[str, Any]] = []
        seed_items: List[Dict[str, Any]] = []
        failed_count = 0
        for account_id in normalized_ids:
            record = records_by_id.get(account_id)
            email = str((record or {}).get("email") or "").strip()
            item: Dict[str, Any] = {
                "account_id": account_id,
                "email": email,
                "status": "pending",
                "verdict": "pending",
                "bot_flag_source": None,
                "valid_session": False,
                "email_match": None,
                "policy": "",
                "risk": None,
                "event": "",
                "checked_at": "",
                "response_ms": 0,
                "error": "",
            }
            seed_items.append(item)
            if record is None:
                item.update(status="failed", verdict="error", error="记录不存在")
                failed_count += 1
                continue
            try:
                self._find_sso_file(record, Path(gr.DATA_DIR), Path(gr.APP_DIR))
            except (FileNotFoundError, OSError, TypeError, ValueError, UnicodeError) as exc:
                item.update(status="failed", verdict="error", error=str(exc))
                failed_count += 1
                continue
            runnable.append(record)
        if not runnable:
            first_error = next((item["error"] for item in seed_items if item["error"]), "没有可用 SSO")
            raise ValueError(f"所选账号均无法检查：{first_error}")

        with self._lock:
            if self._running:
                raise RuntimeError("SSO 详细检查任务正在运行")
            first = runnable[0]
            self._running = True
            self._account_id = int(first.get("id") or 0)
            self._email = str(first.get("email") or "").strip()
            self._stage = "准备 SSO 检查"
            self._error = ""
            self._started_at = time.time()
            self._finished_at = None
            self._total_count = len(normalized_ids)
            self._completed_count = failed_count
            self._clean_count = 0
            self._flagged_count = 0
            self._unknown_count = 0
            self._failed_count = failed_count
            self._run_id = uuid.uuid4().hex
            self._items = seed_items

        job_index = {int(item["account_id"]): item for item in seed_items}

        def runner() -> None:
            from backend.integrations import resin as _resin

            try:
                for record in runnable:
                    account_id = int(record.get("id") or 0)
                    email = str(record.get("email") or "").strip()
                    self._set(account_id=account_id, email=email, stage="检查账号风控")
                    try:
                        # Resin：SSO 检查属于该账号的流量，走账号粘性身份
                        _resin.set_current_account(email)
                        outcome = self._run_record(record, store)
                    except Exception as exc:
                        outcome = {
                            "status": "failed",
                            "verdict": "error",
                            "error": str(exc) or exc.__class__.__name__,
                        }
                    finally:
                        _resin.clear_current_account()
                    with self._lock:
                        item = job_index[account_id]
                        item.update(outcome)
                        item["error"] = str(item.get("error") or "")[:500]
                        self._completed_count += 1
                        status = str(item.get("status") or "failed")
                        if status == "clean":
                            self._clean_count += 1
                        elif status == "flagged":
                            self._flagged_count += 1
                        elif status == "unknown":
                            self._unknown_count += 1
                        else:
                            self._failed_count += 1
            finally:
                with self._lock:
                    for item in seed_items:
                        if item["status"] == "pending":
                            item.update(status="failed", verdict="error", error="任务提前结束")
                            self._completed_count += 1
                            self._failed_count += 1
                    self._running = False
                    self._finished_at = time.time()
                    self._stage = (
                        f"检查完成（正常 {self._clean_count}，异常 {self._flagged_count}，"
                        f"未知 {self._unknown_count}，失败 {self._failed_count}）"
                    )
                    self._error = (
                        f"{self._failed_count} 个账号检查失败" if self._failed_count else ""
                    )

        self._thread = threading.Thread(
            target=runner,
            name=f"account-sso-check-{self._account_id}",
            daemon=True,
        )
        try:
            self._thread.start()
        except Exception as exc:
            with self._lock:
                newly_failed = 0
                for item in seed_items:
                    if item["status"] == "pending":
                        item.update(status="failed", verdict="error", error=str(exc))
                        newly_failed += 1
                self._completed_count += newly_failed
                self._failed_count += newly_failed
                self._running = False
                self._stage = "SSO 检查启动失败"
                self._error = str(exc)
                self._finished_at = time.time()
            raise
        return self.status()

    @staticmethod
    def _find_sso_file(record: Dict[str, Any], data_dir: Path, app_dir: Path) -> Path:
        root = (data_dir / "accounts").resolve()
        email = str(record.get("email") or "").strip()
        direct = str(record.get("account_file") or "").strip()
        candidates = [Path(direct).expanduser()] if direct else []
        if email:
            safe_email = email.replace("/", "_").replace("\\", "_")
            candidates.append(root / f"{safe_email}.txt")
        for candidate in candidates:
            path = candidate if candidate.is_absolute() else app_dir / candidate
            try:
                resolved = path.resolve()
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            if resolved.is_file():
                return resolved
        raise FileNotFoundError("未找到该账号对应的 SSO 文件")

    def _run_record(self, record: Dict[str, Any], store: Any) -> Dict[str, Any]:
        from backend.integrations.sso_checker import SsoCheckConfig, SsoChecker, SsoCredential
        from backend.registration import engine as gr

        gr.load_config()
        account_id = int(record.get("id") or 0)
        email = str(record.get("email") or "").strip()
        path = self._find_sso_file(record, Path(gr.DATA_DIR), Path(gr.APP_DIR))
        token = read_sso_token(path)
        checker = SsoChecker(
            SsoCheckConfig(
                proxy=gr._resolve_cpa_proxy(),
                user_agent=gr.get_user_agent(),
            )
        )
        credential = SsoCredential(token, expected_email=email, label=email)
        retry_delays = (0, 2, 4, 8)
        result = None
        state: Dict[str, Any] = {}
        for attempt, delay in enumerate(retry_delays, start=1):
            if delay:
                self._set(stage=f"风控字段为空，{delay}s 后复查（{attempt}/{len(retry_delays)}）")
                time.sleep(delay)
            self._set(stage=f"读取会话与 botFlag（{attempt}/{len(retry_delays)}）")
            result = checker.check(credential)
            state = result.to_dict(flagged_sources=checker.config.flagged_sources)
            source = (state.get("bot_flag") or {}).get("source")
            if source is not None and source != "":
                break

        if result is None:  # pragma: no cover - retry_delays 始终至少包含一次检查
            raise RuntimeError("SSO 检查未执行")
        bot_flag = dict(state.get("bot_flag") or {})
        source = bot_flag.get("source")
        verdict = str(state.get("verdict") or "error")
        if source in (0, "0"):
            status = "clean"
        elif source is not None and source != "":
            status = "flagged"
        elif verdict in {"error"}:
            status = "failed"
        else:
            status = "unknown"
        state.update(
            {
                "enabled": True,
                "mode": "batch_detailed",
                "found": bool(bot_flag.get("found")),
                "flagged": status == "flagged",
                "bot_flag_source": source,
                "bot_flag_details": str(bot_flag.get("details") or ""),
                "policy": str(bot_flag.get("policy") or ""),
                "risk": bot_flag.get("risk"),
                "event": str(bot_flag.get("event") or ""),
                "denied": bool(bot_flag.get("denied")),
                "attempts": attempt,
            }
        )
        compact = {
            "status": status,
            "verdict": verdict,
            "bot_flag_source": source,
            "valid_session": bool(state.get("valid_session")),
            "email_match": state.get("email_match"),
            "policy": str(bot_flag.get("policy") or ""),
            "risk": bot_flag.get("risk"),
            "event": str(bot_flag.get("event") or ""),
            "checked_at": str(state.get("checked_at") or ""),
            "response_ms": int(state.get("response_ms") or 0),
            "attempts": attempt,
            "error": str(state.get("error") or ""),
        }
        self._persist_result(store, account_id, state, compact)
        return compact

    @staticmethod
    def _persist_result(store: Any, account_id: int, state: Dict[str, Any], compact: Dict[str, Any]) -> None:
        updater = getattr(store, "update_sso_check_result", None)
        if callable(updater):
            updater(account_id, risk_state=state, status=str(compact.get("status") or "unknown"))
            return
        # 测试桩可以只实现 get_results_by_ids；真实仓储始终走上面的原子更新。


sso_check_coordinator = SsoCheckJobCoordinator()
