# -*- coding: utf-8 -*-
"""账号重新登录后台任务。

Web 请求只负责启动任务；浏览器登录、SSO 刷新与授权文件重建在单独线程执行。
"""
from __future__ import annotations

import datetime
import os
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote


def enqueue_relogin_grokiq_notification(
    store: Any,
    account_id: int,
    cpa_detail: Dict[str, Any],
    config: Any,
    *,
    log_callback: Any = None,
) -> Dict[str, Any] | None:
    """重登导入 grok_build 成功后，走与注册相同的 GrokIQ Webhook 入队。"""
    from backend.integrations import grokiq

    if not grokiq.grok_build_import_succeeded(cpa_detail.get("grok2api_remote_result")):
        return None
    records = store.get_results_by_ids([account_id])
    if not records:
        return None
    try:
        event = grokiq.enqueue_imported_account(store, records[0], config)
    except Exception as exc:
        if log_callback:
            log_callback(f"[GrokIQ] 账号已导入 Grok2API，但联动通知入队失败: {exc}")
        return None
    if event and log_callback:
        log_callback(f"[GrokIQ] 已加入联动通知队列: {event.get('event_id')}")
    return event


class ReloginJobCoordinator:
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
        self._success_count = 0
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
                "success_count": self._success_count,
                "failed_count": self._failed_count,
                "run_id": self._run_id,
                # 逐条浅拷贝：list() 的元素仍是同一批可变 dict，会把内部状态泄漏给调用方。
                "items": [dict(item) for item in self._items],
            }

    def _set(self, **values: Any) -> None:
        with self._lock:
            for key, value in values.items():
                setattr(self, f"_{key}", value)

    def start(self, account_id: int) -> Dict[str, Any]:
        return self.start_many([account_id])

    def start_many(self, account_ids: Iterable[int]) -> Dict[str, Any]:
        from backend.registration import engine as gr

        normalized_ids: List[int] = []
        seen = set()
        for raw_id in account_ids or []:
            try:
                account_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            if account_id <= 0 or account_id in seen:
                continue
            seen.add(account_id)
            normalized_ids.append(account_id)
        if not normalized_ids:
            raise ValueError("请选择要重新登录的账号")
        with self._lock:
            if self._running:
                raise RuntimeError(f"账号 {self._email or self._account_id} 正在重新登录")

        store = gr.get_registration_repository()
        records = store.get_results_by_ids(normalized_ids)
        if not records:
            message = "记录不存在" if len(normalized_ids) == 1 else "没有匹配的记录"
            raise LookupError(message)
        records_by_id = {int(record.get("id") or 0): record for record in records}

        runnable: List[Dict[str, Any]] = []
        validation_errors: List[str] = []
        # 预置每个账号的条目并保持请求顺序，运行中即可增量读取，且 len(items) == total_count 恒成立。
        seed_items: List[Dict[str, Any]] = []
        for account_id in normalized_ids:
            record = records_by_id.get(account_id)
            email = str((record or {}).get("email") or "").strip()
            item: Dict[str, Any] = {
                "account_id": account_id,
                "email": email,
                "status": "pending",
                "error": "",
            }
            seed_items.append(item)
            if record is None:
                item.update(status="failed", error="记录不存在")
                validation_errors.append(f"账号 {account_id}: 记录不存在")
                continue
            password = str(record.get("password") or "")
            label = email or f"账号 {account_id}"
            if not email or "@" not in email:
                item.update(status="failed", error="缺少有效邮箱")
                validation_errors.append(f"{label}: 缺少有效邮箱")
            elif not password:
                item.update(status="failed", error="没有保存密码")
                validation_errors.append(f"{label}: 没有保存密码")
            else:
                runnable.append(record)
        if not runnable:
            raise ValueError(f"所选账号均无法重新登录：{validation_errors[0]}")

        with self._lock:
            if self._running:
                raise RuntimeError(f"账号 {self._email or self._account_id} 正在重新登录")
            first = runnable[0]
            self._running = True
            self._account_id = int(first.get("id") or 0)
            self._email = str(first.get("email") or "").strip()
            self._stage = "启动浏览器"
            self._error = ""
            self._started_at = time.time()
            self._finished_at = None
            self._total_count = len(normalized_ids)
            self._completed_count = len(validation_errors)
            self._success_count = 0
            self._failed_count = len(validation_errors)
            # 与计数同锁赋值，避免并发 status() 读到「新计数 + 旧 items」。
            self._run_id = uuid.uuid4().hex
            self._items = seed_items

        job_items = seed_items
        job_index = {int(item["account_id"]): item for item in job_items}

        def runner() -> None:
            try:
                for record in runnable:
                    error = ""
                    account_id = int(record.get("id") or 0)
                    outcome: Any = ""
                    try:
                        self._set(
                            account_id=account_id,
                            email=str(record.get("email") or "").strip(),
                            stage="启动浏览器",
                        )
                        outcome = self._run_record(record, store)
                        error = str(outcome.get("error") or "") if isinstance(outcome, dict) else str(outcome or "")
                    except Exception as exc:
                        error = str(exc) or exc.__class__.__name__
                    with self._lock:
                        item = job_index.get(account_id)
                        if item is not None:
                            item["status"] = "failed" if error else "success"
                            # 截断仅作用于轮询下发的内存副本；落库错误由 _run_record 完整保存。
                            item["error"] = str(error)[:500]
                            if isinstance(outcome, dict):
                                for key in (
                                    "stage", "error_type", "url", "page_title", "visible_error",
                                    "page_text", "controls", "screenshot_url", "traceback",
                                    "screenshot_name", "captured_at",
                                ):
                                    value = str(outcome.get(key) or "")
                                    if value:
                                        item[key] = value
                        self._completed_count += 1
                        if error:
                            self._failed_count += 1
                        else:
                            self._success_count += 1
            finally:
                with self._lock:
                    for item in job_items:
                        if item["status"] == "pending":
                            item.update(status="failed", error="任务提前结束")
                            self._completed_count += 1
                            self._failed_count += 1
                    failed = [item for item in job_items if item["status"] == "failed"]
                    if self._total_count == 1:
                        self._stage = "重新登录失败" if failed else "重新登录完成"
                        self._error = failed[0]["error"] if failed else ""
                    else:
                        self._stage = (
                            f"批量重新登录完成（成功 {self._success_count}，失败 {self._failed_count}）"
                        )
                        self._error = f"{self._failed_count} 个账号重新登录失败" if failed else ""
                    self._running = False
                    self._finished_at = time.time()

        self._thread = threading.Thread(
            target=runner,
            name=f"account-relogin-{self._account_id}",
            daemon=True,
        )
        try:
            self._thread.start()
        except Exception as exc:
            with self._lock:
                for item in seed_items:
                    if item["status"] == "pending":
                        item.update(status="failed", error=str(exc))
                self._running = False
                self._stage = "重新登录启动失败"
                self._error = str(exc)
                self._finished_at = time.time()
            raise
        return self.status()

    def _run_record(self, record: Dict[str, Any], store: Any) -> str:
        from backend.automation.session import stop_browser
        from backend.integrations import resin as _resin
        from backend.registration import engine as gr
        from backend.registration.login_flow import (
            capture_login_diagnostics,
            capture_login_failure,
            login_with_password,
        )

        account_id = int(record.get("id") or 0)
        email = str(record.get("email") or "").strip()
        password = str(record.get("password") or "")
        cpa_detail: Dict[str, Any] = {}
        account_file = ""

        def log(message: str) -> None:
            text = str(message or "")
            if "打开重新登录页" in text:
                self._set(stage="填写邮箱和密码")
            elif "等待 sso" in text:
                self._set(stage="等待新的 SSO")
            elif "[CPA]" in text:
                self._set(stage="重建授权文件")

        try:
            # Resin：重登浏览器与授权重建都属于该账号的流量，走账号粘性身份
            _resin.set_current_account(email)
            gr.load_config()
            gr._wire_runtime_modules()
            gr._bs.allow_browser_launches()
            sso = login_with_password(email, password, timeout=100, log_callback=log)

            self._set(stage="保存账号文件")
            account_path = Path(gr.account_file_for_email(email))
            account_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = account_path.with_name(f".{account_path.name}.{uuid.uuid4().hex}.tmp")
            temporary.write_text(f"{email}----{password}----{sso}\n", encoding="utf-8")
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, account_path)
            account_file = str(account_path)

            self._set(stage="重建 CPA / Grok2API 文件")
            cpa_ok = gr.add_sso_to_cpa(
                sso,
                email=email,
                log_callback=log,
                result_out=cpa_detail,
            )
            cpa_success = cpa_ok and str(cpa_detail.get("status") or "") == "success"
            if not cpa_success:
                raise RuntimeError(str(cpa_detail.get("error") or "授权文件重建未完成"))
            store.update_relogin_result(
                account_id,
                account_file=account_file,
                cpa_detail=cpa_detail,
                status="success",
                error="",
            )
            enqueue_relogin_grokiq_notification(
                store,
                account_id,
                cpa_detail,
                gr.config,
                log_callback=log,
            )
            return ""
        except Exception as exc:
            error = str(exc) or exc.__class__.__name__
            failure_stage = str(self.status().get("stage") or "重新登录")
            diagnostic = capture_login_diagnostics()
            trace_text = traceback.format_exc()
            captured_at = datetime.datetime.now().astimezone()
            stamp = captured_at.strftime("%Y%m%d_%H%M%S_%f")
            safe_email = email.replace("/", "_").replace("\\", "_")
            try:
                screenshot_path = capture_login_failure(
                    Path(gr.DATA_DIR)
                    / "screenshots"
                    / "relogin-failures"
                    / f"relogin-{account_id}-{safe_email}-{stamp}.png"
                )
            except Exception:
                screenshot_path = ""
            screenshot_name = Path(screenshot_path).name if screenshot_path else ""
            screenshot_url = (
                f"/api/accounts/{account_id}/relogin-screenshots/{quote(screenshot_name, safe='')}"
                if screenshot_name else ""
            )
            store.update_relogin_result(
                account_id,
                account_file=account_file,
                cpa_detail=cpa_detail,
                status="partial" if account_file else "failed",
                error=error,
                screenshot_path=screenshot_path,
                diagnostics={
                    "stage": failure_stage,
                    "error_type": exc.__class__.__name__,
                    "url": diagnostic.get("url", ""),
                    "page_title": diagnostic.get("title", ""),
                    "visible_error": diagnostic.get("visible_error", ""),
                    "page_text": diagnostic.get("page_text", ""),
                    "controls": diagnostic.get("controls", ""),
                    "screenshot_path": screenshot_path,
                    "screenshot_name": screenshot_name,
                    "captured_at": captured_at.isoformat(timespec="seconds"),
                    "traceback": trace_text,
                },
            )
            return {
                "error": error,
                "stage": failure_stage,
                "error_type": exc.__class__.__name__,
                "url": diagnostic.get("url", ""),
                "page_title": diagnostic.get("title", ""),
                "visible_error": diagnostic.get("visible_error", ""),
                "page_text": diagnostic.get("page_text", ""),
                "controls": diagnostic.get("controls", ""),
                "screenshot_url": screenshot_url,
                "screenshot_name": screenshot_name,
                "captured_at": captured_at.isoformat(timespec="seconds"),
                "traceback": trace_text[-8000:],
            }
        finally:
            _resin.clear_current_account()
            try:
                stop_browser(force=True)
            except BaseException:
                pass


relogin_coordinator = ReloginJobCoordinator()
