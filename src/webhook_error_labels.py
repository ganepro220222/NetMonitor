"""Human-readable labels for webhook outbox last_error codes (ops-facing)."""
from __future__ import annotations

# Internal code -> 运维可读中文（DB 仍存英文 code，仅展示层翻译）
WEBHOOK_ERROR_LABELS: dict[str, str] = {
    "gate_or_rebuild": "消息已过期，未发送（监控状态已更新）",
    "malformed_gate": "消息格式无效，已丢弃",
    "superseded_by_closed_summary": "已由闭环摘要取代，无需重复发送",
    "coalesced": "已合并到较新的告警",
    "target_orphan": "监控目标已删除或不存在",
    "stale_identity": "目标身份已变更，旧消息已作废",
    "stale_incident_on_restart": "程序重启后，旧故障通知已失效",
    "recovered_after_restart": "程序重启后继续重试",
    "stale_sending_recovered": "发送中断已恢复，将继续投递",
    "unblocked_for_closed_summary": "已随闭环摘要一并处理",
    "delivery_failed": "投递失败",
    "cancelled": "已取消",
    "superseded": "已被更新的消息取代",
    "gate": "状态校验未通过，未发送",
    "missing": "队列记录已不存在",
    "dropped": "已丢弃",
}

WEBHOOK_EVENT_LABELS: dict[str, str] = {
    "alert_red": "告警",
    "recovery": "恢复",
    "alert_reminder": "续报",
    "incident_closed_summary": "闭环摘要",
    "diagnostic_update": "诊断更新",
}


def webhook_error_label(code: str) -> str:
    if not code:
        return "—"
    c = str(code).strip()
    if c in WEBHOOK_ERROR_LABELS:
        return WEBHOOK_ERROR_LABELS[c]
    low = c.lower()
    if low in WEBHOOK_ERROR_LABELS:
        return WEBHOOK_ERROR_LABELS[low]
    # HTTP / 网络层错误通常已是可读句子
    if " " in c or c.upper().startswith("HTTP"):
        return c
    if any(k in low for k in ("timeout", "timed out", "connection", "refused", "dns")):
        return c
    return f"投递异常（{c}）"


def webhook_event_label(event: str) -> str:
    if not event:
        return "—"
    return WEBHOOK_EVENT_LABELS.get(str(event).strip(), str(event).strip())


def enrich_webhook_failure(item: dict) -> dict:
    """Add error_text / event_text for API + UI."""
    out = dict(item)
    err = out.get("error") or out.get("last_error") or ""
    out["error_text"] = webhook_error_label(err)
    ev = out.get("event") or ""
    out["event_text"] = webhook_event_label(ev)
    return out


def enrich_webhook_delivery(row: dict) -> dict:
    out = dict(row)
    err = out.get("last_error") or out.get("error") or ""
    out["error_text"] = webhook_error_label(err)
    ev = out.get("event") or ""
    out["event_text"] = webhook_event_label(ev)
    return out
