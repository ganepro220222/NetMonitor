"""Shared traceroute hop-list → human-readable break summary."""

from __future__ import annotations


def summarize_break(hops: list) -> dict:
    """Reduce a hop list to a cautious Chinese break-point summary.

    Wording avoids claiming an absolute fault location — only last reachable
    hop and first non-responsive hop after that.
    """
    hops = hops or []
    total = len(hops)
    last_ok = None
    break_at = None
    for h in hops:
        st = h.get("status")
        if st == "ok":
            last_ok = {"hop": h.get("hop"), "ip": h.get("ip")}
        elif st == "break" and break_at is None:
            break_at = {"hop": h.get("hop"), "ip": h.get("ip"),
                        "error": h.get("error")}

    if total == 1 and hops[0].get("status") == "break" and hops[0].get("error"):
        return {"reached": False, "last_ok": None, "break_at": None,
                "total_hops": 0,
                "text": f"追踪失败：{hops[0].get('error')}"}

    if break_at is None:
        tail = (f"，最后可达 第{last_ok['hop']}跳 {last_ok['ip']}"
                if last_ok and last_ok.get("ip") else "")
        return {"reached": True, "last_ok": last_ok, "break_at": None,
                "total_hops": total,
                "text": f"路径完整、未发现明确断点（共{total}跳）{tail}"}

    last_part = (f"最后可达 第{last_ok['hop']}跳 {last_ok['ip']}"
                 if last_ok and last_ok.get("ip")
                 else "首跳即不可达")
    bip = break_at.get("ip")
    berr = break_at.get("error")
    if bip and berr:
        break_part = f"第{break_at['hop']}跳起中断（断点 {bip}，{berr}）"
    elif bip:
        break_part = f"第{break_at['hop']}跳起中断（断点 {bip}）"
    else:
        break_part = f"第{break_at['hop']}跳起中断（断点无响应）"
    return {"reached": False, "last_ok": last_ok, "break_at": break_at,
            "total_hops": total,
            "text": f"{last_part} → {break_part}（共{total}跳）"}


def trace_signature(summary: dict) -> tuple:
    """Compact signature for change-only diagnostic_update dedup."""
    last_ok = summary.get("last_ok") or {}
    break_at = summary.get("break_at") or {}
    return (
        summary.get("reached"),
        last_ok.get("hop"),
        last_ok.get("ip"),
        break_at.get("hop"),
        break_at.get("ip"),
        break_at.get("error"),
    )
