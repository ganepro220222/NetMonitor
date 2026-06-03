"""Regression checks for bug 41 (Web title alert names stay current)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _read_embedded_js():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"let titleTimer=null;.*?function dismissAlert\(\)", text, re.S)
    if not m:
        raise RuntimeError("checkAlerts block not found in web_server.py")
    return m.group(0)


def test_source_uses_mutable_title_alert_text():
    block = _read_embedded_js()
    ok = ("let titleAlertText=''" in block
          and "titleAlertText=`🔴 告警 ${names}`" in block
          and "document.title=f?titleAlertText:" in block
          and "document.title=f?`🔴 告警 ${names}`" not in block)
    print(f"Bug41 source wiring: titleAlertText present, closure names gone -> {ok}")
    return ok


def _simulate_check_alerts(targets, visible=None):
    """Python model of fixed checkAlerts title logic."""
    visible = visible or (lambda tid: True)
    title_timer = [None]
    title_alert_text = [""]
    document_title = [""]

    def check_alerts():
        reds = [t for t in targets.values()
                if t["status"] == "red" and visible(t["tid"])]
        if reds:
            names = "、".join(t["label"] for t in reds)
            title_alert_text[0] = f"🔴 告警 {names}"
            if title_timer[0] is None:
                title_timer[0] = True

                def tick():
                    document_title[0] = title_alert_text[0]

                tick()
        else:
            title_alert_text[0] = ""
            title_timer[0] = None
            document_title[0] = "网络连通性监测"

    def get_title():
        return title_alert_text[0] or document_title[0]

    return check_alerts, get_title


def test_title_updates_when_red_set_changes():
    targets = {"a": {"tid": "a", "label": "A", "status": "red"}}
    check, get_title = _simulate_check_alerts(targets)
    check()
    first = get_title()
    targets["b"] = {"tid": "b", "label": "B", "status": "red"}
    check()
    after = get_title()
    ok = first == "🔴 告警 A" and "B" in after and "A" in after
    print("Bug41 simulate: first has A only ->", first.endswith("A"))
    print("Bug41 simulate: after has A and B ->", ok)
    return ok


def test_title_clears_when_no_reds():
    targets = {"a": {"tid": "a", "label": "A", "status": "red"}}
    check, get_title = _simulate_check_alerts(targets)
    check()
    targets["a"]["status"] = "green"
    check()
    ok = get_title() == "网络连通性监测"
    print(f"Bug41 clear: title={get_title()!r} -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_uses_mutable_title_alert_text()),
        ("names update", test_title_updates_when_red_set_changes()),
        ("clear", test_title_clears_when_no_reds()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 41 checks passed.")


if __name__ == "__main__":
    main()
