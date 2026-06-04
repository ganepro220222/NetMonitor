"""Regression checks for bug 120 (stats/SLA tab time range reset on every visit)."""
import os
import re

WEB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _js_block():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"<script>\s*(.*)\s*</script>\s*</body>", src, re.DOTALL)
    return m.group(1) if m else ""


def test_switch_uses_guarded_handlers():
    js = _js_block()
    ok = (
        "setTimeout(onStatsTabActive,50)" in js
        and "setTimeout(onSLATabActive,50)" in js
        and "setTimeout(initStatsTab,50)" not in js
        and "setTimeout(initSLATab,50)" not in js
    )
    print(f"Bug120 switchTab uses onStatsTabActive/onSLATabActive -> {ok}")
    return ok


def test_init_flags_and_first_visit_only():
    js = _js_block()
    revisit = re.search(
        r"function onStatsTabActive\(\).*?loadWaveform\(\);",
        js, re.DOTALL,
    )
    ok = (
        "_statsTabInited" in js
        and "_slaTabInited" in js
        and re.search(
            r"function onStatsTabActive\(\)\{[^}]*if\(!_statsTabInited\)",
            js, re.DOTALL,
        )
        and re.search(
            r"function onSLATabActive\(\)\{[^}]*if\(!_slaTabInited\)",
            js, re.DOTALL,
        )
        and bool(revisit)
        and "setQuick(firstBtn)" not in revisit.group(0)
    )
    print(f"Bug120 first-visit flags + revisit refresh without setQuick -> {ok}")
    return ok


def test_init_sla_not_forced_on_every_switch():
    js = _js_block()
    m = re.search(
        r"function onSLATabActive\(\)\{.*?initSLATab\(\);.*?return;.*?loadSLA\(\);",
        js, re.DOTALL,
    )
    ok = (
        "function initSLATab()" in js
        and "_slaRollingDays=7" in js
        and bool(m)
    )
    print(f"Bug120 SLA revisit calls loadSLA only (no initSLATab reset) -> {ok}")
    return ok


def main():
    results = [
        ("handlers", test_switch_uses_guarded_handlers()),
        ("flags", test_init_flags_and_first_visit_only()),
        ("sla_guard", test_init_sla_not_forced_on_every_switch()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 120 checks passed.")


if __name__ == "__main__":
    main()
