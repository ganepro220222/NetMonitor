"""Regression checks for bug 73 (Web /api/waveform/export ms timestamps)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import fmt_ts_ms

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_waveform_export_formatters():
    base = 1780507000.0
    t1 = base + 0.10
    t2 = base + 0.70
    s1 = fmt_ts_ms(t1)
    s2 = fmt_ts_ms(t2)
    u1 = round(float(t1), 3)
    u2 = round(float(t2), 3)
    ok = (
        s1 != s2
        and re.search(r"\.\d{3}$", s1)
        and re.search(r"\.\d{3}$", s2)
        and u1 == 1780507000.1
        and u2 == 1780507000.7
    )
    print(f"Bug73 ts={s1!r}/{s2!r} unix={u1}/{u2} -> {ok}")
    return ok


def test_source_waveform_export_uses_fmt_ts_ms():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    block = text.split('def api_waveform_export():', 1)[1].split(
        'def api_waveform():', 1)[0]
    ok = (
        "fmt_ts_ms(ts)" in block
        and "round(float(ts), 3)" in block
        and '"Unix 时间戳"' in block
        and 'strftime("%Y-%m-%d %H:%M:%S")' not in block.split("for p in pts:")[-1]
        and "from .data_store import excel_safe_text as _excel_safe_text, fmt_ts_ms"
            in text
    )
    print(f"Bug73 source fmt_ts_ms in /api/waveform/export -> {ok}")
    return ok


def main():
    results = [
        ("formatters", test_waveform_export_formatters()),
        ("source", test_source_waveform_export_uses_fmt_ts_ms()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 73 checks passed.")


if __name__ == "__main__":
    main()
