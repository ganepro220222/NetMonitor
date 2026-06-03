"""Regression checks for bug 51 (waveform select must not esc textContent)."""
import html
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def _populate_waveform_block(text: str) -> str:
    return text.split("function _populateWaveformTids()", 1)[1].split(
        "function resetWaveformUi()", 1)[0]


def test_source_no_esc_on_text_content():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _populate_waveform_block(f.read())
    ok = (
        "opt.textContent = `${t.label||t.tid} (${t.ip||''})`;" in block
        and re.search(r"opt\.textContent\s*=\s*`.*esc\(", block) is None
    )
    print(f"Bug51 source textContent without esc -> {ok}")
    return ok


def test_esc_still_used_for_inner_html_paths():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    ok = "const esc=s=>" in text and "innerHTML" in text and "esc(" in text
    print(f"Bug51 esc retained for innerHTML -> {ok}")
    return ok


def test_simulate_double_escape_symptom():
    label, ip = "AT&T <core>", "10.0.0.1"
    wrong = f"{esc(label)} ({esc(ip)})"
    fixed = f"{label} ({ip})"
    ok = (
        wrong == "AT&amp;T &lt;core&gt; (10.0.0.1)"
        and fixed == "AT&T <core> (10.0.0.1)"
        and "&amp;" in wrong
        and "&amp;" not in fixed
    )
    print(f"Bug51 double-escape sim -> {ok}")
    return ok


def test_text_content_needs_raw_strings():
    """textContent displays literal text; esc() would show entities to the user."""
    raw = 'A "quoted" <tag> & co'
    escaped = esc(raw)
    ok = raw != escaped and html.unescape(escaped) == raw
    print(f"Bug51 textContent expects raw -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_no_esc_on_text_content()),
        ("innerhtml", test_esc_still_used_for_inner_html_paths()),
        ("symptom", test_simulate_double_escape_symptom()),
        ("raw_text", test_text_content_needs_raw_strings()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 51 checks passed.")


if __name__ == "__main__":
    main()
