"""Regression check: diagnostic-history scrollbar autohide must not flicker.

The ICMP / DNS diagnostic *history* sub-window auto-hides its scrollbar
based on content overflow.  The old _autohide_scrollbar() called
bar.grid() / bar.grid_remove() UNCONDITIONALLY every pass; grid() on an
already-shown bar still re-lays-out the list and fires a <Configure>,
which re-runs the sync -> a self-sustaining show->hide->show oscillation
(visible flicker) once the list overflowed.  _sync_history_list_scrollbar
also force-hid the bar first, blinking it away on every <Configure>.

Fix: make the toggle idempotent (act only when the desired shown/hidden
state differs from the current grid_info() state), and stop force-hiding
in the sync.  A stable overflow state must then perform ZERO geometry
operations on re-measure -> the <Configure> feedback loop is broken.

We verify the REAL IcmpDiagWindow._autohide_scrollbar behaviour by
injecting a minimal fake customtkinter so the UI module imports in this
headless / ctk-less environment, then driving the method with fake
canvas + scrollbar stand-ins.  DnsDiagWindow mirrors ICMP; its parity is
asserted by source-text checks below.
"""
import os
import re
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ── Inject a minimal fake customtkinter so the UI module imports headless.
class _FakeCtk(types.ModuleType):
    def __getattr__(self, name):
        # Any ctk.CTkXxx referenced at import / class-body time (e.g. the
        # CTkToplevel base class) resolves to a harmless dummy type.  The
        # methods we actually exercise take fake stand-ins, not ctk widgets.
        return type(name, (), {"__init__": lambda self, *a, **k: None})


sys.modules.setdefault("customtkinter", _FakeCtk("customtkinter"))

from src.ui.icmp_diag_window import IcmpDiagWindow   # noqa: E402  (after fake)


# ── Fake Tk stand-ins ────────────────────────────────────────────────
class _FakeBar:
    def __init__(self, shown):
        self._shown = shown
        self.grid_calls = 0
        self.grid_remove_calls = 0

    def grid_info(self):
        return {"row": 0} if self._shown else {}

    def grid(self):
        self.grid_calls += 1
        self._shown = True

    def grid_remove(self):
        self.grid_remove_calls += 1
        self._shown = False


class _FakeCanvas:
    def __init__(self, content_h, visible_h):
        self._c, self._v = content_h, visible_h

    def update_idletasks(self):
        pass

    def bbox(self, _all):
        return (0, 0, 0, self._c)

    def winfo_height(self):
        return self._v


class _FakeScroll:
    def __init__(self, content_h, visible_h, shown):
        self._parent_canvas = _FakeCanvas(content_h, visible_h)
        self._scrollbar = _FakeBar(shown)

    def update_idletasks(self):
        pass


class _FakeSelf:
    def after(self, *a, **k):       # _retries=0 path never calls this
        raise AssertionError("after() should not be called with _retries=0")


def _drive(content_h, visible_h, shown, passes=1):
    scroll = _FakeScroll(content_h, visible_h, shown)
    for _ in range(passes):
        IcmpDiagWindow._autohide_scrollbar(_FakeSelf(), scroll, _retries=0)
    return scroll._scrollbar


def test_stable_overflow_is_noop():
    # The bug's exact condition: list overflows, bar already shown.
    # Re-measuring must touch geometry ZERO times (no grid()/grid_remove()),
    # so no <Configure> is emitted and the flicker loop cannot start.
    bar = _drive(content_h=500, visible_h=200, shown=True, passes=5)
    ok = bar.grid_calls == 0 and bar.grid_remove_calls == 0
    print(f"stable overflow no-op (x5): grid={bar.grid_calls} "
          f"remove={bar.grid_remove_calls} -> {ok}")
    return ok


def test_stable_fit_is_noop():
    bar = _drive(content_h=100, visible_h=200, shown=False, passes=5)
    ok = bar.grid_calls == 0 and bar.grid_remove_calls == 0
    print(f"stable fit no-op (x5): grid={bar.grid_calls} "
          f"remove={bar.grid_remove_calls} -> {ok}")
    return ok


def test_shows_once_when_overflow_and_hidden():
    bar = _drive(content_h=500, visible_h=200, shown=False, passes=3)
    ok = bar.grid_calls == 1 and bar.grid_remove_calls == 0   # exactly one flip
    print(f"overflow+hidden -> show once (x3): grid={bar.grid_calls} "
          f"remove={bar.grid_remove_calls} -> {ok}")
    return ok


def test_hides_once_when_fit_and_shown():
    bar = _drive(content_h=100, visible_h=200, shown=True, passes=3)
    ok = bar.grid_remove_calls == 1 and bar.grid_calls == 0   # exactly one flip
    print(f"fit+shown -> hide once (x3): grid={bar.grid_calls} "
          f"remove={bar.grid_remove_calls} -> {ok}")
    return ok


# ── Source-text parity: DnsDiagWindow must carry the same fix ─────────
def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_dns_mirrors_idempotent_fix():
    icmp = _read("src/ui/icmp_diag_window.py")
    dns = _read("src/ui/dns_diag_window.py")
    checks = {}
    for name, src in (("icmp", icmp), ("dns", dns)):
        checks[f"{name}_grid_info_guard"] = "is_shown = bool(bar.grid_info())" in src
        checks[f"{name}_idempotent_branch"] = (
            "if want_visible and not is_shown:" in src
            and "elif not want_visible and is_shown:" in src)
        # old unconditional pattern gone
        checks[f"{name}_no_uncond_grid"] = not re.search(
            r"if content_h > visible_h \+ 2:\s*\n\s*bar\.grid\(\)", src)
        # sync no longer force-hides
        m = re.search(r"def _sync_history_list_scrollbar\(.*?\n(?:.*\n)*?"
                      r"(?=\n    def )", src)
        checks[f"{name}_sync_no_force_hide"] = (
            m is not None and "_hide_scrollbar_now" not in m.group(0))
    bad = [k for k, v in checks.items() if not v]
    ok = not bad
    print(f"dns/icmp parity -> {ok}" + (f"  FAILED={bad}" if bad else ""))
    return ok


def main():
    results = [
        test_stable_overflow_is_noop(),
        test_stable_fit_is_noop(),
        test_shows_once_when_overflow_and_hidden(),
        test_hides_once_when_fit_and_shown(),
        test_dns_mirrors_idempotent_fix(),
    ]
    print("ALL PASS" if all(results) else "SOME FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
