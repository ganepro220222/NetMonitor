"""Regression: tool windows use transient + deferred raise (Bug 143)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FILES = {
    "window_utils": os.path.join(ROOT, "src", "ui", "window_utils.py"),
    "waveform": os.path.join(ROOT, "src", "ui", "waveform_window.py"),
    "icmp": os.path.join(ROOT, "src", "ui", "icmp_diag_window.py"),
    "dns": os.path.join(ROOT, "src", "ui", "dns_diag_window.py"),
    "tracert": os.path.join(ROOT, "src", "ui", "traceroute_result_window.py"),
    "main": os.path.join(ROOT, "src", "ui", "main_window.py"),
}


def main():
    src = {k: open(p, encoding="utf-8").read() for k, p in FILES.items()}

    checks = [
        ("utils transient", "def bind_tool_window_parent" in src["window_utils"]),
        ("utils raise", "def raise_tool_window" in src["window_utils"]),
        ("utils win topmost", '"-topmost"' in src["window_utils"]),
        ("waveform bind", "bind_tool_window_parent(self, parent)" in src["waveform"]),
        ("icmp bind", "bind_tool_window_parent(self, parent)" in src["icmp"]),
        ("dns bind", "bind_tool_window_parent(self, parent)" in src["dns"]),
        ("tracert bind", "bind_tool_window_parent(self, parent)" in src["tracert"]),
        ("main refocus", src["main"].count("raise_tool_window(existing, self)") >= 3),
        ("icmp history", "bind_tool_window_parent(win, self)" in src["icmp"]),
        ("dns history", "bind_tool_window_parent(win, self)" in src["dns"]),
        ("no raw lift icmp", "self.lift()\n        self.focus_force()" not in src["icmp"]),
    ]
    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"Bug143 {name} -> {ok}")
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    from src.ui.window_utils import bind_tool_window_parent, raise_tool_window
    print("Bug143 imports -> True")
    print("All bug 143 checks passed.")


if __name__ == "__main__":
    main()
