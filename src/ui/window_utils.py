"""CTkToplevel z-order helpers (Windows + maximized parent)."""
from __future__ import annotations

import platform


def bind_tool_window_parent(win, parent) -> None:
    """Keep a non-modal tool window stacked above its parent."""
    try:
        win.transient(parent)
    except Exception:
        pass


def raise_tool_window(win, parent=None) -> None:
    """Bring a tool window to the front after the WM has mapped it."""
    def _do_raise() -> None:
        try:
            if not win.winfo_exists():
                return
            if parent is not None:
                try:
                    if parent.winfo_exists():
                        win.lift(parent)
                    else:
                        win.lift()
                except Exception:
                    win.lift()
            else:
                win.lift()
            win.focus_force()
            if platform.system() == "Windows":
                win.attributes("-topmost", True)
                win.after(120, _clear_topmost, win)
        except Exception:
            pass

    try:
        win.update_idletasks()
    except Exception:
        pass
    try:
        win.after(1, _do_raise)
    except Exception:
        pass


def _clear_topmost(win) -> None:
    try:
        if win.winfo_exists():
            win.attributes("-topmost", False)
    except Exception:
        pass
