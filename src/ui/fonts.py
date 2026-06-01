from __future__ import annotations

"""
fonts.py
--------
集中管理整个程序的字体配置。

为什么要单独做一个字体模块？
  因为 CustomTkinter 没有全局字体设置，每个控件都要单独指定。
  如果把 font 的创建逻辑散落在各个文件里，将来想换字体就要改十几处。
  把它集中在这里，所有文件只需要 from src.ui.fonts import F 然后用 F.body() 等方法，
  未来换字体只需要改这一个文件。

字体选择逻辑：
  Windows → 微软雅黑（Microsoft YaHei）：Windows 自带，对中文支持极好
  macOS   → 苹方（PingFang SC）：macOS 系统中文字体
  Linux   → 思源黑体（Noto Sans CJK SC）：主流 Linux 发行版自带
  若以上都找不到则回退到 customtkinter 的默认字体（不指定 family）
"""

import platform
import customtkinter as ctk


def _detect_font_family() -> str:
    """根据操作系统返回最合适的中文字体名称。"""
    system = platform.system()
    if system == "Windows":
        return "Microsoft YaHei"
    elif system == "Darwin":
        return "PingFang SC"
    else:
        return "Noto Sans CJK SC"


# 全局字体族，其他模块直接引用这个变量
FONT_FAMILY = _detect_font_family()


def make(size: int, weight: str = "normal") -> ctk.CTkFont:
    """
    创建一个指定大小和粗细的 CTkFont。
    所有文件统一调用这个函数，而不是直接写 ctk.CTkFont(...)。

    使用示例：
      from src.ui.fonts import make as F
      label = ctk.CTkLabel(self, font=F(14, "bold"))
    """
    return ctk.CTkFont(family=FONT_FAMILY, size=size, weight=weight)


# ── CTkScrollbar 重入守卫补丁 ────────────────────────────────────────────
#
# 根因：CTkScrollbar._draw() 调用 canvas.update_idletasks()。
# update_idletasks() 处理队列中所有待处理事件，包括 Configure 事件，
# 这些事件触发 _update_dimensions_event → _draw() → update_idletasks()
# → 无限递归 → RecursionError 崩溃。
#
# 修复分两层：
#   层 1 — CTkScrollbar._draw 重入守卫（精确覆盖滚动条自身）
#   层 2 — CTkBaseClass._update_dimensions_event 重入守卫（覆盖所有 CTK 控件）
#           因为 CTkFrame._draw 同样会通过 canvas 操作触发递归，
#           单独守卫 CTkScrollbar 不够。
#
# 两个守卫都是幂等的（多次 import 不重复打）。
def _patch_ctk_scrollbar_reentrance() -> None:
    try:
        from customtkinter.windows.widgets import ctk_scrollbar as _mod
        cls = _mod.CTkScrollbar
        if getattr(cls, "_draw_reentrancy_patched", False):
            return
        _orig_draw = cls._draw
        _active: set[int] = set()

        def _safe_draw(self, no_color_updates: bool = False) -> None:
            oid = id(self)
            if oid in _active:
                return
            _active.add(oid)
            try:
                _orig_draw(self, no_color_updates)
            finally:
                _active.discard(oid)

        cls._draw = _safe_draw
        cls._draw_reentrancy_patched = True
    except Exception:
        pass


def _patch_ctk_base_update_dimensions() -> None:
    """
    Guard CTkBaseClass._update_dimensions_event against re-entrant calls.

    When any CTK widget's _draw() calls update_idletasks(), pending
    <Configure> events are processed immediately.  Those events call
    _update_dimensions_event on other (or the same) CTK widgets, which
    calls _draw(), which calls update_idletasks() again — a recursive
    cascade that exhausts Python's call stack.

    Patching the single base-class method with a per-instance guard
    silently drops re-entrant calls.  The widget will be redrawn on the
    next genuine event-loop iteration with the correct final dimensions.
    """
    try:
        from customtkinter.windows.widgets.core_widget_classes \
            import ctk_base_class as _mod
        cls = _mod.CTkBaseClass
        if getattr(cls, "_ude_reentrancy_patched", False):
            return
        _orig = cls._update_dimensions_event
        _active: set[int] = set()

        def _safe_ude(self, event=None):
            oid = id(self)
            if oid in _active:
                return
            _active.add(oid)
            try:
                _orig(self, event)
            finally:
                _active.discard(oid)

        cls._update_dimensions_event = _safe_ude
        cls._ude_reentrancy_patched = True
    except AttributeError as e:
        print(f"[WARNING] CTkBaseClass re-entrancy patch failed "
              f"(CTK API may have changed): {e}")
    except Exception:
        pass


_patch_ctk_scrollbar_reentrance()
_patch_ctk_base_update_dimensions()
# ────────────────────────────────────────────────────────────────────────────
# ────────────────────────────────────────────────────────────────────────────


def bind_scrollbar_visibility(scroll_frame):
    """
    让 CTkScrollableFrame 的滚动条仅在内容溢出时显示。
    安全保障由 _patch_ctk_base_update_dimensions() 全局守卫提供。
    防抖：resize 期间大量 Configure 事件只触发一次 _check。
    """
    def _check():
        try:
            canvas = scroll_frame._parent_canvas
            sbar   = scroll_frame._scrollbar
            y0, y1 = canvas.yview()
            if y0 <= 0.001 and y1 >= 0.999:  # HiDPI float-rounding tolerance
                sbar.grid_remove()
            else:
                sbar.grid()
        except Exception:
            pass

    def _on_configure(event=None):
        try:
            canvas = scroll_frame._parent_canvas
            # Debounce: cancel previous timer so rapid resizing doesn't queue
            # hundreds of _check callbacks that all fire at once 150ms later.
            if hasattr(scroll_frame, '_vsb_timer'):
                try: canvas.after_cancel(scroll_frame._vsb_timer)
                except Exception: pass
            scroll_frame._vsb_timer = canvas.after(150, _check)
        except Exception:
            pass

    try:
        scroll_frame.bind("<Configure>", _on_configure, add="+")
        scroll_frame._parent_canvas.bind("<Configure>", _on_configure, add="+")
        try:
            scroll_frame._scrollbar.grid_remove()
        except Exception:
            pass
        _on_configure()
    except Exception:
        pass
