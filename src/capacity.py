"""
capacity.py — 桌面 UI 支持的监控节点容量策略（无 UI 依赖）。

这些常量与判定逻辑刻意独立于 customtkinter / tkinter，放在一个不导入
任何 GUI 库的模块里，这样容量上限就能在没有图形依赖的环境下被单元测试
直接 import 验证（参见 scripts/verify_capacity_30.py）。main_window.py
从这里导入，不再在 UI 模块内重复定义，避免上限/文案各处漂移。
"""
from __future__ import annotations

# 当前架构下桌面 UI 正式支持的最大监控节点数。
# 每个节点占用一个后台监控线程；ICMP 节点每次探测还会 fork 一个系统
# ping 进程（无进程池复用），因此节点数偏多且 ping 间隔偏短时，Windows
# 上的进程创建与调度延迟会抬高测得的 RTT，削弱监测精度。接近警告阈值
# 时，ICMP 节点较多的用户应优先把 ping 间隔调到
# RECOMMENDED_LARGE_TARGET_INTERVAL_S 或以上。
# 30 是“不改 ICMP 探测机制、不做 UI 虚拟化”的前提下当前架构可稳妥承受
# 的上限；再往上需要架构改造（raw socket / 进程池 / 增量渲染）。
MAX_TARGETS = 30

# 软警告阈值：恰好添加到第 WARN_TARGETS 个节点时弹一次提示
# （见 target_limit_state）。必须严格小于 MAX_TARGETS。
WARN_TARGETS = 25

# 节点数较多（尤其 ICMP 节点占多数）时推荐的 ping 间隔（秒）。
# 所有相关弹窗文案统一引用这个常量，避免“文案写 2 秒、别处写 3 秒”的漂移。
RECOMMENDED_LARGE_TARGET_INTERVAL_S = 2.0


def target_limit_state(count: int) -> str:
    """根据“当前已有 count 个节点、正准备添加第 count+1 个”返回容量状态。

    返回值：
      "blocked" — 已达 MAX_TARGETS，应阻止继续添加；
      "warn"    — 正要添加第 WARN_TARGETS 个，应弹一次软提示；
      "ok"      — 正常，无需打扰。

    "warn" 使用精确相等（count == WARN_TARGETS - 1）而非 >=，沿用既有 UI
    行为：软提示只在“恰好跨过阈值”那一次弹出，不在之后每次添加都重复弹。
    代价是删除节点后再添加会再次命中该点而重复提示——这是历史既有行为，
    本次扩容不改变它，仅在此固化语义以便测试。
    """
    if count >= MAX_TARGETS:
        return "blocked"
    if count == WARN_TARGETS - 1:
        return "warn"
    return "ok"
