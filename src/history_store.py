from __future__ import annotations

"""
history_store.py
----------------
为每个被监测的 IP 维护一份延时历史数据，供趋势图使用。

设计思路：
  这个模块解决的是"图表需要历史数据，但 Ping 引擎只给当前数据"的问题。
  每次 Ping 引擎回调时，主窗口除了更新卡片显示，
  还会调用这里把数据追加进来。
  
  数据结构使用 collections.deque（双端队列），它有一个非常方便的特性：
  当你指定了 maxlen，队列满了之后再追加数据，
  最旧的那条数据会被自动丢弃，始终保持固定长度。
  这就实现了"滑动窗口"式的历史记录，不会无限占用内存。

关于时间戳：
  我们存储相对时间（距当前多少秒前），而不是绝对时间戳。
  这样图表的 X 轴可以直接显示"60秒前、30秒前、现在"，
  不需要做复杂的时区和格式转换。
  实际存储时还是保存 time.time() 的绝对时间，
  在读取时再转换成相对时间，这样更灵活。
"""

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DataPoint:
    """单个历史数据点。"""
    timestamp: float          # Unix 时间戳（time.time()）
    latency_ms: Optional[float]  # 延时，None 表示该次超时


class TargetHistory:
    """
    单个监测目标的历史数据缓冲区。

    使用时间窗口（而非数据点数量）来限定图表范围。
    好处：ICMP（1s 间隔）和 HTTP（20~60s 间隔）的波形图 X 轴完全对齐，
    视觉上一致，排查近期故障时细节不会被长时间跨度淹没。

    WINDOW_SECONDS = 300：所有节点的图表均显示最近 5 分钟。
    maxlen = 1000：内存安全上限（1s 间隔 = 16 分钟存储，远超显示窗口）。
    每次读取数据时过滤掉 WINDOW_SECONDS 之前的点，不存额外数据到图表。
    """

    WINDOW_SECONDS: int = 300   # 所有图表统一显示最近 N 秒
    # At global min ping_interval (0.5s) a full window needs ~600 samples;
    # 1000 leaves headroom for per-target overrides down to 0.5s.
    DEFAULT_MAXLEN: int = 1000

    def __init__(self, maxlen: int = DEFAULT_MAXLEN):
        # maxlen 是内存安全上限，与显示窗口无关
        self._buffer: deque[DataPoint] = deque(maxlen=maxlen)

    def add(self, latency_ms: Optional[float]):
        """追加一个新的数据点，时间戳自动设为当前时间。"""
        self._buffer.append(DataPoint(
            timestamp=time.time(),
            latency_ms=latency_ms
        ))

    def get_plot_data(self) -> tuple[list[float], list[Optional[float]]]:
        """
        返回适合直接传给 matplotlib 的两组数据，**只包含最近 WINDOW_SECONDS 秒内**的点：
          times    : X 轴，距"现在"的秒数（负值，0 = 现在）
          latencies: Y 轴，延时 ms；超时/失败的点为 None

        时间过滤保证了：
          • ICMP 1s 间隔 → 最多 300 个点填满 5 分钟窗口，线条密集
          • HTTP 20s 间隔 → 约 15 个点分布在同样的 5 分钟窗口，线条稀疏但坐标系对齐
          • 两者 X 轴范围相同，可以直接横向对比近期状态
        """
        now    = time.time()
        cutoff = now - self.WINDOW_SECONDS
        times      = []
        latencies  = []
        # list() snapshot: avoids RuntimeError if ping thread appends
        # to the deque concurrently while we iterate here on the UI thread.
        for point in list(self._buffer):
            if point.timestamp >= cutoff:          # 只取时间窗口内的点
                times.append(point.timestamp - now)
                latencies.append(point.latency_ms)
        return times, latencies

    def get_latest_timestamp(self) -> Optional[float]:
        """Wall-clock ts of the newest buffered probe (for chart dirty-check)."""
        return self._buffer[-1].timestamp if self._buffer else None

    def is_empty(self) -> bool:
        return len(self._buffer) == 0

    def __len__(self) -> int:
        return len(self._buffer)


class HistoryStore:
    """
    所有监测目标的历史数据管理器。
    主窗口持有这个实例，在每次 Ping 回调时调用 update()。
    """

    def __init__(self, maxlen_per_target: int = TargetHistory.DEFAULT_MAXLEN):
        self._maxlen = maxlen_per_target
        self._histories: dict[str, TargetHistory] = {}

    def ensure_target(self, target_id: str):
        """确保某个目标有对应的历史缓冲区，如果没有就创建。"""
        # setdefault is atomic under CPython's GIL — eliminates TOCTOU race
        # between the `if not in` check and the dict assignment.
        self._histories.setdefault(target_id, TargetHistory(maxlen=self._maxlen))

    def update(self, target_id: str, latency_ms: Optional[float]):
        """追加一条新数据。如果目标不存在则自动创建缓冲区。"""
        self.ensure_target(target_id)
        self._histories[target_id].add(latency_ms)

    def get_history(self, target_id: str) -> Optional[TargetHistory]:
        """获取某个目标的历史数据对象，不存在则返回 None。"""
        return self._histories.get(target_id)

    def remove_target(self, target_id: str):
        """删除某个目标的历史数据（目标被用户删除时调用）。"""
        self._histories.pop(target_id, None)
