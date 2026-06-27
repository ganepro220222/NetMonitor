#!/usr/bin/env python3
"""Reproduce stale-response overwrite when overlapping screen fetches lack seq guard."""

from __future__ import annotations

import asyncio


async def simulate_without_guard():
    state = {"paths": "initial"}
    render_order: list[str] = []

    async def load_all(tag: str, delay: float):
        await asyncio.sleep(delay)
        state["paths"] = tag
        render_order.append(tag)

    await asyncio.gather(
        load_all("old", 0.20),
        load_all("new", 0.05),
    )
    return render_order, state["paths"]


async def simulate_with_guard():
    state = {"paths": "initial"}
    render_order: list[str] = []
    seq = 0

    async def load_all(tag: str, delay: float):
        nonlocal seq
        my = seq = seq + 1
        await asyncio.sleep(delay)
        if my != seq:
            return
        state["paths"] = tag
        render_order.append(tag)

    await asyncio.gather(
        load_all("old", 0.20),
        load_all("new", 0.05),
    )
    return render_order, state["paths"]


async def main():
    order, final_paths = await simulate_without_guard()
    print(f"without_guard render_order={order!r} final_paths={final_paths!r}")
    assert order == ["new", "old"], order
    assert final_paths == "old", final_paths
    print("BUG: stale older response overwrote newer state")

    order2, final2 = await simulate_with_guard()
    print(f"with_guard render_order={order2!r} final_paths={final2!r}")
    assert order2 == ["new"], order2
    assert final2 == "new", final2
    print("OK: seq guard keeps newest response")


if __name__ == "__main__":
    asyncio.run(main())
