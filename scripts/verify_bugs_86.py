"""Regression checks for bug 86.

A slow SSE client's per-connection queue can saturate with stale
green/latency updates.  The old _SSEBroadcaster.push() did
``q.put_nowait(data); except queue.Full: pass`` -- so once the FIFO queue
was full, a fresh red-alert update was silently dropped and the client
stayed stuck on the old status until reconnect.  Fix (option A): when the
queue is full, drop the OLDEST queued message and enqueue the newest, so
the latest state always gets in (newest state matters more than replaying
the oldest stale update on a monitoring page).
"""
import os
import sys
import json
import queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import _SSEBroadcaster


def _drain(q):
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    return items


def test_queue_full_keeps_newest_alert():
    # Reproduce the reported scenario: queue saturated with green updates,
    # then the node goes red while the queue is already full.
    b = _SSEBroadcaster()
    q = b.subscribe()
    cap = q.maxsize
    for seq in range(cap):
        b.push(json.dumps({"type": "update",
                           "target": {"tid": "T", "status": "green",
                                      "seq": seq}}))
    assert q.full(), f"precondition: queue should be full ({q.qsize()}/{cap})"

    red = json.dumps({"type": "update",
                     "target": {"tid": "T", "status": "red", "seq": cap}})
    b.push(red)

    items = _drain(q)
    parsed = [json.loads(it) for it in items]
    seqs = [p["target"]["seq"] for p in parsed]

    size_ok = len(items) <= cap                       # never exceeded bound
    contains_red = any(p["target"]["status"] == "red"  # the bug: was False
                       for p in parsed)
    dropped_oldest = (0 not in seqs) and (cap in seqs)  # oldest evicted, new in
    ok = size_ok and contains_red and dropped_oldest
    print(f"Bug86 queue-full keeps newest: size={len(items)} "
          f"contains_red={contains_red} dropped_oldest={dropped_oldest} -> {ok}")
    return ok


def test_normal_push_is_plain_fifo():
    # When NOT full, push must stay a plain FIFO append -- no eviction,
    # no reordering, nothing dropped.
    b = _SSEBroadcaster()
    q = b.subscribe()
    for seq in range(5):
        b.push(json.dumps({"seq": seq}))
    seqs = [json.loads(it)["seq"] for it in _drain(q)]
    ok = seqs == [0, 1, 2, 3, 4]
    print(f"Bug86 normal push stays FIFO: {seqs} -> {ok}")
    return ok


def test_fanout_to_all_clients():
    # Eviction is per-queue; a full slow client must not affect a healthy one.
    b = _SSEBroadcaster()
    slow = b.subscribe()
    fast = b.subscribe()
    for seq in range(slow.maxsize):
        b.push(json.dumps({"seq": seq}))
    # fast client drains as it goes -> stays empty-ish; push one more.
    _drain(fast)
    b.push(json.dumps({"seq": 999999}))
    fast_last = json.loads(_drain(fast)[-1])["seq"]
    slow_last = json.loads(_drain(slow)[-1])["seq"]
    ok = fast_last == 999999 and slow_last == 999999
    print(f"Bug86 fan-out both see newest: fast={fast_last} slow={slow_last} -> {ok}")
    return ok


def main():
    results = [
        test_queue_full_keeps_newest_alert(),
        test_normal_push_is_plain_fifo(),
        test_fanout_to_all_clients(),
    ]
    print("ALL PASS" if all(results) else "SOME FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
