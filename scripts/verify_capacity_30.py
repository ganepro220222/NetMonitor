"""Regression checks for the 30-node capacity expansion.

Two independent concerns, both introduced by the capacity work:

  1. Capacity policy (src/capacity.py) — the limit constants and the
     add-flow decision function.  These tests import ONLY src.capacity,
     never src.ui.main_window, so they pass in environments where
     customtkinter is not installed (main_window.py imports ctk at line 3).

  2. Incremental DataStore._hourly_agg() — must catch up missing hours and
     recompute only the recent window, NOT rescan the whole raw-retention
     span (168 hours at the 7-day default) on every tick.
"""
import os
import sys
import time
import tempfile
import sqlite3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ── 1. Capacity policy (must not need a GUI stack) ─────────────────────

def test_capacity_constants():
    from src.capacity import (MAX_TARGETS, WARN_TARGETS,
                              RECOMMENDED_LARGE_TARGET_INTERVAL_S)
    ok = (MAX_TARGETS == 30
          and WARN_TARGETS == 25
          and WARN_TARGETS < MAX_TARGETS
          and RECOMMENDED_LARGE_TARGET_INTERVAL_S == 2.0)
    print(f"capacity constants MAX={MAX_TARGETS} WARN={WARN_TARGETS} "
          f"rec_interval={RECOMMENDED_LARGE_TARGET_INTERVAL_S} -> {ok}")
    return ok


def test_capacity_is_ui_free():
    # The whole point of capacity.py is to be importable without a GUI
    # stack.  Verify it imports cleanly AND its source declares no tk
    # import.
    #
    # We deliberately do NOT assert `"customtkinter" not in sys.modules`:
    # that is process-global state, so a unified test runner that imported
    # ctk earlier (e.g. via main_window) would trip this even though
    # capacity.py is innocent.  The source-text check is order-independent
    # and covers the only realistic risk, since capacity.py imports no
    # project modules and so cannot pull tk in transitively.
    import src.capacity  # noqa: F401  (must not raise)
    with open(os.path.join(ROOT, "src", "capacity.py"), encoding="utf-8") as f:
        src_text = f.read()
    ok = ("import customtkinter" not in src_text
          and "import tkinter" not in src_text)
    print(f"capacity.py UI-free (no tk import) -> {ok}")
    return ok


def test_target_limit_state_boundaries():
    from src.capacity import target_limit_state
    cases = {0: "ok", 23: "ok", 24: "warn", 25: "ok",
             29: "ok", 30: "blocked", 31: "blocked", 100: "blocked"}
    bad = {c: (target_limit_state(c), exp)
           for c, exp in cases.items() if target_limit_state(c) != exp}
    ok = not bad
    print(f"target_limit_state boundaries -> {ok}"
          + (f"  MISMATCH={bad}" if bad else ""))
    return ok


def test_main_window_uses_capacity_module():
    # main_window.py must IMPORT the policy, not redefine the old 20/15.
    with open(os.path.join(ROOT, "src", "ui", "main_window.py"),
              encoding="utf-8") as f:
        text = f.read()
    ok = ("from src.capacity import" in text
          and "MAX_TARGETS      = 20" not in text
          and "MAX_TARGETS = 20" not in text
          and "WARN_TARGETS     = 15" not in text
          and 'target_limit_state(len(self._cards)) == "blocked"' in text
          and 'target_limit_state(len(self._cards)) == "warn"' in text)
    print(f"main_window imports capacity (no local 20/15) -> {ok}")
    return ok


# ── 2. Incremental hourly aggregation ──────────────────────────────────

def _new_store_conn(raw_retention_days=7):
    from src.data_store import DataStore
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    ds = DataStore(db_path=db, raw_retention_days=raw_retention_days)
    ds._schema_ready.wait(timeout=5)
    ds.shutdown()                       # stop writer thread, take the DB solo
    return ds, sqlite3.connect(db)


def _ins_raw(conn, tid, hour_ts, n=5, base=10.0, status="green"):
    for s in range(n):
        conn.execute(
            "INSERT INTO pings_raw(target_id,ts,latency_ms,status) VALUES(?,?,?,?)",
            (tid, hour_ts + s * 60, base + s, status))
    conn.commit()


def _count_raw_scans(conn, fn):
    c = [0]

    def tr(sql):
        if " ".join(sql.upper().split()).startswith(
                "SELECT LATENCY_MS, STATUS FROM PINGS_RAW"):
            c[0] += 1
    conn.set_trace_callback(tr)
    fn()
    conn.set_trace_callback(None)
    return c[0]


def _count_target_discovery_scans(conn, fn):
    windowed = [0]
    full = [0]

    def tr(sql):
        u = " ".join(sql.upper().split())
        if u.startswith("SELECT DISTINCT TARGET_ID FROM PINGS_RAW"):
            if " WHERE " in u:
                windowed[0] += 1
            else:
                full[0] += 1

    conn.set_trace_callback(tr)
    fn()
    conn.set_trace_callback(None)
    return windowed[0], full[0]


def _count_gap_scans(conn, fn):
    c = [0]

    def tr(sql):
        u = " ".join(sql.upper().split())
        if ("DISTINCT" in u and "(TS / 3600) * 3600" in u
                and "EXCEPT" in u and "PINGS_RAW" in u):
            c[0] += 1
    conn.set_trace_callback(tr)
    fn()
    conn.set_trace_callback(None)
    return c[0]


def test_hourly_agg_incremental_when_caught_up():
    ds, conn = _new_store_conn()
    C = (int(time.time()) // 3600) * 3600
    for h in (1, 2, 3):
        _ins_raw(conn, "T", C - h * 3600)
    ds._hourly_agg(conn)                            # first catch-up
    scans = _count_raw_scans(conn, lambda: ds._hourly_agg(conn))
    # Old code clamped to recompute_floor → rescanned 7*24 = 168 hours
    # even when fully caught up.  Now: only RECENT_RECOMPUTE_HOURS (3).
    ok = scans <= 3
    print(f"hourly_agg caught-up rescans={scans} (old=168, expect<=3) -> {ok}")
    return ok


def test_hourly_agg_fills_missing_hours():
    ds, conn = _new_store_conn()
    C = (int(time.time()) // 3600) * 3600
    for h in range(1, 7):                           # C-6h..C-1h have raw
        _ins_raw(conn, "T", C - h * 3600)
    # Pretend aggregation only ever reached C-6h (writer offline a while).
    conn.execute(
        "INSERT INTO pings_hourly(target_id,hour_ts,sample_n,success_n,"
        "lat_avg,lat_max,lat_min,lat_p95,loss_rate) VALUES('T',?,5,5,10,14,10,14,0)",
        (C - 6 * 3600,))
    conn.commit()
    ds._hourly_agg(conn, backfill_internal_gaps=True)
    got = conn.execute(
        "SELECT COUNT(*) FROM pings_hourly WHERE target_id='T'").fetchone()[0]
    ok = got == 6                                   # C-6h..C-1h all present
    print(f"hourly_agg missing-hour catch-up buckets={got} (expect 6) -> {ok}")
    return ok


def test_hourly_agg_absorbs_recent_late_flush():
    ds, conn = _new_store_conn()
    C = (int(time.time()) // 3600) * 3600
    for h in (1, 2, 3):
        _ins_raw(conn, "T", C - h * 3600, n=5)
    ds._hourly_agg(conn)
    before = conn.execute(
        "SELECT sample_n FROM pings_hourly WHERE target_id='T' AND hour_ts=?",
        (C - 1 * 3600,)).fetchone()[0]
    _ins_raw(conn, "T", C - 1 * 3600, n=3, base=99.0)   # late flush, recent hr
    ds._hourly_agg(conn)
    after = conn.execute(
        "SELECT sample_n FROM pings_hourly WHERE target_id='T' AND hour_ts=?",
        (C - 1 * 3600,)).fetchone()[0]
    ok = before == 5 and after == 8
    print(f"hourly_agg recent late-flush sample_n {before}->{after} "
          f"(expect 5->8) -> {ok}")
    return ok


def test_hourly_agg_fills_internal_gaps_before_hwm():
    """HWM at C-1h but C-6h..C-4h missing — must backfill, not only recent 3h."""
    ds, conn = _new_store_conn()
    C = (int(time.time()) // 3600) * 3600
    for h in range(1, 7):
        _ins_raw(conn, "T", C - h * 3600)
    conn.execute(
        "INSERT INTO pings_hourly(target_id,hour_ts,sample_n,success_n,"
        "lat_avg,lat_max,lat_min,lat_p95,loss_rate) VALUES('T',?,5,5,10,14,10,14,0)",
        (C - 1 * 3600,))
    conn.commit()
    ds._hourly_agg(conn, backfill_internal_gaps=True)
    hours_ago = {
        (C - row[0]) // 3600
        for row in conn.execute(
            "SELECT hour_ts FROM pings_hourly WHERE target_id='T'"
        ).fetchall()
    }
    ok = hours_ago == {1, 2, 3, 4, 5, 6}
    print(f"hourly_agg internal-gap backfill hours_ago={sorted(hours_ago)} "
          f"(expect 1..6) -> {ok}")
    return ok


def test_hourly_agg_routine_uses_recent_window_target_discovery():
    ds, conn = _new_store_conn()
    C = (int(time.time()) // 3600) * 3600
    for h in (1, 2, 3):
        _ins_raw(conn, "T", C - h * 3600)
    ds._hourly_agg(conn)
    windowed, full = _count_target_discovery_scans(
        conn, lambda: ds._hourly_agg(conn))
    ok = windowed >= 1 and full == 0
    print(f"hourly_agg routine target discovery windowed={windowed} full={full} "
          f"(expect windowed>=1, full=0) -> {ok}")
    return ok


def test_hourly_agg_backfill_uses_full_target_discovery():
    ds, conn = _new_store_conn()
    C = (int(time.time()) // 3600) * 3600
    for h in (1, 2, 3):
        _ins_raw(conn, "T", C - h * 3600)
    ds._hourly_agg(conn)
    windowed, full = _count_target_discovery_scans(
        conn, lambda: ds._hourly_agg(conn, backfill_internal_gaps=True))
    ok = full >= 1
    print(f"hourly_agg backfill target discovery windowed={windowed} full={full} "
          f"(expect full>=1) -> {ok}")
    return ok


def test_hourly_agg_routine_skips_gap_scan_when_caught_up():
    ds, conn = _new_store_conn()
    C = (int(time.time()) // 3600) * 3600
    for h in (1, 2, 3):
        _ins_raw(conn, "T", C - h * 3600)
    ds._hourly_agg(conn)
    gap_scans = _count_gap_scans(conn, lambda: ds._hourly_agg(conn))
    bucket_scans = _count_raw_scans(conn, lambda: ds._hourly_agg(conn))
    ok = gap_scans == 0 and bucket_scans <= 3
    print(f"hourly_agg routine gap_scans={gap_scans} bucket_scans={bucket_scans} "
          f"(expect 0 gap, <=3 bucket) -> {ok}")
    return ok


def test_hourly_agg_gap_backfill_mode_runs_gap_scan():
    ds, conn = _new_store_conn()
    C = (int(time.time()) // 3600) * 3600
    for h in (1, 2, 3):
        _ins_raw(conn, "T", C - h * 3600)
    ds._hourly_agg(conn)
    gap_scans = _count_gap_scans(
        conn, lambda: ds._hourly_agg(conn, backfill_internal_gaps=True))
    ok = gap_scans >= 1
    print(f"hourly_agg gap-backfill mode gap_scans={gap_scans} (expect>=1) -> {ok}")
    return ok


def test_hourly_agg_old_late_flush_tradeoff():
    # Documents the INTENTIONAL trade-off: a late flush older than the
    # recent recompute window (3h) into an already-aggregated hour is NOT
    # re-absorbed on the routine tick.
    ds, conn = _new_store_conn()
    C = (int(time.time()) // 3600) * 3600
    for h in (1, 2, 3, 4, 5):
        _ins_raw(conn, "T", C - h * 3600, n=5)
    ds._hourly_agg(conn)
    _ins_raw(conn, "T", C - 5 * 3600, n=3, base=99.0)   # 5h-old late flush
    ds._hourly_agg(conn)
    after = conn.execute(
        "SELECT sample_n FROM pings_hourly WHERE target_id='T' AND hour_ts=?",
        (C - 5 * 3600,)).fetchone()[0]
    ok = after == 5                                 # unchanged, by design
    print(f"hourly_agg old late-flush sample_n stays {after} "
          f"(expect 5, by design) -> {ok}")
    return ok


def main():
    results = [
        ("capacity_constants",        test_capacity_constants()),
        ("capacity_ui_free",          test_capacity_is_ui_free()),
        ("limit_state_boundaries",    test_target_limit_state_boundaries()),
        ("main_window_uses_capacity", test_main_window_uses_capacity_module()),
        ("hourly_incremental",        test_hourly_agg_incremental_when_caught_up()),
        ("hourly_fills_missing",      test_hourly_agg_fills_missing_hours()),
        ("hourly_internal_gaps",      test_hourly_agg_fills_internal_gaps_before_hwm()),
        ("hourly_recent_targets",     test_hourly_agg_routine_uses_recent_window_target_discovery()),
        ("hourly_backfill_targets",   test_hourly_agg_backfill_uses_full_target_discovery()),
        ("hourly_no_routine_gap",     test_hourly_agg_routine_skips_gap_scan_when_caught_up()),
        ("hourly_gap_mode",           test_hourly_agg_gap_backfill_mode_runs_gap_scan()),
        ("hourly_recent_late",        test_hourly_agg_absorbs_recent_late_flush()),
        ("hourly_old_late_tradeoff",  test_hourly_agg_old_late_flush_tradeoff()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All capacity-30 checks passed.")


if __name__ == "__main__":
    main()
