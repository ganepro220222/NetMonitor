"""Regression: detection state survives restart seeding (no phantom transitions)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def _seed_red_crash(ds, tid="T1"):
    """Persist green->red then simulate process exit (no recovery row)."""
    now = time.time()
    ds.record_alert(
        target_id=tid, label="GW", ip="10.0.0.1", ts=now - 120,
        old_status="green", new_status="red", category="availability")
    ds.record_alert(
        target_id=tid, label="GW", ip="10.0.0.1", ts=now - 60,
        old_status="red", new_status="red", category="availability")
    ds.flush()


def _simulate_first_probe_transition(last_statuses, tid, new_status):
    """Mirror MainWindow._on_state_update transition bookkeeping."""
    old_st = last_statuses.get(tid)
    would_record = old_st is not None and old_st != new_status
    if would_record:
        last_statuses[tid] = new_status
    return would_record, old_st


def test_crash_while_red_seeds_red():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    _seed_red_crash(ds)
    seeded = ds.get_last_known_statuses()
    ok = seeded.get("T1") == "red"
    print(f"restart seed crash-while-red -> {ok} seeded={seeded}")
    return ok


def test_red_seed_records_recovery_on_first_green():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    _seed_red_crash(ds)
    last_statuses = {
        tid: st for tid, st in ds.get_last_known_statuses().items()
    }
    would_record, old_st = _simulate_first_probe_transition(
        last_statuses, "T1", "green")
    if would_record:
        ds.record_alert(
            target_id="T1", label="GW", ip="10.0.0.1", ts=time.time(),
            old_status=old_st, new_status="green", category="ok")
        ds.flush()
    conn = ds._read_conn()
    row = conn.execute(
        "SELECT old_status, new_status FROM alert_events "
        "WHERE target_id='T1' ORDER BY id DESC LIMIT 1").fetchone()
    ok = would_record and row == ("red", "green")
    print(f"restart red seed + first green recovery -> {ok} last_row={row}")
    return ok


def test_gray_placeholder_is_wrong_baseline():
    """Default gray card seed records gray->green, not red->green recovery."""
    wrong = {"T1": "gray"}
    would_wrong, old_wrong = _simulate_first_probe_transition(
        wrong, "T1", "green")
    correct = {"T1": "red"}
    would_good, old_good = _simulate_first_probe_transition(
        correct, "T1", "green")
    ok = (
        would_wrong and old_wrong == "gray"
        and would_good and old_good == "red"
    )
    print(f"gray phantom vs red recovery baseline -> {ok} "
          f"wrong=({old_wrong}->green) good=({old_good}->green)")
    return ok


def test_paused_seed_allows_red_transition():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    now = time.time()
    ds.record_alert(
        target_id="T2", label="GW", ip="10.0.0.2", ts=now - 90,
        old_status="green", new_status="red", category="availability")
    ds.record_alert(
        target_id="T2", label="GW", ip="10.0.0.2", ts=now - 30,
        old_status="red", new_status="paused", category="paused")
    ds.flush()
    seeded = ds.get_last_known_statuses()
    last_statuses = dict(seeded)
    would_record, old_st = _simulate_first_probe_transition(
        last_statuses, "T2", "red")
    ok = seeded.get("T2") == "paused" and would_record and old_st == "paused"
    print(f"paused seed + post-restart red records -> {ok} seeded={seeded}")
    return ok


def main():
    results = [
        ("crash_red_seed", test_crash_while_red_seeds_red()),
        ("red_recovery", test_red_seed_records_recovery_on_first_green()),
        ("gray_baseline", test_gray_placeholder_is_wrong_baseline()),
        ("paused_red", test_paused_seed_allows_red_transition()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("PASS verify_detection_restart_state")
    return 0


if __name__ == "__main__":
    sys.exit(main())
