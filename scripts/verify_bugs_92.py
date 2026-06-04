"""Regression checks for bug 92 (_last_statuses gray on new card)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MAIN_WINDOW = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "main_window.py",
)


def _simulate_first_probe_alert(last, tid, new_status, use_setdefault):
    if use_setdefault:
        last.setdefault(tid, "gray")
    old_st = last.get(tid)
    alerts = []
    if old_st and old_st != new_status:
        cat = "availability" if (new_status == "red" or old_st == "red") else "ok"
        alerts.append({
            "old_status": old_st, "new_status": new_status, "category": cat,
        })
        last[tid] = new_status
    return alerts


def test_first_red_records_gray_to_red_with_baseline():
    last = {}
    alerts = _simulate_first_probe_alert(last, "T", "red", use_setdefault=True)
    ok = (
        len(alerts) == 1
        and alerts[0]["old_status"] == "gray"
        and alerts[0]["new_status"] == "red"
        and alerts[0]["category"] == "availability"
    )
    print(f"Bug92 with baseline: {alerts} -> {ok}")
    return ok


def test_first_red_without_baseline_skips_alert():
    last = {}
    alerts = _simulate_first_probe_alert(last, "T", "red", use_setdefault=False)
    ok = len(alerts) == 0
    print(f"Bug92 without baseline: alerts={alerts} -> {ok}")
    return ok


def test_setdefault_does_not_clobber_existing():
    last = {"T": "orange"}
    last.setdefault("T", "gray")
    ok = last["T"] == "orange"
    print(f"Bug92 setdefault preserves existing -> {ok}")
    return ok


def test_source_create_card_setdefault():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        block = f.read().split("def _create_card(self, target):", 1)[1].split(
            "def _update_empty_state", 1)[0]
    ok = (
        '_current_statuses[tid] = "gray"' in block
        and '_last_statuses.setdefault(tid, "gray")' in block
        and block.index("_current_statuses") < block.index("setdefault")
    )
    print(f"Bug92 source _create_card setdefault -> {ok}")
    return ok


def main():
    results = [
        ("with_baseline", test_first_red_records_gray_to_red_with_baseline()),
        ("no_baseline", test_first_red_without_baseline_skips_alert()),
        ("no_clobber", test_setdefault_does_not_clobber_existing()),
        ("source", test_source_create_card_setdefault()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 92 checks passed.")


if __name__ == "__main__":
    main()
