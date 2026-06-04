"""Regression checks for bug 102 (startup DB status must override gray seed)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MAIN_WINDOW = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "main_window.py",
)


def _simulate_post_card_seed(last, cards, last_statuses, use_old_guard):
    """Mirror _create_card setdefault then _start_engine DB reseed."""
    for tid in cards:
        last.setdefault(tid, "gray")
    for tid, st in last_statuses.items():
        if use_old_guard:
            if tid not in last:
                last[tid] = st
        else:
            if tid in cards:
                last[tid] = st


def _first_recovery_alert(last, tid, new_status="green"):
    old_st = last.get(tid)
    if old_st and old_st != new_status:
        return {"old_status": old_st, "new_status": new_status}
    return None


def test_db_red_overwrites_gray_baseline():
    last = {}
    cards = {"T"}
    _simulate_post_card_seed(last, cards, {"T": "red"}, use_old_guard=False)
    ev = _first_recovery_alert(last, "T")
    ok = last["T"] == "red" and ev and ev["old_status"] == "red" and ev["new_status"] == "green"
    print(f"Bug102 fixed path red->green: {ev} -> {ok}")
    return ok


def test_old_guard_leaves_gray_breaks_recovery():
    last = {}
    cards = {"T"}
    _simulate_post_card_seed(last, cards, {"T": "red"}, use_old_guard=True)
    ev = _first_recovery_alert(last, "T")
    ok = last["T"] == "gray" and ev and ev["old_status"] == "gray"
    print(f"Bug102 old guard gray->green (bad): {ev} -> {ok}")
    return ok


def test_deleted_target_not_seeded():
    last = {}
    cards = {"T"}
    _simulate_post_card_seed(last, cards, {"OLD": "red", "T": "green"}, use_old_guard=False)
    ok = "OLD" not in last and last.get("T") == "green"
    print(f"Bug102 only current cards reseeded -> {ok}")
    return ok


def test_new_node_keeps_gray_without_db_row():
    last = {}
    cards = {"NEW"}
    _simulate_post_card_seed(last, cards, {}, use_old_guard=False)
    ok = last.get("NEW") == "gray"
    print(f"Bug102 new node keeps gray default -> {ok}")
    return ok


def test_source_start_engine_overwrites_cards():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        block = f.read().split("def _start_engine(self):", 1)[1].split(
            "def _state_is_current", 1)[0]
    ok = "tid in self._cards" in block and "if tid not in _lst" not in block
    print(f"Bug102 source _start_engine overwrites for cards -> {ok}")
    return ok


def main():
    results = [
        ("fixed", test_db_red_overwrites_gray_baseline()),
        ("old_bad", test_old_guard_leaves_gray_breaks_recovery()),
        ("no_ghost", test_deleted_target_not_seeded()),
        ("new_gray", test_new_node_keeps_gray_without_db_row()),
        ("source", test_source_start_engine_overwrites_cards()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 102 checks passed.")


if __name__ == "__main__":
    main()
