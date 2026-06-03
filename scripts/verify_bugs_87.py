"""Regression checks for bug 87 (_last_statuses gray after resume)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MAIN_WINDOW = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "main_window.py",
)


def simulate_pause_resume_probe_chain(fixed: bool):
    """Minimal state-machine model of pause / resume / first probe."""
    last = {"T": "red"}
    db_events = []

    old_status = "red"
    db_events.append((old_status, "paused"))
    last["T"] = "paused"

    db_events.append(("paused", "gray"))
    if fixed:
        last["T"] = "gray"

    old_st = last["T"]
    if old_st != "green":
        db_events.append((old_st, "green"))
        last["T"] = "green"

    chain_ok = all(
        db_events[i][0] == db_events[i - 1][1]
        for i in range(1, len(db_events))
    )
    return db_events, chain_ok, last["T"]


def test_broken_chain_without_gray_seed():
    events, ok, final = simulate_pause_resume_probe_chain(fixed=False)
    expect = (
        events == [("red", "paused"), ("paused", "gray"), ("paused", "green")]
        and not ok
        and final == "green"
    )
    print(f"Bug87 broken model events={events} continuous={ok} -> {expect}")
    return expect


def test_fixed_chain_with_gray_seed():
    events, ok, final = simulate_pause_resume_probe_chain(fixed=True)
    expect = (
        events == [("red", "paused"), ("paused", "gray"), ("gray", "green")]
        and ok
        and final == "green"
    )
    print(f"Bug87 fixed model events={events} continuous={ok} -> {expect}")
    return expect


def test_resume_updates_last_statuses_in_source():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        block = f.read().split("def _on_target_resume", 1)[1].split(
            "def _refresh_summary", 1)[0]
    ok = (
        'new_status="gray"' in block
        and 'category="resumed"' in block
        and '_lst[target_id] = "gray"' in block
        and block.index('category="resumed"') < block.index('_lst[target_id] = "gray"')
    )
    print(f"Bug87 resume seeds _last_statuses gray -> {ok}")
    return ok


def main():
    results = [
        ("broken", test_broken_chain_without_gray_seed()),
        ("fixed", test_fixed_chain_with_gray_seed()),
        ("source", test_resume_updates_last_statuses_in_source()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 87 checks passed.")


if __name__ == "__main__":
    main()
