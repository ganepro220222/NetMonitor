"""Regression checks for bug 47 (corrupt pinnedTargets localStorage)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def load_pinned_targets_sim(raw):
    """Mirror loadPinnedTargets() in embedded dashboard JS."""
    storage = {"pinnedTargets": raw} if raw is not None else {}

    def get_item(key):
        return storage.get(key)

    def remove_item(key):
        storage.pop(key, None)

    try:
        val = get_item("pinnedTargets")
        if not val:
            return None
        parsed = json.loads(val)
        return parsed if isinstance(parsed, list) else None
    except (json.JSONDecodeError, TypeError, ValueError):
        remove_item("pinnedTargets")
        return None


def test_source_has_load_pinned_targets():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("<script>", 1)[1].split("function isVisible", 1)[0]
    ok = ("function loadPinnedTargets()" in block
          and "let pinnedTargets=loadPinnedTargets();" in block
          and "JSON.parse(localStorage.getItem('pinnedTargets')" not in block)
    print(f"Bug47 source loadPinnedTargets -> {ok}")
    return ok


def test_missing_returns_null():
    ok = load_pinned_targets_sim(None) is None
    print(f"Bug47 missing -> {ok}")
    return ok


def test_valid_array():
    ok = load_pinned_targets_sim('["a","b"]') == ["a", "b"]
    print(f"Bug47 valid array -> {ok}")
    return ok


def test_corrupt_clears_and_returns_null():
    class _Store:
        def __init__(self, raw):
            self.data = {"pinnedTargets": raw}

        def get(self, key):
            return self.data.get(key)

        def remove(self, key):
            self.data.pop(key, None)

    store = _Store("not-json")
    try:
        raw = store.get("pinnedTargets")
        parsed = json.loads(raw) if raw else None
        result = parsed if isinstance(parsed, list) else None
    except json.JSONDecodeError:
        store.remove("pinnedTargets")
        result = None
    ok = result is None and "pinnedTargets" not in store.data
    print(f"Bug47 corrupt JSON -> {ok}")
    return ok


def test_non_array_returns_null():
    ok = load_pinned_targets_sim('{"x":1}') is None
    print(f"Bug47 non-array object -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_has_load_pinned_targets()),
        ("missing", test_missing_returns_null()),
        ("valid", test_valid_array()),
        ("corrupt", test_corrupt_clears_and_returns_null()),
        ("non-array", test_non_array_returns_null()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 47 checks passed.")


if __name__ == "__main__":
    main()
