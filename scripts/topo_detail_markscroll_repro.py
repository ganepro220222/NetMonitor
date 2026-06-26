"""Regression: markScrollable(root) must include root when it matches .topo-detail."""


def mark_scrollable_old(root):
    marked = []
    for el in (root or "doc").querySelectorAll(".topo-detail"):
        marked.append(el)
    return marked


def mark_scrollable_new(root):
    base = root or "doc"
    marked = []
    if hasattr(base, "matches") and base.matches(".topo-detail"):
        marked.append(base)
    marked.extend(base.querySelectorAll(".topo-detail"))
    return marked


class El:
    def __init__(self, cls, children=None):
        self.cls = cls
        self.children = children or []

    def matches(self, sel):
        parts = [p.strip() for p in sel.split(",")]
        return f".{self.cls}" in parts

    def querySelectorAll(self, sel):
        out = []
        for c in self.children:
            if c.matches(sel):
                out.append(c)
            out.extend(c.querySelectorAll(sel))
        return out


def main():
    topo = El("topo-detail", [El("inner")])
    old = mark_scrollable_old(topo)
    new = mark_scrollable_new(topo)
    print(f"root_call_old={topo in old} root_call_new={topo in new}")
    if topo not in old and topo in new:
        print("PASS markScrollable includes root")
        return 0
    print("FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
