"""Reproduce mapHint db warning overwritten by overseas branches."""
DB_WARN = " · 缺少 ip2region 数据库（运行 python scripts/download_ip2region.py）"


def build_map_hint(map_mode, hidden_overseas, overseas, geo_db_ready, geo_map_user_choice=None):
    map_hint = "中国地图 · 省界清晰" if map_mode == "china" else "世界地图 · 境内外混合"
    if map_mode == "china" and hidden_overseas:
        map_hint = f"中国地图 · {hidden_overseas} 个境外目标在下方（请切「世界」）"
    elif map_mode == "world" and overseas:
        map_hint = f"世界地图 · 含 {overseas} 个境外目标"
    if geo_db_ready is False:
        map_hint += DB_WARN
    if not geo_map_user_choice:
        map_hint = "自动跟随轮播 · " + map_hint
    has_db = DB_WARN in map_hint
    return map_hint, has_db


def main():
    cases = [
        ("china", 1, 1, False),
        ("world", 0, 1, False),
        ("china", 0, 0, False),
        ("world", 1, 1, False),
    ]
    ok = True
    for map_mode, hidden, overseas, db_ready in cases:
        hint, has_db = build_map_hint(map_mode, hidden, overseas, db_ready)
        print(f"({map_mode!r}, {hidden}, {overseas}, {db_ready}) {hint} has_db_warning={has_db}")
        if db_ready is False and not has_db:
            ok = False
    if not ok:
        print("FAIL: db warning missing when geo_db_ready is false")
        return 1
    print("PASS: db warning preserved in all cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
