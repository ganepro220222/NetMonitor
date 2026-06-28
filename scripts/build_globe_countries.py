#!/usr/bin/env python3
"""Build globe.gl-ready country polygons (Natural Earth 50m) for screen.html.

Downloads ne_50m_admin_0_countries.geojson, strips degenerate rings that crash
d3-geo / globe.gl, normalises {name} for CN_COUNTRY lookup, writes
src/web/vendor/ne_countries.json (offline vendored asset).

Run from repo root:  python scripts/build_globe_countries.py
"""
from __future__ import annotations

import json
import math
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "src", "web", "vendor", "ne_countries.json")
SRC_URL = (
    "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/"
    "geojson/ne_50m_admin_0_countries.geojson"
)
MIN_FEATURES = 200
MIN_BYTES = 400_000
MIN_RINGS = 250
MAX_RINGS = 650
# Drop micro secondary islands/holes (each ring is a separate globe.gl draw call,
# but invisible at globe scale). Every country always keeps its largest landmass,
# so no country disappears; only tiny secondary rings below this area (sq-degrees)
# are removed. This cut globe draw calls ~8100 -> ~1850 with no visible change.
KEEP_SECONDARY_AREA = 0.6


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "network-monitor-build/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def _dedupe_ring(ring: list, eps: float = 1e-10) -> list:
    if not ring:
        return []
    out = [ring[0]]
    for p in ring[1:]:
        if abs(p[0] - out[-1][0]) > eps or abs(p[1] - out[-1][1]) > eps:
            out.append(p)
    if len(out) > 1:
        a, b = out[0], out[-1]
        if abs(a[0] - b[0]) <= eps and abs(a[1] - b[1]) <= eps:
            out[-1] = out[0]
        elif abs(a[0] - b[0]) > eps or abs(a[1] - b[1]) > eps:
            out.append(out[0])
    return out


def _ring_area(ring: list) -> float:
    if len(ring) < 4:
        return 0.0
    area = 0.0
    for i in range(len(ring) - 1):
        x1, y1 = ring[i]
        x2, y2 = ring[i + 1]
        area += x1 * y2 - x2 * y1
    return abs(area) / 2.0


def _clean_ring(ring: list) -> list | None:
    if not ring:
        return None
    cleaned = _dedupe_ring(ring)
    if len(cleaned) < 4:
        return None
    if _ring_area(cleaned) < 1e-10:
        return None
    for p in cleaned:
        if len(p) < 2 or not math.isfinite(p[0]) or not math.isfinite(p[1]):
            return None
        if abs(p[0]) > 180 or abs(p[1]) > 90:
            return None
    return cleaned


def _clean_polygon(coords: list) -> list | None:
    rings = []
    for ring in coords:
        cr = _clean_ring(ring)
        if cr:
            rings.append(cr)
    if not rings:
        return None
    return rings


def _filter_islands(geometry: dict) -> dict:
    """Keep each country's main landmass; drop tiny secondary islands/holes that
    each cost a draw call but are invisible at globe scale."""
    def big(ring: list) -> bool:
        return _ring_area(ring) >= KEEP_SECONDARY_AREA
    if geometry["type"] == "Polygon":
        rings = geometry["coordinates"]
        kept = [rings[0]] + [r for r in rings[1:] if big(r)]  # outer + large holes
        return {"type": "Polygon", "coordinates": kept}
    # MultiPolygon: prune holes per polygon, then keep the biggest polygon + large ones
    pruned = []
    for poly in geometry["coordinates"]:
        if not poly:
            continue
        pruned.append([poly[0]] + [r for r in poly[1:] if big(r)])
    if not pruned:
        return geometry
    pruned.sort(key=lambda poly: _ring_area(poly[0]), reverse=True)
    kept = [pruned[0]] + [poly for poly in pruned[1:] if big(poly[0])]
    if len(kept) == 1:
        return {"type": "Polygon", "coordinates": kept[0]}
    return {"type": "MultiPolygon", "coordinates": kept}


def _pick_name(props: dict) -> str:
    """Prefer cartographic NAME labels (match world.json + CN_COUNTRY keys).

    Natural Earth source uses NAME/ADMIN; our vendored output only stores {name}.
    Always accept an existing non-empty "name" so a re-build cannot wipe labels
    to "Unknown" (regression that broke hover labels in b738b25).
    """
    for key in ("NAME", "BRK_NAME", "ADMIN", "SOVEREIGNT", "NAME_LONG", "name"):
        val = (props.get(key) or "").strip()
        if val and val != "Unknown":
            return val
    return "Unknown"


def _clean_feature(feature: dict) -> dict | None:
    geom = feature.get("geometry") or {}
    gtype = geom.get("type")
    coords = geom.get("coordinates")
    if not coords:
        return None

    if gtype == "Polygon":
        poly = _clean_polygon(coords)
        if not poly:
            return None
        geometry = {"type": "Polygon", "coordinates": poly}
    elif gtype == "MultiPolygon":
        polys = []
        for poly_coords in coords:
            poly = _clean_polygon(poly_coords)
            if poly:
                polys.append(poly)
        if not polys:
            return None
        geometry = {"type": "MultiPolygon", "coordinates": polys}
    else:
        return None

    geometry = _filter_islands(geometry)
    props = feature.get("properties") or {}
    return {
        "type": "Feature",
        "properties": {"name": _pick_name(props)},
        "geometry": geometry,
    }


def build(raw_geojson: dict) -> dict:
    features = []
    dropped = 0
    for feat in raw_geojson.get("features") or []:
        cleaned = _clean_feature(feat)
        if cleaned:
            features.append(cleaned)
        else:
            dropped += 1
    if dropped:
        print(f"  dropped invalid features: {dropped}")
    return {"type": "FeatureCollection", "features": features}


def _ring_count(out: dict) -> int:
    total = 0
    for f in out["features"]:
        g = f["geometry"]
        if g["type"] == "Polygon":
            total += len(g["coordinates"])
        else:
            total += sum(len(poly) for poly in g["coordinates"])
    return total


def validate(out: dict, path: str) -> None:
    n = len(out.get("features") or [])
    if n < MIN_FEATURES:
        raise SystemExit(f"Too few features after clean: {n} (need >= {MIN_FEATURES})")
    size = os.path.getsize(path)
    if size < MIN_BYTES:
        raise SystemExit(f"Output too small: {size} bytes (need >= {MIN_BYTES})")
    names = [((f.get("properties") or {}).get("name") or "").strip() for f in out["features"]]
    unknown = sum(1 for nm in names if nm == "Unknown" or not nm)
    if unknown:
        raise SystemExit(f"{unknown} feature(s) have missing/Unknown name — rebuild from Natural Earth, not ne_countries.json")
    if len(set(names)) < MIN_FEATURES - 5:
        raise SystemExit(f"Too few unique country names: {len(set(names))}")
    rings = _ring_count(out)
    if rings < MIN_RINGS or rings > MAX_RINGS:
        raise SystemExit(f"Unexpected ring count {rings} (expected {MIN_RINGS}–{MAX_RINGS} after island filter)")
    verts = 0
    for f, nm in zip(out["features"], names):
        g = f["geometry"]
        if g["type"] == "Polygon":
            rs = g["coordinates"]
        else:
            rs = [r for poly in g["coordinates"] for r in poly]
        for ring in rs:
            verts += len(ring)
            if len(ring) < 4:
                raise SystemExit(f"Degenerate ring remains in {nm}")
    print(f"  features={n}  rings={rings}  vertices={verts}  bytes={size}")


def main() -> int:
    print(f"Fetching {SRC_URL} ...")
    raw = _fetch(SRC_URL)
    geo = json.loads(raw.decode("utf-8"))
    print(f"  raw features={len(geo.get('features') or [])}")

    out = build(geo)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, separators=(",", ":"))

    print(f"Wrote {OUT}")
    with open(OUT, encoding="utf-8") as fh:
        validate(json.load(fh), OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
