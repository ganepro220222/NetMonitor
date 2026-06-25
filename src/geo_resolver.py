"""Offline geo resolution for the /screen geographic view.

Priority:
  1. Manual ``geo`` on target (or ``monitor_geo`` in settings) — always used.
  2. Public IP + optional ip2region.xdb under assets/ — no CDN API, no network.
  3. Private IP without manual geo — ``kind=private`` (logical inset, no fake coords).

Intranet / air-gapped use:
  ip2region.xdb is a read-only local binary database (~11 MB on disk, similar
  in RAM once loaded).  Lookups never open sockets; private IPs (10/172/192…)
  skip the database entirely.  Removing the file disables auto public-IP
  geolocation but does not affect monitoring or the map (manual geo still works).
"""
from __future__ import annotations

import ipaddress
import os
import struct
import threading
import time
from pathlib import Path
from typing import Any

# Approximate city / province centroids for China (offline fallback).
_CITY_COORDS: dict[str, tuple[float, float]] = {
    "北京": (39.9042, 116.4074),
    "上海": (31.2304, 121.4737),
    "天津": (39.3434, 117.3616),
    "重庆": (29.5630, 106.5516),
    "广州": (23.1291, 113.2644),
    "深圳": (22.5431, 114.0579),
    "杭州": (30.2741, 120.1551),
    "南京": (32.0603, 118.7969),
    "武汉": (30.5928, 114.3055),
    "成都": (30.5728, 104.0668),
    "西安": (34.3416, 108.9398),
    "郑州": (34.7466, 113.6254),
    "济南": (36.6512, 117.1201),
    "青岛": (36.0671, 120.3826),
    "福州": (26.0745, 119.2965),
    "厦门": (24.4798, 118.0894),
    "昆明": (25.0389, 102.7183),
    "贵阳": (26.6470, 106.6302),
    "长沙": (28.2280, 112.9388),
    "南昌": (28.6820, 115.8579),
    "合肥": (31.8206, 117.2272),
    "石家庄": (38.0428, 114.5149),
    "太原": (37.8706, 112.5489),
    "沈阳": (41.8057, 123.4315),
    "大连": (38.9140, 121.6147),
    "哈尔滨": (45.8038, 126.5350),
    "长春": (43.8171, 125.3235),
    "呼和浩特": (40.8429, 111.7492),
    "乌鲁木齐": (43.8256, 87.6168),
    "拉萨": (29.6520, 91.1721),
    "银川": (38.4872, 106.2309),
    "西宁": (36.6171, 101.7782),
    "兰州": (36.0611, 103.8343),
    "海口": (20.0440, 110.1999),
    "南宁": (22.8170, 108.3665),
    "苏州": (31.2989, 120.5853),
    "无锡": (31.4912, 120.3124),
    "宁波": (29.8683, 121.5440),
    "温州": (28.0006, 120.6994),
    "东莞": (23.0207, 113.7518),
    "佛山": (23.0218, 113.1219),
    "珠海": (22.2710, 113.5767),
    "中山": (22.5170, 113.3928),
    "四川": (30.6517, 104.0757),
    "广东": (23.1317, 113.2663),
    "浙江": (30.2875, 120.1536),
    "江苏": (32.0603, 118.7969),
    "山东": (36.6683, 117.0207),
    "河南": (34.7466, 113.6254),
    "湖北": (30.5928, 114.3055),
    "湖南": (28.2280, 112.9388),
    "福建": (26.0745, 119.2965),
    "台湾": (25.0330, 121.5654),
    "香港": (22.3193, 114.1694),
    "澳门": (22.1987, 113.5439),
}


def is_private_ip(ip: str) -> bool:
    """True for RFC1918, loopback, link-local and similar non-public space."""
    ip = (ip or "").strip()
    if not ip or ip == "*":
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def is_public_ip(ip: str) -> bool:
    ip = (ip or "").strip()
    if not ip or ip == "*":
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and not is_private_ip(ip)


def _norm_coord(val: Any) -> float | None:
    try:
        v = float(val)
    except (TypeError, ValueError):
        return None
    if not (v == v and abs(v) != float("inf")):  # reject NaN/inf
        return None
    return round(v, 6)


def parse_manual_geo(raw: dict | None) -> dict | None:
    """Return normalized {lat, lon, label?, city?, region?} or None."""
    if not isinstance(raw, dict):
        return None
    lat = _norm_coord(raw.get("lat"))
    lon = _norm_coord(raw.get("lon"))
    if lat is None or lon is None:
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    out: dict[str, Any] = {"lat": lat, "lon": lon}
    for key in ("label", "city", "region"):
        val = raw.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()
    return out


def region_string_to_coords(region: str) -> tuple[float, float] | None:
    """Map ip2region region text to approximate lat/lon."""
    text = (region or "").strip()
    if not text:
        return None
    parts = [p.strip() for p in text.split("|") if p.strip() and p.strip() != "0"]
    for part in reversed(parts):
        if part in _CITY_COORDS:
            return _CITY_COORDS[part]
    for name, coords in _CITY_COORDS.items():
        if name in text:
            return coords
    return None


class _XdbMemorySearcher:
    """In-memory ip2region xdb v3/v4 IPv4 searcher (Apache-2.0 algorithm)."""

    _HEADER_LEN = 256
    _VEC_COLS = 256
    _VEC_SIZE = 8
    _INDEX_SIZE = 14  # IPv4: 4 + 4 + 2 + 4

    def __init__(self, db_path: str):
        with open(db_path, "rb") as fh:
            self._buf = fh.read()
        if len(self._buf) < self._HEADER_LEN + 1024:
            raise ValueError("xdb too small")

    @staticmethod
    def _parse_ipv4(ip: str) -> bytes | None:
        try:
            addr = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            return None
        if addr.version != 4:
            return None
        return addr.packed

    @staticmethod
    def _le_u32(buf: bytes, off: int) -> int:
        return struct.unpack_from("<I", buf, off)[0]

    @staticmethod
    def _le_u16(buf: bytes, off: int) -> int:
        return struct.unpack_from("<H", buf, off)[0]

    @staticmethod
    def _v4_sub_compare(ip1: bytes, buf: bytes, offset: int) -> int:
        """Compare big-endian IP to little-endian segment bounds in xdb."""
        j = offset + len(ip1) - 1
        for i in range(len(ip1)):
            b1, b2 = ip1[i], buf[j]
            if b1 < b2:
                return -1
            if b1 > b2:
                return 1
            j -= 1
        return 0

    def search(self, ip: str) -> str | None:
        ip_bytes = self._parse_ipv4(ip)
        if not ip_bytes:
            return None
        i0, i1 = ip_bytes[0], ip_bytes[1]
        idx = i0 * self._VEC_COLS * self._VEC_SIZE + i1 * self._VEC_SIZE
        off = self._HEADER_LEN + idx
        if off + 8 > len(self._buf):
            return None
        s_ptr = self._le_u32(self._buf, off)
        e_ptr = self._le_u32(self._buf, off + 4)
        if s_ptr == 0 or e_ptr == 0 or e_ptr < s_ptr:
            return None
        index_size = self._INDEX_SIZE
        d_len = d_ptr = 0
        left, right = 0, (e_ptr - s_ptr) // index_size
        ip_len = len(ip_bytes)
        d_off = ip_len << 1
        while left <= right:
            mid = (left + right) >> 1
            p = s_ptr + mid * index_size
            if p + index_size > len(self._buf):
                break
            seg = self._buf[p:p + index_size]
            cmp_lo = self._v4_sub_compare(ip_bytes, seg, 0)
            if cmp_lo < 0:
                right = mid - 1
            elif self._v4_sub_compare(ip_bytes, seg, ip_len) > 0:
                left = mid + 1
            else:
                d_len = self._le_u16(seg, d_off)
                d_ptr = self._le_u32(seg, d_off + 2)
                break
        if d_len <= 0 or d_ptr <= 0:
            return None
        end = d_ptr + d_len
        if end > len(self._buf):
            return None
        try:
            text = self._buf[d_ptr:end].decode("utf-8")
        except UnicodeDecodeError:
            text = self._buf[d_ptr:end].decode("latin-1", errors="replace")
        return text or None


class GeoResolver:
    """Thread-safe offline resolver with in-memory cache."""

    _CACHE_MISS = object()

    def __init__(self, xdb_path: str | None = None):
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, dict | None]] = {}
        self._cache_ttl = 3600.0
        self._xdb: _XdbMemorySearcher | None = None
        path = xdb_path or self.default_xdb_path()
        if path and os.path.isfile(path):
            try:
                self._xdb = _XdbMemorySearcher(path)
            except Exception:
                self._xdb = None

    @staticmethod
    def resolve_xdb_path(base_dir: str | None = None) -> str | None:
        """Locate ip2region.xdb for dev tree or PyInstaller onedir (exe 旁 assets/)."""
        import sys
        roots: list[str] = []
        if base_dir:
            roots.append(base_dir)
        if getattr(sys, "frozen", False):
            roots.append(os.path.dirname(sys.executable))
        roots.append(str(Path(__file__).resolve().parent.parent))
        seen: set[str] = set()
        for root in roots:
            if not root:
                continue
            root = os.path.abspath(root)
            if root in seen:
                continue
            seen.add(root)
            for rel in (
                "assets/ip2region_v4.xdb",
                "assets/ip2region.xdb",
                "data/ip2region_v4.xdb",
                "data/ip2region.xdb",
            ):
                p = os.path.join(root, rel)
                if os.path.isfile(p):
                    return p
        return None

    @staticmethod
    def default_xdb_path() -> str | None:
        return GeoResolver.resolve_xdb_path()

    def _cache_get(self, key: str):
        with self._lock:
            hit = self._cache.get(key, self._CACHE_MISS)
            if hit is self._CACHE_MISS:
                return self._CACHE_MISS
            if time.time() - hit[0] >= self._cache_ttl:
                return self._CACHE_MISS
            return hit[1]

    def _cache_set(self, key: str, value: dict | None):
        with self._lock:
            self._cache[key] = (time.time(), value)

    def lookup_public_ip(self, ip: str) -> dict | None:
        """Resolve a public IPv4 to geo dict or None."""
        ip = (ip or "").strip()
        if not is_public_ip(ip):
            return None
        cached = self._cache_get(f"ip:{ip}")
        if cached is not self._CACHE_MISS:
            return cached
        region = None
        if self._xdb is not None:
            try:
                region = self._xdb.search(ip)
            except Exception:
                region = None
        coords = region_string_to_coords(region or "") if region else None
        if coords is None:
            self._cache_set(f"ip:{ip}", None)
            return None
        lat, lon = coords
        parts = [p.strip() for p in (region or "").split("|") if p.strip() and p.strip() != "0"]
        # v4: 国家|省|市|ISP|ISO
        if len(parts) >= 3:
            city, region_name = parts[2], parts[1]
        elif len(parts) >= 2:
            city, region_name = parts[1], parts[0]
        else:
            city = parts[0] if parts else ""
            region_name = ""
        out = {
            "lat": lat,
            "lon": lon,
            "city": city or None,
            "region": region_name or None,
            "country": parts[0] if parts else "中国",
            "source": "ip2region" if self._xdb else "offline",
        }
        self._cache_set(f"ip:{ip}", out)
        return out

    def resolve_target(
            self,
            *,
            ip: str,
            resolve_ip: str | None,
            manual_geo: dict | None,
    ) -> dict:
        """Return {kind, geo} for one target."""
        manual = parse_manual_geo(manual_geo)
        if manual is not None:
            g = dict(manual)
            g.setdefault("label", g.get("city") or g.get("region") or "手动")
            return {"kind": "manual", "geo": g}

        probe = (resolve_ip or ip or "").strip()
        if is_private_ip(probe):
            return {"kind": "private", "geo": None}

        if not is_public_ip(probe):
            return {"kind": "private", "geo": None}

        geo = self.lookup_public_ip(probe)
        if geo:
            return {"kind": "public", "geo": geo}
        return {"kind": "public", "geo": None}

    def resolve_break_geo(self, break_ip: str | None) -> dict | None:
        """Geolocate break hop only when public and resolvable."""
        ip = (break_ip or "").strip()
        if not ip or ip == "*" or not is_public_ip(ip):
            return None
        return self.lookup_public_ip(ip)
