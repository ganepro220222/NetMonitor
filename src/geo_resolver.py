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

# Approximate place centroids (city / province / country names from ip2region).
_PLACE_COORDS: dict[str, tuple[float, float]] = {
    # ── 中国（省 / 市）──
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
    "中国": (35.8617, 104.1954),
    # 省级（ip2region 常返回「XX省」，坐标取省会近似）
    "黑龙江": (45.8038, 126.5350),
    "吉林": (43.8171, 125.3235),
    "辽宁": (41.8057, 123.4315),
    "河北": (38.0428, 114.5149),
    "山西": (37.8706, 112.5489),
    "内蒙古": (40.8429, 111.7492),
    "江苏": (32.0603, 118.7969),
    "浙江": (30.2875, 120.1536),
    "安徽": (31.8206, 117.2272),
    "江西": (28.6820, 115.8579),
    "山东": (36.6683, 117.0207),
    "河南": (34.7466, 113.6254),
    "湖北": (30.5928, 114.3055),
    "湖南": (28.2280, 112.9388),
    "广东": (23.1317, 113.2663),
    "广西": (22.8170, 108.3665),
    "海南": (20.0440, 110.1999),
    "四川": (30.6517, 104.0757),
    "贵州": (26.6470, 106.6302),
    "云南": (25.0389, 102.7183),
    "西藏": (29.6520, 91.1721),
    "陕西": (34.3416, 108.9398),
    "甘肃": (36.0611, 103.8343),
    "青海": (36.6171, 101.7782),
    "宁夏": (38.4872, 106.2309),
    "新疆": (43.8256, 87.6168),
    # ── 海外主要国家 / 地区 / 城市（ip2region 英文段）──
    "United States": (39.8283, -98.5795),
    "USA": (39.8283, -98.5795),
    "California": (36.7783, -119.4179),
    "New York": (40.7128, -74.0060),
    "Virginia": (37.4316, -78.6569),
    "Washington": (47.7511, -120.7401),
    "Texas": (31.9686, -99.9018),
    "Oregon": (43.8041, -120.5542),
    "Illinois": (40.6331, -89.3985),
    "Florida": (27.6648, -81.5158),
    "Japan": (36.2048, 138.2529),
    "Tokyo": (35.6762, 139.6503),
    "Osaka": (34.6937, 135.5023),
    "Singapore": (1.3521, 103.8198),
    "South Korea": (35.9078, 127.7669),
    "Korea": (35.9078, 127.7669),
    "Seoul": (37.5665, 126.9780),
    "Germany": (51.1657, 10.4515),
    "France": (46.2276, 2.2137),
    "United Kingdom": (55.3781, -3.4360),
    "UK": (55.3781, -3.4360),
    "Netherlands": (52.1326, 5.2913),
    "Ireland": (53.4129, -8.2439),
    "Canada": (56.1304, -106.3468),
    "Australia": (-25.2744, 133.7751),
    "New Zealand": (-40.9006, 174.8860),
    "India": (20.5937, 78.9629),
    "Russia": (61.5240, 105.3188),
    "Brazil": (-14.2350, -51.9253),
    "Mexico": (23.6345, -102.5528),
    "Thailand": (15.8700, 100.9925),
    "Vietnam": (14.0583, 108.2772),
    "Malaysia": (4.2105, 101.9758),
    "Indonesia": (-0.7893, 113.9213),
    "Philippines": (12.8797, 121.7740),
    "United Arab Emirates": (23.4241, 53.8478),
    "UAE": (23.4241, 53.8478),
    "Dubai": (25.2048, 55.2708),
    "Israel": (31.0461, 34.8516),
    "Turkey": (38.9637, 35.2433),
    "South Africa": (-30.5595, 22.9375),
    "Italy": (41.8719, 12.5674),
    "Spain": (40.4637, -3.7492),
    "Sweden": (60.1282, 18.6435),
    "Norway": (60.4720, 8.4689),
    "Finland": (61.9241, 25.7482),
    "Poland": (51.9194, 19.1451),
    "Switzerland": (46.8182, 8.2275),
    "Austria": (47.5162, 14.5501),
    "Belgium": (50.5039, 4.4699),
    "Czech": (49.8175, 15.4730),
    "Hong Kong": (22.3193, 114.1694),
    "Macao": (22.1987, 113.5439),
    "Taiwan": (25.0330, 121.5654),
}

_ISO_COUNTRY: dict[str, tuple[float, float]] = {
    "CN": (35.8617, 104.1954),
    "US": (39.8283, -98.5795),
    "JP": (36.2048, 138.2529),
    "SG": (1.3521, 103.8198),
    "KR": (35.9078, 127.7669),
    "DE": (51.1657, 10.4515),
    "FR": (46.2276, 2.2137),
    "GB": (55.3781, -3.4360),
    "UK": (55.3781, -3.4360),
    "NL": (52.1326, 5.2913),
    "IE": (53.4129, -8.2439),
    "CA": (56.1304, -106.3468),
    "AU": (-25.2744, 133.7751),
    "NZ": (-40.9006, 174.8860),
    "IN": (20.5937, 78.9629),
    "RU": (61.5240, 105.3188),
    "BR": (-14.2350, -51.9253),
    "MX": (23.6345, -102.5528),
    "TH": (15.8700, 100.9925),
    "VN": (14.0583, 108.2772),
    "MY": (4.2105, 101.9758),
    "ID": (-0.7893, 113.9213),
    "PH": (12.8797, 121.7740),
    "AE": (23.4241, 53.8478),
    "IL": (31.0461, 34.8516),
    "TR": (38.9637, 35.2433),
    "ZA": (-30.5595, 22.9375),
    "IT": (41.8719, 12.5674),
    "ES": (40.4637, -3.7492),
    "SE": (60.1282, 18.6435),
    "NO": (60.4720, 8.4689),
    "FI": (61.9241, 25.7482),
    "PL": (51.9194, 19.1451),
    "CH": (46.8182, 8.2275),
    "AT": (47.5162, 14.5501),
    "BE": (50.5039, 4.4699),
    "HK": (22.3193, 114.1694),
    "TW": (25.0330, 121.5654),
}

# Anycast / public DNS — ip2region often returns a random PoP; use stable coords.
_WELL_KNOWN_ANYCAST: dict[str, dict[str, Any]] = {
    "1.1.1.1": {
        "lat": 37.7622, "lon": -122.4396,
        "city": "旧金山", "region": "加利福尼亚", "country": "United States",
    },
    "1.0.0.1": {
        "lat": 37.7622, "lon": -122.4396,
        "city": "旧金山", "region": "加利福尼亚", "country": "United States",
    },
    "8.8.8.8": {
        "lat": 37.4056, "lon": -122.0775,
        "city": "山景城", "region": "加利福尼亚", "country": "United States",
    },
    "8.8.4.4": {
        "lat": 37.4056, "lon": -122.0775,
        "city": "山景城", "region": "加利福尼亚", "country": "United States",
    },
}

# Backward alias used in tests / external imports
_CITY_COORDS = _PLACE_COORDS


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


def is_ip_literal(ip: str) -> bool:
    """True when *ip* is a literal IPv4/IPv6 address (not a hostname)."""
    ip = (ip or "").strip()
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


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


# ip2region / 中文地名常见行政后缀（由长到短，只剥一层）
_ADMIN_SUFFIXES = (
    "特别行政区", "自治区", "自治州", "地区", "省", "市", "区", "县",
)

# 中国地理中心 — 仅作最后兜底，不应与具体省市坐标混用
_CN_COUNTRY_CENTER = (35.8617, 104.1954)


def _normalize_admin_name(name: str) -> str:
    """Strip one trailing admin suffix: 兰州市→兰州, 甘肃省→甘肃."""
    s = (name or "").strip()
    if not s or s == "0":
        return ""
    for suffix in _ADMIN_SUFFIXES:
        if s.endswith(suffix) and len(s) > len(suffix):
            return s[:-len(suffix)].strip()
    return s


def _lookup_place(name: str) -> tuple[float, float] | None:
    key = (name or "").strip()
    if not key or key == "0":
        return None
    candidates = [key]
    norm = _normalize_admin_name(key)
    if norm and norm not in candidates:
        candidates.append(norm)
    for cand in candidates:
        if cand in _PLACE_COORDS:
            return _PLACE_COORDS[cand]
        low = cand.lower()
        for k, v in _PLACE_COORDS.items():
            if k.lower() == low:
                return v
    return None


def build_manual_geo_from_fields(
    *,
    lat: str = "",
    lon: str = "",
    city: str = "",
    region: str = "",
    label: str = "",
) -> dict | None:
    """Build monitor/target geo from UI field strings.

    Returns None when all fields are empty (use automatic ip2region).
    Raises ValueError with a user-facing message on invalid input.
    """
    lat_s = (lat or "").strip()
    lon_s = (lon or "").strip()
    city_s = (city or "").strip()
    region_s = (region or "").strip()
    label_s = (label or "").strip()

    if not any((lat_s, lon_s, city_s, region_s, label_s)):
        return None

    draft: dict[str, Any] = {}
    if label_s:
        draft["label"] = label_s
    if city_s:
        draft["city"] = city_s
    if region_s:
        draft["region"] = region_s

    if lat_s or lon_s:
        if not lat_s or not lon_s:
            raise ValueError("纬度和经度须同时填写，或留空后填写城市名自动解析")
        try:
            draft["lat"] = float(lat_s)
            draft["lon"] = float(lon_s)
        except ValueError as exc:
            raise ValueError("经纬度必须是有效数字") from exc
        result = parse_manual_geo(draft)
        if result is None:
            raise ValueError("经纬度超出有效范围（纬度 -90~90，经度 -180~180）")
        return result

    place = city_s or region_s
    if not place:
        raise ValueError("仅填写显示名称无法定位，请填写经纬度或城市名")
    hit = _lookup_place(place) or _lookup_place(_normalize_admin_name(place))
    if not hit:
        raise ValueError(f"无法识别地名「{place}」，请填写经纬度或更换城市名")
    draft["lat"] = hit[0]
    draft["lon"] = hit[1]
    return parse_manual_geo(draft)


def parse_region_fields(region: str) -> dict[str, str]:
    """Parse ip2region v4 segment: Country|Region|City|ISP|ISO."""
    raw = [(p or "").strip() for p in (region or "").split("|")]
    while len(raw) < 5:
        raw.append("")
    country, province, city, isp, iso = raw[:5]
    if city == "0":
        city = ""
    return {
        "country": country,
        "region": province,
        "city": city,
        "isp": isp,
        "iso": iso.upper() if iso else "",
    }


def region_string_to_coords(region: str) -> tuple[float, float, str] | None:
    """Map ip2region region text to (lat, lon, precision)."""
    text = (region or "").strip()
    if not text:
        return None
    fields = parse_region_fields(text)
    # City → province/region → country → ISO
    for key, precision in (
        (fields["city"], "city"),
        (fields["region"], "region"),
        (fields["country"], "country"),
    ):
        hit = _lookup_place(key)
        if hit:
            return hit[0], hit[1], precision
    iso = fields.get("iso") or ""
    if len(iso) == 2 and iso in _ISO_COUNTRY:
        lat, lon = _ISO_COUNTRY[iso]
        return lat, lon, "country"
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
        wk = _WELL_KNOWN_ANYCAST.get(ip)
        if wk:
            out = {
                **wk,
                "precision": "anycast",
                "source": "wellknown",
            }
            self._cache_set(f"ip:{ip}", out)
            return out
        region = None
        if self._xdb is not None:
            try:
                region = self._xdb.search(ip)
            except Exception:
                region = None
        coords_hit = region_string_to_coords(region or "") if region else None
        if coords_hit is None:
            self._cache_set(f"ip:{ip}", None)
            return None
        lat, lon, precision = coords_hit
        fields = parse_region_fields(region or "")
        city = fields["city"] or None
        region_name = fields["region"] or None
        country = fields["country"] or "中国"
        out = {
            "lat": lat,
            "lon": lon,
            "city": city,
            "region": region_name,
            "country": country,
            "precision": precision,
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
        if not is_ip_literal(probe):
            return {"kind": "public", "geo": None}

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
