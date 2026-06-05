"""Regression checks for bug 127 (DNSSEC leaf NODATA DS vs delegation)."""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import dns_diag
from src.dns_diag import (
    DnsSecLink,
    ERROR_NO_ANSWER,
    ERROR_NXDOMAIN,
    ERROR_OK,
    _dnssec_has_ns_records,
    _dnssec_is_delegation_point,
    _verify_zone_link,
    _zone_labels_root_to_leaf,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DNS_DIAG = os.path.join(ROOT, "src", "dns_diag.py")


def _ensure_dns_stubs():
    """_verify_zone_link lazy-imports dnspython; stub when absent."""
    if "dns" in sys.modules:
        return
    stub = MagicMock()
    sys.modules["dns"] = stub
    sys.modules["dns.dnssec"] = MagicMock()
    sys.modules["dns.name"] = MagicMock()
    sys.modules["dns.rrset"] = MagicMock()


def test_zone_labels_unchanged():
    zones = _zone_labels_root_to_leaf("www.example.com")
    ok = zones == [".", "com.", "example.com.", "www.example.com."]
    print(f"Bug127 zone label walk unchanged -> {ok}")
    return ok


def test_has_ns_records_answer():
    try:
        import dns.message
        import dns.name
        import dns.rdata
        import dns.rdataclass
        import dns.rdatatype
        import dns.rrset
    except ImportError as exc:
        print(f"Bug127 has_ns answer skipped (no dnspython): {exc}")
        return True

    zone = "example.com."
    resp = dns.message.make_response(dns.message.make_query(
        dns.name.from_text(zone), dns.rdatatype.NS))
    ns_rrset = dns.rrset.from_text(
        zone, 300, dns.rdataclass.IN, "NS", "ns1.example.com.")
    resp.answer.append(ns_rrset)
    ok = _dnssec_has_ns_records(resp, zone)
    print(f"Bug127 NS in ANSWER detected -> {ok}")
    return ok


def test_has_ns_records_nodata():
    try:
        import dns.message
        import dns.name
        import dns.rdatatype
    except ImportError:
        return True

    zone = "www.google.com."
    resp = dns.message.make_response(dns.message.make_query(
        dns.name.from_text(zone), dns.rdatatype.NS))
    ok = not _dnssec_has_ns_records(resp, zone)
    print(f"Bug127 empty NS response is not delegation -> {ok}")
    return ok


def test_is_delegation_unsigned_apex():
    resolver = MagicMock()
    with patch.object(dns_diag, "_dnssec_lookup") as mock_lookup:
        mock_lookup.return_value = (MagicMock(), ERROR_OK, "")
        with patch.object(dns_diag, "_dnssec_has_ns_records", return_value=True):
            ok = _dnssec_is_delegation_point(resolver, "example.com.")
    print(f"Bug127 unsigned apex with NS is delegation -> {ok}")
    return ok


def test_is_delegation_leaf_not_cut():
    resolver = MagicMock()
    with patch.object(dns_diag, "_dnssec_lookup") as mock_lookup:
        mock_lookup.return_value = (MagicMock(), ERROR_NO_ANSWER, "")
        with patch.object(dns_diag, "_dnssec_has_ns_records", return_value=False):
            ok = not _dnssec_is_delegation_point(resolver, "www.google.com.")
    print(f"Bug127 www leaf without NS is not delegation -> {ok}")
    return ok


def test_verify_zone_link_contained_on_leaf_nodata():
    _ensure_dns_stubs()
    link = DnsSecLink(zone="www.google.com.")
    resolver = MagicMock()
    with patch.object(dns_diag, "_dnssec_lookup") as mock_lookup:
        mock_lookup.return_value = (MagicMock(), ERROR_NO_ANSWER, "")
        with patch.object(dns_diag, "_find_rrset_and_rrsig", return_value=(None, None)):
            with patch.object(dns_diag, "_dnssec_is_delegation_point", return_value=False):
                _, hint, note = _verify_zone_link(
                    resolver, "www.google.com.", {}, link)
    ok = hint == "contained" and "非 delegation" in note
    print(f"Bug127 DS NODATA at leaf returns contained -> {ok}")
    return ok


def test_verify_zone_link_insecure_on_unsigned_delegation():
    _ensure_dns_stubs()
    link = DnsSecLink(zone="example.com.")
    resolver = MagicMock()
    with patch.object(dns_diag, "_dnssec_lookup") as mock_lookup:
        mock_lookup.return_value = (MagicMock(), ERROR_NO_ANSWER, "")
        with patch.object(dns_diag, "_find_rrset_and_rrsig", return_value=(None, None)):
            with patch.object(dns_diag, "_dnssec_is_delegation_point", return_value=True):
                _, hint, note = _verify_zone_link(
                    resolver, "example.com.", {}, link)
    ok = hint == "insecure" and "未签名" in note
    print(f"Bug127 DS NODATA at delegation stays insecure -> {ok}")
    return ok


def test_walk_handles_contained_hint():
    with open(DNS_DIAG, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "def _dnssec_is_delegation_point" in src
        and "def _dnssec_has_ns_records" in src
        and 'if hint == "contained":' in src
        and '"contained"' in src
        and "叶名位于已信任 zone 内（非 delegation）" in src
        and "zone provably unsigned" not in src
    )
    print(f"Bug127 source has delegation + contained walk -> {ok}")
    return ok


def test_nxdomain_not_delegation():
    resolver = MagicMock()
    with patch.object(dns_diag, "_dnssec_lookup") as mock_lookup:
        mock_lookup.return_value = (None, ERROR_NXDOMAIN, "nx")
        ok = not _dnssec_is_delegation_point(resolver, "missing.example.")
    print(f"Bug127 NXDOMAIN is not delegation -> {ok}")
    return ok


def main():
    results = [
        ("zones", test_zone_labels_unchanged()),
        ("ns_answer", test_has_ns_records_answer()),
        ("ns_nodata", test_has_ns_records_nodata()),
        ("deleg_apex", test_is_delegation_unsigned_apex()),
        ("deleg_leaf", test_is_delegation_leaf_not_cut()),
        ("contained", test_verify_zone_link_contained_on_leaf_nodata()),
        ("insecure", test_verify_zone_link_insecure_on_unsigned_delegation()),
        ("source", test_walk_handles_contained_hint()),
        ("nxdomain", test_nxdomain_not_delegation()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 127 checks passed.")


if __name__ == "__main__":
    main()
