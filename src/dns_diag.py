"""
dns_diag.py — DNS resolution diagnostics (Phases 1–3C-5)

Scope:
  • Manual-trigger queries for A / AAAA / CNAME / MX / NS / TXT / SOA.
  • CNAME chain expansion when qtype ∈ {A, AAAA} (toggleable).
  • Structured result + per-step trace for UI rendering.
  • Async runner with cancel support, sharing the global single-slot
    semaphore with ICMP diagnostics (src.diag_sem).
  • C-side window (ui/dns_diag_window.py)         — Phase 1
  • Web /api/dns_diag/* endpoints (web_server.py) — Phase 2
  • History persistence in dns_diagnostic_history — Phase 3A
    (run_dns_diag_async writes via DataStore.record_dns_diag_result
     when data_store/target_id are supplied; cancelled runs are
     skipped, every other terminal result is stored)

Phase 3B adds:
  • Optional custom nameserver (single IP literal).  Engine, validation,
    C-side window and Web Tab all respect req.nameserver; the original
    DB schema is untouched — the snapshot lives in details_json so we
    don't need a v5 migration just to track a single field.

Phase 3C-1 adds:
  • "compare" mode — same domain, system default vs user-picked IP,
    run SEQUENTIALLY (system → custom) inside a single DIAG_TASK_SEM
    slot.  Why sequential, not parallel:
      - Parallel would need a second sem slot or break the "1 diag at a
        time" contract (ICMP/DNS share the slot).
      - Sequential output is the operator's mental model: "baseline,
        then comparison" — and lets us interrupt cleanly between the
        two halves on Stop without aborting an in-flight resolve.
      - RTT skew from parallel UDP sends would distort the "耗时" delta.
    Cancel is checked between the two queries, before any second-half
    work starts.  v1 verdict is structural only (answer-value set
    equality); TTL / CNAME-chain differences are surfaced as hints
    but do not flip success → false on their own.  Schema is unchanged
    — compare snapshots live entirely inside details_json.mode=compare.

Phase 3C-3 adds:
  • Multi-resolver compare — 系统默认 + 最多 _MAX_COMPARE_CUSTOM_NS=3
    个自定义 IP，共 ≤ 4 列对照.  Run order is system → custom₁ → … →
    customₙ, always sequential (same rationale as 3C-1).  Cancel
    checks live BETWEEN sides (N+1 checkpoints); cancelled runs are
    discarded entirely (no partial persistence).
  • Engine: DnsDiagRequest gains `nameservers: list[str]` (preferred
    in compare mode); the legacy single-value `nameserver` is still
    accepted as a 1-element fallback.  Validation enforces de-dup and
    the 1..3 length range.
  • Result: DnsCompareResult.sides: list[DnsCompareSide] is the new
    canonical container; `.system` / `.custom` survive as @property
    aliases pointing at sides[0] / sides[1] so older history rows and
    any caller written against the 3C-1 shape keep working.
  • Diff matrix: build_compare_diff_matrix(sides) returns an N-column
    matrix with `side_labels: [{key,label}, …]` and per-row
    `cells: {key: {text,ok}}`.  When sides has length 2 the rows ALSO
    carry redundant `system/custom` keys so older JS fallbacks keep
    rendering correctly.
  • Serialisation: dns_compare_to_dict adds `compare_version: 2`,
    `sides: [...]`, `nameservers: [...]`; the v1 `system/custom`
    payload and the single-IP `nameserver` field are preserved for
    backward compatibility with pre-3C-3 history rows.

Phase 3C-5 adds:
  • "dnssec" mode — client-side DNSSEC validation.  Engine fetches
    DNSKEY / DS / target rrsets (with EDNS DO=1 + CD=1) via the chosen
    resolver, then validates the trust chain LOCALLY against an
    embedded IANA Root KSK-2017 anchor (key tag 20326).  The result
    is a DnsSecResult carrying a verification chain (one DnsSecLink
    per zone from "." down to leaf) plus a four-state verdict:
       SECURE        – chain fully validated end-to-end
       INSECURE      – some parent zone has no DS for its child
                       (zone未签名 — extremely common in CN)
       BOGUS         – DS / DNSKEY / RRSIG cryptographic check failed
       INDETERMINATE – network / config error; verdict undetermined
    The mode is single-slot like compare / trace_auth.  We do NOT
    trust the resolver's AD bit — it is reported in result.ad_flag
    purely as an informational signal.  NSEC / NSEC3 existence proof
    for NXDOMAIN is OUT of v1 scope; an NXDOMAIN response just
    becomes INDETERMINATE with an explanatory message.
  • requirements.txt adds cryptography>=41.0 so dns.dnssec.validate
    can handle ECDSA / Ed25519 / RSASHA256 (the only legacy-RSA case
    dnspython handles without it is RSA/SHA1, which ~no signed zone
    uses anymore).

OUT of scope (reserved for later phases):
  • Five-or-more resolver comparison
  • Dual-CUSTOM compare (the system side is always implicit baseline)
  • Parallel cross-resolver queries
  • NSEC / NSEC3 existence proof for NXDOMAIN
  • Combined DNSSEC + authority-trace one-button workflow
  • Online trust-anchor refresh (root KSK rollover handling)
  • Periodic / scheduled DNS diagnostics
  • Partial persistence of cancelled multi-side runs ("M/N completed")

Architectural note:
  The regular monitoring loop has its OWN DNS implementation
  (ping_engine.DNSMonitor — a UDP A-record probe with hijack detection).
  Do NOT touch it.  This module is an independent dnspython-based query
  engine used only when the user opens the 🌐 diagnostics window.  The
  two paths must never share state, otherwise an on-demand query could
  pollute the monitor's alerting decisions.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Literal, Optional

# dnspython is a hard dependency declared in requirements.txt.  We import
# lazily inside _do_query() instead of at module load, so a misconfigured
# install only breaks the diagnostic window — not the whole app launch.
# The lazy import also keeps PyInstaller's static analysis honest:
# hiddenimports in build_exe.spec already declares the dns submodules.

from src.diag_sem import DIAG_TASK_SEM


# ── Public type aliases ─────────────────────────────────────────────────

DnsQType = Literal["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
_VALID_QTYPES: tuple = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")

# Phase 3C-1: query mode.  "single" preserves Phase 3B behaviour byte-
# for-byte; "compare" runs the same query against system DNS then a
# user-supplied IP, sequentially, and packs both results + a verdict
# into a DnsCompareResult.  See module docstring for the why-sequential
# rationale.
#
# Phase 3C-4 adds "trace_auth" — iterative resolution starting at the
# IPv4 root hints, walking the delegation chain zone-by-zone (RD=0) to
# the authoritative NS, then querying the target qtype.  The result is
# a DnsAuthResult carrying the full hop log; CNAME chasing inside the
# regular resolver paths is replaced here by an OPTIONAL one-step
# follow at the very end (see run_dns_auth_trace).  The mode is single-
# slot like compare (one DIAG_TASK_SEM at a time) and ALWAYS uses the
# system network UDP/53 — `nameserver` / `nameservers` are silently
# ignored because trace_auth is conceptually "what would a recursive
# resolver have done if it started fresh".
#
# Phase 3C-5 adds "dnssec" — client-side DNSSEC validation.  Uses the
# chosen resolver (system default or operator-supplied IP, same as
# single mode) purely as a TRANSPORT for fetching DNSKEY / DS / target
# rrsets with EDNS DO=1 + CD=1 set, then validates the trust chain
# LOCALLY against an embedded IANA root KSK.  The AD bit on the
# response is recorded as informational but is NEVER consulted for
# the SECURE / INSECURE / BOGUS / INDETERMINATE verdict — the whole
# point is to not trust the resolver's word.  `nameservers` /
# `trace_chain` / `auth_max_hops` are silently ignored.
DnsQueryMode = Literal["single", "compare", "trace_auth", "dnssec"]
_VALID_MODES: tuple = ("single", "compare", "trace_auth", "dnssec")

# Maximum CNAME chain depth before we declare a loop / chain-too-deep.
# 10 is generous — RFC-compliant chains are usually 1–3 deep; > 10
# indicates a misconfiguration or an intentional loop.
_MAX_CNAME_DEPTH = 10

# Phase 3C-3: maximum number of CUSTOM resolvers in compare mode (the
# system side is always implicit and not counted).  v1 cap is 3 → 4
# total columns with the system side.  Reasons for capping at 3:
#   • 4 columns is the widest layout that still keeps IP values on
#     one line inside the 1100 px diff modal without ellipsis-ing
#     IPv6 addresses.
#   • Past 5 the diff verdict text becomes unreadable ("分歧在 col-2、
#     col-4、col-7…") and the cancel UX gets fuzzy (which side is the
#     worker on right now?).
#   • The whole point of compare mode is operator triage, not bulk
#     benchmarking — N=4 covers ~all "system vs Google vs Cloudflare
#     vs 114" workflows.
_MAX_COMPARE_CUSTOM_NS = 3

# Phase 3C-4: maximum hops in an authority-trace walk (counting EVERY
# RD=0 query — referrals, CNAME-follow re-iteration, glue-fix borrows).
# 12 is comfortable: a TLD chain rarely needs more than 5 (root → TLD
# → SLD → optional sub-delegations → final qtype), and CNAME follow
# adds at most another full chain.  Past 12 we're almost certainly in
# a delegation loop or hostile zone; surface ERROR_AUTH_MAX_HOPS so
# the operator sees what was already collected.
_MAX_AUTH_HOPS = 12

# Phase 3C-4: per-hop UDP timeout floor — the operator-supplied
# req.timeout_s gets clamped to MIN here so a typo'd 0.05 timeout
# doesn't burn all _MAX_AUTH_HOPS slots on flaky-network back-offs.
_MIN_AUTH_HOP_TIMEOUT_S = 0.5

# Phase 3C-4: when a referral lacks glue (next NS only given by name,
# no in-bailiwick A/AAAA in ADDITIONAL), we ask the SYSTEM recursive
# resolver to resolve the NS hostname → IP and then continue iterating.
# This consumes one "glue borrow" budget per zone; if we still can't
# get a usable IP after exhausting the budget, the hop fails with
# ERROR_GLUE_MISSING.  Budget per missing-NS event is 1 (one borrow
# attempt covers ALL of the referral's NS names since one resolver
# call returns whatever IPs the system DNS has cached).
_AUTH_GLUE_BORROW_BUDGET = 1

# Phase 3C-4: IANA root server list (IPv4 only — v1 scope).  Each is
# a public anycast cluster, but for the trace we pick ONE (a) and only
# fall back to b/c if a times out — the operator's intent is "show me
# the iterative walk", not "stress-test root anycast".  Names carried
# for display in the first hop's server_host field.
_ROOT_IPV4_HINTS: list = [
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "170.247.170.2"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
]
_ROOT_TRY_LIMIT = 3   # try at most a/b/c if earlier ones time out


# ── Unified error codes ─────────────────────────────────────────────────

ERROR_OK                  = "ok"
ERROR_TIMEOUT             = "timeout"
ERROR_NXDOMAIN            = "nxdomain"
ERROR_NO_ANSWER           = "no_answer"
ERROR_SERVFAIL            = "servfail"
ERROR_REFUSED             = "refused"
ERROR_RESOLVER_UNREACH    = "resolver_unreachable"
ERROR_INVALID_DOMAIN      = "invalid_domain"
ERROR_CANCELLED           = "cancelled"
ERROR_CNAME_LOOP          = "cname_loop"
ERROR_CNAME_TOO_DEEP      = "cname_too_deep"
# Phase 3C-4 — authority-trace specific terminal codes.
ERROR_AUTH_MAX_HOPS       = "auth_max_hops"
ERROR_GLUE_MISSING        = "glue_missing"
ERROR_AUTH_TRACE_FAILED   = "auth_trace_failed"
# Phase 3C-5 — DNSSEC-specific terminal codes.  These are NOT used as
# DnsSecResult.status (which is the 4-state secure / insecure / bogus
# / indeterminate enum); they only flow through the persistence layer
# as error_summary so the history filter on rcode != NOERROR still
# distinguishes "未签名" (operationally fine) from "签名错误" (an
# actual incident).  The DnsSecResult.status field is the canonical
# verdict — see DnsSecStatus / run_dnssec_validate.
ERROR_DNSSEC_INSECURE     = "dnssec_insecure"
ERROR_DNSSEC_BOGUS        = "dnssec_bogus"
ERROR_DNSSEC_INDETERMINATE= "dnssec_indeterminate"
ERROR_UNKNOWN             = "unknown_error"


# ── Phase 3C-5: Root trust anchor (IANA Root KSK-2017, key tag 20326) ──
#
# This is the public Key Signing Key for the DNS root zone ("."), the
# foundation of all DNSSEC validation.  Hard-coded as a DNSKEY RR text
# so the validator does not need any network bootstrap to know what to
# trust — exactly the property a "client-side independent validation"
# is supposed to have.
#
# Format mirrors the IANA-published trust anchor XML:
#   . IN DNSKEY 257 3 8 <base64-public-key>
# Field meanings:
#   257  flags  (256 = ZSK, 257 = KSK + SEP).  We embed only the KSK.
#   3    protocol (always 3 for DNSSEC)
#   8    algorithm (RSA/SHA-256, the algorithm KSK-2017 uses)
#   ...  base64-encoded RSA-2048 public key
#
# Out-of-scope (per 3C-5 plan §13):
#   • Online refresh.  When ICANN next rolls the KSK (KSK-2024 or
#     later), this constant must be updated in a code release; the
#     validator does NOT fetch a fresh anchor over the network.
#   • Multiple anchors.  IANA's trust-anchor XML can carry several
#     keys in parallel during a rollover; v1 only ships the single
#     active KSK to keep the bootstrap obvious.
# DNSKEY rdata text — just the four fields (flags, protocol, algorithm,
# base64 key).  Stored without name / ttl / class so it can be fed
# straight to dns.rdata.from_text without a zone-file pre-parse pass.
_ROOT_KSK_2017_DNSKEY_RDATA = (
    "257 3 8 "
    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3"
    "+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv"
    "ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF"
    "0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e"
    "oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd"
    "RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN"
    "R1AkUTV74bU="
)
# Documented key tag of the embedded KSK; computed at module load and
# cached for the chain-validation early-exit when a fetched root
# DNSKEY rrset does not contain this key tag.
_ROOT_KSK_2017_KEY_TAG = 20326

# Phase 3C-5: DS digest-algorithm human labels for the verification
# chain UI.  The numeric IANA codes are otherwise opaque on the wire.
# 1 (SHA-1) is deprecated but still in use; 2 (SHA-256) is the default
# for modern delegations; 4 (SHA-384) is used by some signed TLDs.
_DS_DIGEST_NAMES: dict = {
    1: "SHA-1",
    2: "SHA-256",
    3: "GOST-94",   # historical, rarely seen
    4: "SHA-384",
}


# ── Data models ─────────────────────────────────────────────────────────

@dataclass
class DnsDiagRequest:
    """Unified DNS diagnostic request."""
    target:       str
    qtype:        DnsQType = "A"
    timeout_s:    float    = 2.0
    # Only meaningful when qtype is A / AAAA: walk CNAME chain to its
    # terminal IP.  Other qtypes return their direct answer (e.g. asking
    # for CNAME on an A-only name must return no_answer, NOT auto-recurse).
    trace_chain:  bool     = True
    # Phase 3B: optional custom resolver.  None / "" → system default
    # (dnspython picks up /etc/resolv.conf or the OS DNS list).  When
    # set, must be an IPv4 / IPv6 literal — domain names rejected at
    # validation time so the diag module never re-enters DNS to find
    # its own resolver.  Single NS only.
    #
    # Phase 3C-1 / 3C-3 semantics:
    #   mode=single  — `nameserver` is the (optional) custom resolver.
    #                  None / "" means "use system default" (3B behaviour).
    #                  `nameservers` is ignored here.
    #   mode=compare — `nameservers` (plural) is the preferred field
    #                  carrying 1..3 custom IPs (system side is always
    #                  implicit baseline).  If `nameservers` is None /
    #                  empty, the engine falls back to the single
    #                  `nameserver` value for backward compatibility
    #                  with 3C-1 callers.  Validation rejects empty
    #                  compare requests.
    nameserver:   Optional[str] = None
    # Phase 3C-3: optional list of custom resolvers for compare mode.
    # When non-None / non-empty, takes precedence over `nameserver`.
    # Plain Python list (not tuple) so the dataclass default_factory
    # protocol works without import gymnastics.
    nameservers:  Optional[List[str]] = None
    # Phase 3C-1: query mode.  Defaults to "single" so every call site
    # that pre-dates 3C-1 keeps working without code changes.  "compare"
    # is dispatched in run_dns_diag_async (the sync run_dns_diag still
    # only handles single-resolver queries; compare callers should use
    # run_dns_compare instead — see that function's docstring).
    #
    # Phase 3C-4 adds "trace_auth" — when set, the engine ignores
    # nameserver/nameservers/trace_chain and walks the delegation chain
    # from the IPv4 root hints via RD=0 UDP queries.  Result is a
    # DnsAuthResult (see run_dns_auth_trace).  Validation enforces the
    # "no custom resolver" rule for trace_auth so an operator who
    # leaves chips populated then flips to trace_auth doesn't get a
    # silently-ignored input.
    mode:         DnsQueryMode = "single"
    # Phase 3C-4: maximum hops in an authority-trace walk.  Clamped to
    # 4.._MAX_AUTH_HOPS by validate_dns_request.  Default 12 matches
    # the engine cap so a caller can omit the field for the common
    # case.  Only consulted when mode == "trace_auth".
    auth_max_hops: int          = _MAX_AUTH_HOPS


@dataclass
class DnsAnswer:
    """One DNS answer record."""
    name:        str
    qtype:       str
    value:       str
    ttl:         Optional[int] = None
    preference:  Optional[int] = None   # MX only


@dataclass
class DnsTraceStep:
    """One step in the CNAME-walking trace (or the initial query for
    non-A/AAAA types)."""
    query_name:     str
    query_type:     str
    status:         str
    ttl:            Optional[int] = None
    answer_summary: str           = ""


@dataclass
class DnsDiagResult:
    """Aggregate result of a DNS diagnostic run."""
    target:       str
    qtype:        str
    resolver:     str
    success:      bool
    rcode:        str
    elapsed_ms:   float
    cname_chain:  List[str]            = field(default_factory=list)
    answers:      List[DnsAnswer]      = field(default_factory=list)
    trace_steps:  List[DnsTraceStep]   = field(default_factory=list)
    message:      str                  = ""
    # Phase 3B snapshot of req.nameserver.  Empty string == system
    # default; non-empty == the IP literal we forced dnspython to use.
    # Separate from `resolver` (which carries the display label, often
    # an IP either way) so consumers can disambiguate "we used the
    # system NS which happens to be 8.8.8.8" from "user picked 8.8.8.8".
    nameserver:   str                  = ""


@dataclass
class DnsCompareSide:
    """One side of a Phase 3C-3 multi-resolver comparison.

    Carries the full single-query result plus the metadata UI layers
    need to render headers / detail-panel titles without re-deriving
    them from `result.resolver` (which gets fuzzy for the system side
    where dnspython's nameservers list may resolve to a non-public IP
    that doesn't match what the operator chose).

    key:    stable identifier — "system" for the always-first
            baseline, "r1" / "r2" / "r3" for the custom sides in
            insertion order.  Used as the cell-dict key in the diff
            matrix output AND as the lookup key for C-side detail
            panel toggling.  NEVER reused across sides in the same
            run (the diff matrix counts on uniqueness).
    label:  the human-facing IP / hostname displayed in column
            headers and detail toggles.  System side label is the
            actual resolver dnspython picked (so the operator can
            see "我的系统 DNS 实际是哪一个"); custom sides use the
            IP the operator typed verbatim.
    result: the single-query DnsDiagResult.  Inherits all 3B fields
            including the per-side `nameserver` snapshot (empty for
            the system side, the literal IP for custom sides).
    """
    key:    str
    label:  str
    result: "DnsDiagResult"


@dataclass
class DnsCompareResult:
    """Aggregate result of a Phase 3C-3 multi-resolver comparison.

    Carries N (1..4) DnsCompareSide entries.  Side 0 is ALWAYS the
    system-default baseline (its key is the literal string "system"
    so renderers can special-case it without index arithmetic).
    Sides 1..N-1 are the custom resolvers in the order the operator
    added them in the UI.

    Top-level `success` is the structural verdict produced by
    build_compare_conclusion: True iff every side .success is True
    AND every side's answer-key set equals side 0's.  TTL drift and
    CNAME-chain shape differences are annotated in `conclusion` but
    do NOT flip success on their own — those are normal between
    resolvers with independent caches.

    `elapsed_ms` is wall time across ALL N queries plus bookkeeping
    (typically ≈ Σ side.elapsed_ms).  History rows store this in the
    regular elapsed_ms column so the history "耗时" stays consistent
    across single / compare / multi-compare runs.

    Backward compatibility:
      The 3C-1 / 3C-2 callers expected `.system` and `.custom` fields
      directly on this dataclass.  We expose them as @property aliases
      pointing at sides[0] / sides[1] so a 2-side compare run looks
      identical to those callers; a 3-side / 4-side run still answers
      `.custom` with sides[1].result (the FIRST custom side, matching
      the legacy "the custom" mental model).  Callers that need all
      custom sides must read `.sides` directly.
    """
    target:       str
    qtype:        str
    trace_chain:  bool
    # Phase 3C-3: full list of custom resolver IPs in operator-input
    # order (the system side is always implicit).  Empty list would
    # indicate an invalid request; validate_dns_request blocks that
    # so we never construct one in practice.
    nameservers:  List[str]
    sides:        List[DnsCompareSide]
    success:      bool              # structural verdict (see build_compare_conclusion)
    conclusion:   str               # human-readable Chinese summary
    elapsed_ms:   float             # wall time across ALL queries

    # ── v1 / 3C-1 compatibility aliases ─────────────────────────────
    @property
    def nameserver(self) -> str:
        """First custom IP, or "" if none.  Mirrors the 3C-1 scalar field."""
        return self.nameservers[0] if self.nameservers else ""

    @property
    def system(self) -> Optional["DnsDiagResult"]:
        """Baseline side — equivalent to the old `.system` attribute."""
        return self.sides[0].result if self.sides else None

    @property
    def custom(self) -> Optional["DnsDiagResult"]:
        """First custom side — equivalent to the old `.custom` attribute.

        In 3C-3 multi-compare runs there may be additional custom sides
        at sides[2..]; consumers that care about ALL custom sides must
        iterate `.sides[1:]` directly.
        """
        return self.sides[1].result if len(self.sides) > 1 else None


# ── Phase 3C-4: authority-trace data models ─────────────────────────────

@dataclass
class DnsAuthHop:
    """One step of the iterative authority walk.

    Field-by-field rationale:
      hop_index      ordinal 1..N — UI uses it as the row index in the
                     tree view; not strictly needed for replay but
                     surviving the JSON round-trip keeps the tree
                     stable even when a renderer reorders hops by
                     accident.
      zone           the zone we just asked ABOUT (e.g. "com.",
                     "example.com.").  For the very first hop this is
                     "." (root); for the CNAME-follow segment it's the
                     CNAME target's zone walked from root again.
      qname          the actual question name sent.  Equal to `zone`
                     for referral hops, equal to the original target
                     for the final qtype query.
      qtype          NS for referral hops, the request's qtype for the
                     final query / each CNAME-follow's final query.
      server_host    NS hostname we sent the query TO ("a.root-
                     servers.net" / "a.gtld-servers.net" / ...).  Empty
                     when we only know the IP (rare — e.g. glue with
                     no PTR/name).
      server_ip      the IP the UDP packet actually went to.  This is
                     the source of truth for "where did this answer
                     come from?"; UI must display it.
      rcode          textual rcode of the response, or "" when the
                     query never produced a response (timeout etc.).
      rtt_ms         wall-clock round-trip in milliseconds.  -1.0 when
                     no response came back.
      success        did THIS hop produce a usable next-step input?
                     True for both clean referrals AND the final
                     authoritative answer; False for any error.
      answer_summary short text rendered as the hop's secondary line in
                     the tree view ("→ NS a.gtld-servers.net…" or
                     "A 1.2.3.4 (+2)").  Building it on the engine
                     side keeps UI renderers consistent across C/Web.
      referral_ns    NS names the hop returned in AUTHORITY when this
                     was a referral.  Empty on final/non-referral hops.
      glue           per-NS glue IP records pulled from ADDITIONAL,
                     formatted "ns1.x.com → 1.2.3.4".  Empty when no
                     glue accompanied the referral.
      error_code     unified error_code constant (ERROR_*) when
                     success is False; "" otherwise.
      message        Chinese-language one-line summary surfaced to the
                     operator in the tree view.  Populated whenever the
                     answer_summary alone is not self-explanatory (glue
                     borrow, CNAME continuation, error explainer …).
    """
    hop_index:      int
    zone:           str
    qname:          str
    qtype:          str
    server_host:    str
    server_ip:      str
    rcode:          str
    rtt_ms:         float
    success:        bool
    answer_summary: str           = ""
    referral_ns:    List[str]     = field(default_factory=list)
    glue:           List[str]     = field(default_factory=list)
    error_code:     str           = ""
    message:        str           = ""


@dataclass
class DnsAuthResult:
    """Aggregate result of an authority-trace walk.

    success  True iff we reached an authoritative NS AND received a
             usable answer of the requested qtype (or, with CNAME
             follow, the qtype at the CNAME's target).
    rcode    rcode of the FINAL hop on success, or of the FIRST
             failing hop on failure — both are what an operator
             wants to see on the verdict bar.
    elapsed_ms  total wall time across all hops + bookkeeping.
    message  one-line Chinese conclusion (always non-empty).
    cname_chain  optional 1-step CNAME-follow link recorded as
             [orig_target, cname_target] when the engine ended up
             chasing the alias.  Empty when no follow was needed.
             Kept compatible with DnsDiagResult.cname_chain so the
             same C-side tracert button can be plugged in if we
             ever expose A-record tracing from the auth tree.
    """
    target:         str
    qtype:          str
    hops:           List[DnsAuthHop]
    final_answers:  List[DnsAnswer]
    success:        bool
    rcode:          str
    elapsed_ms:     float
    message:        str               = ""
    cname_chain:    List[str]         = field(default_factory=list)


# ── Phase 3C-5: DNSSEC validation data models ───────────────────────────
#
# Status is a four-state enum (not a boolean) because the field has more
# meaning than success/failure in DNSSEC contexts:
#   secure        — trust chain complete, signatures all verify.
#   insecure      — at some level the parent zone has NO DS for the
#                   child (zone is provably unsigned).  This is the
#                   normal state for the majority of CN domains and
#                   MUST NOT be rendered as a red ✗ in the UI; it's
#                   simply "DNSSEC not deployed here".
#   bogus         — at some level a signature failed cryptographically.
#                   This IS a finding — either zone misconfiguration
#                   or active tampering.
#   indeterminate — network / timeout / SERVFAIL / unimplemented edge
#                   case (e.g. NXDOMAIN — NSEC proof out of v1 scope).
#                   Different from BOGUS in that we cannot make any
#                   claim about whether the data was tampered with.
DnsSecStatus = Literal["secure", "insecure", "bogus", "indeterminate"]


@dataclass
class DnsSecLink:
    """One level of the DNSSEC verification chain (root → leaf zone).

    Each link represents a SINGLE zone — its DNSKEY rrset, the DS
    that the parent zone provides for it, and the outcome of binding
    the two together via DNSSEC hash + signature checks.

    Field-by-field rationale:
      zone        the zone we just verified — "." for root, "com."
                  for the TLD, … leaf zone last.  Always dot-terminated
                  to mirror dnspython's name normalisation.
      has_ds      whether the parent zone returned ANY DS records for
                  this zone.  False at the root link (no parent) and
                  False at the boundary where INSECURE was detected.
      ds_ok       whether at least one parent DS digest matched the
                  hash of one of this zone's DNSKEY records.  Only
                  meaningful when has_ds is True; False otherwise.
      has_dnskey  whether this zone's own DNSKEY rrset was fetched.
                  False on root if the resolver flat-out didn't return
                  the root DNSKEYs (treat as INDETERMINATE).
      dnskey_ok   whether the DNSKEY rrset itself verified — via the
                  embedded trust anchor for root, via a matched-DS KSK
                  for non-root zones.  When False the chain is BOGUS
                  unless has_ds was also False (then it's INSECURE).
      algorithm   short human label for the digest algorithm that
                  proved DS ↔ DNSKEY matching (e.g. "SHA-256").  Empty
                  on root (no DS) and on insecure / failed links.
      note        Chinese one-liner shown verbatim in the UI tree row.
                  Always non-empty when has_dnskey / ds_ok / etc.
                  carry meaningful state; explains the verdict so the
                  operator doesn't have to decode boolean flags by
                  eye.
    """
    zone:         str
    has_ds:       bool       = False
    ds_ok:        bool       = False
    has_dnskey:   bool       = False
    dnskey_ok:    bool       = False
    algorithm:    str        = ""
    note:         str        = ""


@dataclass
class DnsSecResult:
    """Aggregate result of a Phase 3C-5 DNSSEC validation run.

    target       the original operator-typed domain (before any CNAME
                 chasing).  Preserved verbatim so history rows reflect
                 the request, not the canonical leaf.
    qtype        the queried type — A / AAAA / CNAME / MX / NS / TXT /
                 SOA.  For A / AAAA the engine first chases CNAMEs to
                 a terminal name (≤ _MAX_CNAME_DEPTH) and validates
                 the leaf zone's chain; cname_chain records the walk.
                 For other qtypes the engine validates the chain for
                 the target name itself (no CNAME chasing).
    resolver     display label of the resolver actually used as
                 TRANSPORT.  Same semantics as DnsDiagResult.resolver
                 — system default name or the operator-typed IP.
    nameserver   Phase 3B snapshot of req.nameserver (empty string
                 means "we used the system default").  Stored
                 alongside resolver so consumers can disambiguate the
                 two without re-deriving.
    status       four-state DnsSecStatus enum — see module-level note.
    chain        verification chain from root (chain[0]) down to leaf.
                 Always non-empty when status is not "indeterminate";
                 an indeterminate verdict due to e.g. a resolver
                 timeout MAY have an empty chain.
    answers      target rrset rendered as DnsAnswer objects, exactly
                 as the single-mode renderer expects.  Populated even
                 on INSECURE so the operator still sees the resolver's
                 answer — the verdict just says "this answer is not
                 cryptographically backed".  Empty when no rrset was
                 obtainable (timeout / NXDOMAIN).
    rrsig_ok     terminal RRSIG validation outcome for the target
                 rrset.  True iff one of the leaf zone's RRSIGs over
                 the target rrset validated against the trusted DNSKEY
                 set.  False (and status == "bogus") on cryptographic
                 failure; False (and status == "insecure") when there
                 is no signature to check; False on NO_ANSWER.
    ad_flag      the AD bit on the FINAL response from the resolver.
                 Informational ONLY — DnsSecStatus is NOT derived
                 from it.  When the resolver is a public validator
                 like 1.1.1.1 / 8.8.8.8 the bit will usually match
                 our verdict on SECURE zones; on INSECURE zones the
                 bit is typically 0; on BOGUS responses the resolver
                 will have already replied SERVFAIL so the bit is
                 absent.  We surface it so operators comparing
                 "what does the resolver claim" vs "what does my own
                 validator say" can spot disagreements.
    elapsed_ms   wall time across the entire validate sequence.
    message      Chinese one-line conclusion (always non-empty).
                 Used as the verdict-bar text and as the persisted
                 history `message` column.
    cname_chain  CNAME walk preceding the final qtype query — same
                 semantics as DnsDiagResult.cname_chain.  Empty for
                 non-A/AAAA qtypes or names that resolved directly.
    """
    target:       str
    qtype:        str
    resolver:     str
    nameserver:   str
    status:       DnsSecStatus
    chain:        List[DnsSecLink]
    answers:      List[DnsAnswer]
    rrsig_ok:     bool
    ad_flag:      Optional[bool]
    elapsed_ms:   float
    message:      str
    cname_chain:  List[str]            = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Strict mapping: success == SECURE.

        Rationale (3C-5 plan §6.3, Q2 confirmed by user):
          INSECURE is NOT a failure operationally, but mapping it to
          success=True would also be wrong — a green ✓ in the history
          list would suggest "DNSSEC verified" when the truth is
          "DNSSEC not deployed".  UI layers (C / Web) render the
          four-state status separately so the history list's
          success/failure pill remains the strict signal while the
          verdict bar carries the nuanced INSECURE / BOGUS / INDET
          colour.
        """
        return self.status == "secure"


# ── JSON serialisation (Phase 2 web layer pre-baked) ────────────────────

def _answer_to_dict(a: DnsAnswer) -> dict:
    return {
        "name":       a.name,
        "qtype":      a.qtype,
        "value":      a.value,
        "ttl":        a.ttl,
        "preference": a.preference,
    }


def _step_to_dict(s: DnsTraceStep) -> dict:
    return {
        "query_name":     s.query_name,
        "query_type":     s.query_type,
        "status":         s.status,
        "ttl":            s.ttl,
        "answer_summary": s.answer_summary,
    }


def dns_result_to_dict(r: DnsDiagResult) -> dict:
    """Serialize a DnsDiagResult to a plain dict for JSON transport.

    The `nameserver` field is the Phase-3B snapshot of req.nameserver;
    empty string == system default.  Persisting it inside details_json
    avoids a DB schema bump while still letting the history list show
    a clear "NS: 8.8.8.8" tag for custom-resolver runs.
    """
    return {
        "target":      r.target,
        "qtype":       r.qtype,
        "resolver":    r.resolver,
        "success":     r.success,
        "rcode":       r.rcode,
        "elapsed_ms":  r.elapsed_ms,
        "cname_chain": list(r.cname_chain),
        "answers":     [_answer_to_dict(a) for a in r.answers],
        "trace_steps": [_step_to_dict(s) for s in r.trace_steps],
        "message":     r.message,
        "nameserver":  r.nameserver or "",
    }


def dns_compare_to_dict(r: DnsCompareResult) -> dict:
    """Serialize a DnsCompareResult to a plain dict for JSON transport.

    Phase 3C-3 emits the v2 shape:
      • `compare_version: 2` — sniffable by replay paths.
      • `sides: [{key,label,result}, …]` — the canonical N-side payload.
      • `nameservers: [...]` — the operator-supplied custom IPs in order.
      • `diff: {side_labels: [...], rows: [...]}` — pre-computed N-column
        diff matrix (see build_compare_diff_matrix).

    For backward compatibility we ALSO emit the v1 (3C-1 / 3C-1.5) keys
    so any code path written against the older shape — history replay
    for pre-3C-3 rows, third-party scrapers, in-flight UI bundles — keeps
    rendering without translation:
      • `system` — copy of sides[0].result
      • `custom` — copy of sides[1].result (if present)
      • `nameserver` — first custom IP (empty if none)
      • `diff.side_labels` ALSO includes a `system` / `custom` shim when
        N == 2 (see build_compare_diff_matrix).
    """
    sides_out = [
        {
            "key":    s.key,
            "label":  s.label or "",
            "result": dns_result_to_dict(s.result) if s.result is not None
                       else None,
        }
        for s in r.sides
    ]
    out = {
        "mode":            "compare",
        "compare_version": 2,
        "target":          r.target,
        "qtype":           r.qtype,
        "trace_chain":     bool(r.trace_chain),
        "nameserver":      r.nameserver or "",
        "nameservers":     list(r.nameservers or []),
        "success":         bool(r.success),
        "conclusion":      r.conclusion or "",
        "elapsed_ms":      r.elapsed_ms,
        "sides":           sides_out,
        # Phase 3C-1.5 — diff-first UI matrix; recomputed at serialise
        # time so history replay tracks the latest diff algorithm even
        # when older rows were stored before the matrix existed.
        "diff":            build_compare_diff_matrix(r.sides),
    }
    # ── v1 (3C-1) compatibility shim ────────────────────────────────
    # Older history replay code and the legacy diff fallback both reach
    # for top-level system/custom dicts; emit them so a single v2 row
    # is still consumable by a v1 renderer without translation.
    if r.sides:
        out["system"] = sides_out[0]["result"]
    if len(r.sides) > 1:
        out["custom"] = sides_out[1]["result"]
    return out


def _auth_hop_to_dict(h: DnsAuthHop) -> dict:
    """Serialise a single authority-trace hop.

    Field names mirror the dataclass exactly so a renderer can do a
    dict-comprehension into a DnsAuthHop without translation.  Lists
    are deep-copied (slice) so a downstream mutation cannot corrupt
    the original DnsAuthResult.
    """
    return {
        "hop_index":      h.hop_index,
        "zone":           h.zone,
        "qname":          h.qname,
        "qtype":          h.qtype,
        "server_host":    h.server_host or "",
        "server_ip":      h.server_ip or "",
        "rcode":          h.rcode or "",
        "rtt_ms":         h.rtt_ms,
        "success":        bool(h.success),
        "answer_summary": h.answer_summary or "",
        "referral_ns":    list(h.referral_ns or []),
        "glue":           list(h.glue or []),
        "error_code":     h.error_code or "",
        "message":        h.message or "",
    }


def dns_auth_to_dict(r: DnsAuthResult) -> dict:
    """Phase 3C-4 — serialise a DnsAuthResult to a JSON-safe dict.

    Shape is intentionally flat (no nested compare-style versioning)
    because we only ship ONE auth-result shape; future iterations
    (DNSSEC validation in 3C-5) will add fields, not restructure.
    The "mode": "trace_auth" key lets dispatchers (web /status,
    history replay, C-side _render_any_result) pick the right
    renderer without an isinstance check.
    """
    return {
        "mode":         "trace_auth",
        "target":       r.target,
        "qtype":        r.qtype,
        "success":      bool(r.success),
        "rcode":        r.rcode or "",
        "elapsed_ms":   r.elapsed_ms,
        "message":      r.message or "",
        "cname_chain":  list(r.cname_chain or []),
        "hops":         [_auth_hop_to_dict(h) for h in (r.hops or [])],
        "answers":      [_answer_to_dict(a) for a in (r.final_answers or [])],
    }


def _sec_link_to_dict(link: DnsSecLink) -> dict:
    """Serialise a single DNSSEC chain link.

    Flat shape (no nested objects) so a JS renderer can pull every
    field straight from the dict — the verification chain table is
    a 1-row-per-link layout, no compound widgets needed.
    """
    return {
        "zone":       link.zone or "",
        "has_ds":     bool(link.has_ds),
        "ds_ok":      bool(link.ds_ok),
        "has_dnskey": bool(link.has_dnskey),
        "dnskey_ok":  bool(link.dnskey_ok),
        "algorithm":  link.algorithm or "",
        "note":       link.note or "",
    }


def dnssec_to_dict(r: DnsSecResult) -> dict:
    """Phase 3C-5 — serialise a DnsSecResult to a JSON-safe dict.

    Shape is flat (no nested versioning) for the same reason as
    dns_auth_to_dict: we ship exactly one DNSSEC result shape; future
    iterations (NSEC proof, anchor refresh) will add fields, not
    restructure.

    Persistence note (decision Q2):
      • `success` mirrors DnsSecResult.success — strict SECURE-only.
        Persisted into the dns_diagnostic_history row's success column
        so the history list's red ✗ never lights up for routine
        INSECURE runs (the operator already sees them daily for
        domestic domains).  The four-state nuance lives in `status`.
      • `status` carries the canonical verdict — UIs read this for
        the verdict bar colour, NOT `success`.
      • `ad_flag` is reported as Optional[bool] so renderers can show
        "(not received)" vs "AD=0" vs "AD=1" distinctly.  We pass
        through None as null in the JSON.
    """
    return {
        "mode":        "dnssec",
        "target":      r.target,
        "qtype":       r.qtype,
        "resolver":    r.resolver or "",
        "nameserver":  r.nameserver or "",
        "status":      r.status,
        "success":     bool(r.success),
        "chain":       [_sec_link_to_dict(l) for l in (r.chain or [])],
        "answers":     [_answer_to_dict(a) for a in (r.answers or [])],
        "rrsig_ok":    bool(r.rrsig_ok),
        # Distinguish ad_flag=False (resolver reported AD=0) from
        # ad_flag=None (we never got a usable response).  json.dumps
        # serialises None to JSON null; both browsers and Python
        # json.loads round-trip that cleanly.
        "ad_flag":     r.ad_flag,
        "elapsed_ms":  r.elapsed_ms,
        "message":     r.message or "",
        "cname_chain": list(r.cname_chain or []),
    }


def dns_run_to_dict(r) -> dict:
    """Single dispatch: serialise any of the four result kinds.

    Used by callers (web /status endpoint, persistence hooks) that
    don't know upfront whether they hold a single, compare,
    trace_auth or dnssec result.  Single results get a
    `"mode": "single"` key tacked on so the front-end can always
    switch on `result.mode` without needing structural checks — the
    empty-string default of mode-less rows persists for backward-
    compat with pre-3C-1 history records.

    Phase 3C-4 / 3C-5: trace_auth and dnssec results are already
    self-tagged inside dns_auth_to_dict / dnssec_to_dict, so the
    isinstance routing here just picks the right serialiser without
    touching the payload.
    """
    if isinstance(r, DnsCompareResult):
        return dns_compare_to_dict(r)
    if isinstance(r, DnsAuthResult):
        return dns_auth_to_dict(r)
    if isinstance(r, DnsSecResult):
        return dnssec_to_dict(r)
    d = dns_result_to_dict(r)
    d["mode"] = "single"
    return d


# ── Validation ──────────────────────────────────────────────────────────

# Acceptable domain label: alphanumerics, hyphen (not leading/trailing),
# 1–63 chars per label.  We deliberately accept Punycode (xn--…) but
# reject obvious garbage early; dnspython itself would otherwise reject
# with a less helpful error.
_DOMAIN_LABEL = r"(?!-)[A-Za-z0-9\-]{1,63}(?<!-)"
_DOMAIN_RE    = re.compile(rf"^(?:{_DOMAIN_LABEL}\.)*{_DOMAIN_LABEL}\.?$")


def _normalize_compare_nameservers(req: DnsDiagRequest) -> list:
    """Phase 3C-3 — collapse req.nameservers / req.nameserver into a clean list.

    Precedence (D7 in the 3C-3 plan):
      1. `req.nameservers` (the N-IP list) when non-None and non-empty.
      2. `req.nameserver`  (the 3C-1 single-IP fallback) when non-empty.
      3. Empty list (validate_dns_request will reject in compare mode).

    Returned list preserves operator-input order (matters for diff
    column placement) and strips whitespace; it does NOT de-dup or
    range-check — those are validator responsibilities so the caller
    can surface a SPECIFIC error message ("重复" vs "超过 N 个" vs
    "解析器格式错误") instead of a swallowed silent drop.
    """
    raw: list = []
    nss = getattr(req, "nameservers", None)
    if nss:
        for x in nss:
            if isinstance(x, str):
                s = x.strip()
                if s:
                    raw.append(s)
    if not raw:
        ns = getattr(req, "nameserver", None)
        if isinstance(ns, str):
            s = ns.strip()
            if s:
                raw.append(s)
    return raw


def validate_dns_request(req: DnsDiagRequest) -> Optional[str]:
    """Return error string if invalid, else None.

    Phase 3B: the optional nameserver field, when non-empty, must be a
    bare IPv4 or IPv6 literal.  We deliberately do NOT accept hostnames
    here: this diagnostic module is supposed to BE the DNS lookup, so
    needing to resolve our own resolver would be both silly and a hidden
    failure mode (which DNS resolves the hostname → bootstraps a cycle).

    Phase 3C-1 / 3C-3 rules:
      mode=single   — unchanged 3B behaviour; `nameserver` optional,
                      `nameservers` ignored if supplied (single-side
                      semantics make a list incoherent here).
      mode=compare  — at least one custom IP required, max 3 (the
                      _MAX_COMPARE_CUSTOM_NS cap).  `nameservers`
                      takes precedence; falls back to `nameserver`
                      single value for legacy 3C-1 clients.  Each
                      IP runs through _validate_nameserver and the
                      whole list is de-duplicated (a literal repeat
                      would just be wasted work + confusing UI).
    """
    if not req.target or not req.target.strip():
        return "域名不能为空"
    name = req.target.strip()
    if len(name) > 253:
        return "域名长度超过 253 个字符"
    if not _DOMAIN_RE.match(name):
        return "域名格式不正确"
    if req.qtype not in _VALID_QTYPES:
        return f"暂不支持的查询类型：{req.qtype}"
    if not (0.2 <= req.timeout_s <= 10):
        return "超时须在 0.2–10 秒范围内"
    mode = getattr(req, "mode", "single") or "single"
    if mode not in _VALID_MODES:
        return f"暂不支持的查询模式：{mode}"

    if mode == "single":
        # Legacy single-resolver validation — only the scalar field
        # matters here; an extra nameservers[] is silently ignored
        # rather than treated as an error so a 3C-3 web client switching
        # mid-form doesn't trip a stale-state validation failure.
        ns_err = _validate_nameserver(req.nameserver)
        if ns_err is not None:
            return ns_err
        return None

    if mode == "trace_auth":
        # Phase 3C-4: authoritative-trace mode.  Custom resolver fields
        # are silently ignored (the whole point of this mode is to
        # bypass any recursive resolver and walk delegation from root),
        # but we explicitly check auth_max_hops so a stale 0 / negative
        # / wildly-large value can't pass through to the engine and
        # either short-circuit immediately or burn the slot for
        # minutes.  Clamping happens in the engine; here we only
        # reject obviously-broken values so the operator gets a clear
        # error rather than silently-clamped behaviour.
        hops = getattr(req, "auth_max_hops", _MAX_AUTH_HOPS)
        try:
            hops_i = int(hops)
        except (TypeError, ValueError):
            return "auth_max_hops 必须是整数"
        if hops_i < 4 or hops_i > _MAX_AUTH_HOPS:
            return (f"auth_max_hops 须在 4..{_MAX_AUTH_HOPS} 之间")
        return None

    if mode == "dnssec":
        # Phase 3C-5: DNSSEC validation mode.  Validation rules mirror
        # single mode (one optional custom resolver, no compare-list,
        # no auth_max_hops).  `nameservers` / `trace_chain` /
        # `auth_max_hops` are silently ignored in the engine; we don't
        # raise here so a Web client switching from a compare draft
        # straight to dnssec doesn't trip a stale-state error.
        ns_err = _validate_nameserver(req.nameserver)
        if ns_err is not None:
            return ns_err
        return None

    # mode == "compare" — multi-resolver validation.
    custom_ips = _normalize_compare_nameservers(req)
    if not custom_ips:
        # In compare mode at least one custom IP is required; empty
        # would mean "system vs system" which is a no-op.
        return "对比模式须指定至少 1 个对照解析器 IP"
    if len(custom_ips) > _MAX_COMPARE_CUSTOM_NS:
        return (f"对比模式最多支持 {_MAX_COMPARE_CUSTOM_NS} 个"
                "对照解析器")
    # Validate each IP literal.  Position-aware error so the operator
    # knows WHICH chip to fix (chip 2 vs chip 3).
    for idx, ip in enumerate(custom_ips):
        ns_err = _validate_nameserver(ip)
        if ns_err is not None:
            return f"对照解析器 #{idx + 1}：{ns_err}"
    # Reject duplicates (case / whitespace already normalised by
    # _normalize_compare_nameservers).  An exact-match duplicate would
    # waste a query slot and create a misleading "all sides agree" row.
    if len(set(custom_ips)) != len(custom_ips):
        return "对照解析器 IP 不能重复"
    return None


def _validate_nameserver(ns: Optional[str]) -> Optional[str]:
    """Validate the optional resolver IP.  Empty / None → OK (system default).

    Kept as a free function so the Web API can call it directly for
    early 400-rejection without constructing a full request object.
    """
    if ns is None:
        return None
    s = (ns or "").strip()
    if not s:
        return None
    if len(s) > 45:                       # max IPv6 string length
        return "解析器须为合法的 IP 地址"
    if "%" in s:                          # zone IDs (fe80::1%eth0) not supported
        return "解析器不支持 zone ID（含 %），请使用纯 IP"
    import socket as _sk
    for fam in (_sk.AF_INET, _sk.AF_INET6):
        try:
            _sk.inet_pton(fam, s)
            return None
        except (OSError, ValueError):
            continue
    return "解析器须为合法的 IPv4 / IPv6 地址"


# ── Resolver factory ────────────────────────────────────────────────────

def _make_resolver(timeout_s: float, nameserver: Optional[str] = None):
    """Build a dnspython Resolver.

    timeout  = per-query wait
    lifetime = total wait across retries (we set both to timeout_s so a
               failing resolver gives up promptly instead of trying every
               nameserver for the full default 5 s × N each).

    Phase 3B: when `nameserver` is a non-empty IP literal, replace the
    system-derived list with a single-element list — this guarantees
    the diagnostic talks to exactly the resolver the user picked, with
    no transparent fallback to the OS list.  Callers are expected to
    have run validate_dns_request first, but we still tolerate None /
    empty string here to keep tests and the sync path zero-config.
    """
    import dns.resolver  # lazy — see module docstring
    r = dns.resolver.Resolver()
    r.timeout  = timeout_s
    r.lifetime = timeout_s
    ns = (nameserver or "").strip()
    if ns:
        # No retries on other servers — the user explicitly chose this one.
        r.nameservers = [ns]
    return r


def _resolver_label(resolver, nameserver: Optional[str] = None) -> str:
    """Display label for the resolver actually in use.

    When the caller passed an explicit `nameserver`, we trust that
    (i.e. show the IP the user typed) so the UI summary line and the
    `resolver` column never disagree with the user's choice — even if
    dnspython for some reason normalised the address (it doesn't today,
    but pinning the label avoids surprises).
    """
    ns = (nameserver or "").strip()
    if ns:
        return ns
    try:
        sys_ns = resolver.nameservers or []
    except Exception:
        sys_ns = []
    return sys_ns[0] if sys_ns else "系统默认"


# ── Rcode / exception mapping ───────────────────────────────────────────

def _rcode_text(answer_or_response) -> str:
    """Pull a human-readable rcode string from a dnspython answer/response.

    dnspython exposes rcode as an enum; .name gives 'NOERROR', 'NXDOMAIN'…
    """
    try:
        import dns.rcode
        resp = getattr(answer_or_response, "response", answer_or_response)
        return dns.rcode.to_text(resp.rcode())
    except Exception:
        return ""


def _classify_exception(exc: BaseException) -> tuple[str, str, str]:
    """Map a dnspython exception to (error_code, rcode_text, message).

    The same dnspython call can raise NXDOMAIN, NoAnswer, NoNameservers,
    Timeout… each with subtly different semantics.  This helper keeps the
    pattern in one place so every query site classifies them the same way.
    """
    import dns.resolver
    import dns.exception
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return ERROR_NXDOMAIN, "NXDOMAIN", "域名不存在"
    if isinstance(exc, dns.resolver.NoAnswer):
        return ERROR_NO_ANSWER, "NOERROR", "查询成功但无对应记录"
    if isinstance(exc, dns.resolver.NoNameservers):
        # All resolvers either refused or failed.  Try to surface the
        # underlying rcode if dnspython attached one — otherwise classify
        # as resolver-unreachable so the user knows to check their DNS
        # setup rather than the queried domain.
        msg = str(exc).lower()
        if "servfail" in msg:
            return ERROR_SERVFAIL, "SERVFAIL", "解析器返回 SERVFAIL"
        if "refused" in msg:
            return ERROR_REFUSED, "REFUSED", "解析器拒绝查询"
        return ERROR_RESOLVER_UNREACH, "", "所有 DNS 解析器均无应答"
    if isinstance(exc, dns.exception.Timeout):
        return ERROR_TIMEOUT, "", "DNS 查询超时"
    if isinstance(exc, dns.name.EmptyLabel):
        return ERROR_INVALID_DOMAIN, "", "域名格式不合法（空标签）"
    return ERROR_UNKNOWN, "", f"{type(exc).__name__}: {exc}"


# ── Record extraction ───────────────────────────────────────────────────

def _extract_answers(name: str, qtype: str, rrset) -> list[DnsAnswer]:
    """Turn a dnspython rrset into our flat DnsAnswer list.

    qtype-specific shaping:
      A / AAAA   → value = "1.2.3.4"
      CNAME / NS → value = "target.example.com." (rstrip "." for display)
      MX         → value = "10 mail.example.com.", preference filled
      TXT        → value = concatenated character-strings, decoded utf-8
                    with errors="replace" so binary bytes don't crash
                    the renderer.  Per RFC 1035 a single TXT record can
                    carry multiple <character-string>s; we join them
                    with no separator, which matches what `dig +short`
                    shows and what most SPF/DKIM consumers expect.
      SOA        → value = "mname=… rname=… serial=… refresh=… retry=…
                    expire=… minimum=…" — a flat key=value form keeps
                    the existing one-row-per-answer table layout
                    while making each field individually scannable.
    """
    out: list[DnsAnswer] = []
    if rrset is None:
        return out
    ttl = getattr(rrset, "ttl", None)
    for rdata in rrset:
        try:
            if qtype in ("A", "AAAA"):
                value = rdata.address
            elif qtype in ("CNAME", "NS"):
                value = str(rdata.target).rstrip(".")
            elif qtype == "MX":
                tgt = str(rdata.exchange).rstrip(".")
                value = f"{rdata.preference} {tgt}"
                out.append(DnsAnswer(name=name, qtype=qtype, value=value,
                                     ttl=ttl, preference=rdata.preference))
                continue
            elif qtype == "TXT":
                # rdata.strings is a tuple[bytes]; some dnspython builds
                # expose it as `.strings`, fall back to str(rdata) which
                # already produces a quoted form for safety.
                parts = getattr(rdata, "strings", None)
                if parts:
                    value = b"".join(parts).decode("utf-8",
                                                   errors="replace")
                else:
                    value = str(rdata).strip('"')
            elif qtype == "SOA":
                # All seven SOA fields in one row.  Trailing dot strip
                # on mname/rname keeps display tidy without losing info.
                mname = str(getattr(rdata, "mname", "")).rstrip(".")
                rname = str(getattr(rdata, "rname", "")).rstrip(".")
                value = (f"mname={mname} rname={rname} "
                         f"serial={getattr(rdata, 'serial', '?')} "
                         f"refresh={getattr(rdata, 'refresh', '?')} "
                         f"retry={getattr(rdata, 'retry', '?')} "
                         f"expire={getattr(rdata, 'expire', '?')} "
                         f"minimum={getattr(rdata, 'minimum', '?')}")
            else:
                value = str(rdata)
        except Exception:
            value = str(rdata)
        out.append(DnsAnswer(name=name, qtype=qtype, value=value, ttl=ttl))
    return out


# ── Core query helper ───────────────────────────────────────────────────

def _query_once(resolver, name: str, qtype: str) -> tuple[
        Optional[object], list[DnsAnswer], str, str, Optional[int], str]:
    """Run a single resolver.resolve() call.

    Returns:
        (answer_obj_or_None, answers, error_code, rcode_text, ttl,
         answer_summary)

    answer_obj is the raw dnspython Answer if NOERROR with non-empty
    rrset, else None.
    """
    import dns.resolver

    try:
        ans = resolver.resolve(name, qtype, raise_on_no_answer=False)
    except Exception as exc:
        code, rcode, msg = _classify_exception(exc)
        return None, [], code, rcode, None, msg

    rcode = _rcode_text(ans) or "NOERROR"
    rrset = getattr(ans, "rrset", None)
    if rrset is None or len(rrset) == 0:
        # NOERROR-no-data: legitimate "name exists but no records of this
        # type".  Different from NXDOMAIN.
        return None, [], ERROR_NO_ANSWER, rcode, None, "无匹配记录"

    answers = _extract_answers(name, qtype, rrset)
    summary = ", ".join(a.value for a in answers[:3])
    if len(answers) > 3:
        summary += f"…(+{len(answers)-3})"
    ttl = getattr(rrset, "ttl", None)
    return ans, answers, ERROR_OK, rcode, ttl, summary


# ── CNAME chain walker (A / AAAA only) ──────────────────────────────────

def _walk_cname_chain(resolver, target: str, qtype: str
                      ) -> tuple[list[str], list[DnsAnswer],
                                 list[DnsTraceStep], str, str, str]:
    """Walk the CNAME chain for an A/AAAA query.

    Algorithm:
      For each step (capped at _MAX_CNAME_DEPTH):
        1. Try CNAME at current name.  If found, record link, advance.
        2. Else try the requested A/AAAA at current name.  If found,
           record final answers and stop.
        3. If both NoAnswer/NXDOMAIN at the same name, propagate that
           as the final error.
        4. If we re-visit a name we've already seen → CNAME loop.

    Returns:
      (cname_chain, final_answers, trace_steps,
       final_error_code, rcode, message)
    """
    current = target.rstrip(".").lower()
    chain:  list[str]          = [current]
    seen:   set[str]           = set()
    steps:  list[DnsTraceStep] = []

    for _depth in range(_MAX_CNAME_DEPTH):
        if current in seen:
            return (chain, [], steps, ERROR_CNAME_LOOP, "",
                    f"CNAME 链出现回环：{current}")
        seen.add(current)

        # 1) CNAME at current?  If yes, follow and re-loop.
        _, cn_answers, cn_code, cn_rcode, cn_ttl, _ = _query_once(
            resolver, current, "CNAME")
        if cn_code == ERROR_OK and cn_answers:
            next_name = cn_answers[0].value.rstrip(".").lower()
            steps.append(DnsTraceStep(
                query_name=current, query_type="CNAME",
                status=ERROR_OK, ttl=cn_ttl,
                answer_summary=f"→ {next_name}"))
            chain.append(next_name)
            current = next_name
            continue

        # Pre-terminal errors that should abort immediately
        if cn_code == ERROR_NXDOMAIN:
            steps.append(DnsTraceStep(
                query_name=current, query_type="CNAME",
                status=ERROR_NXDOMAIN, answer_summary="域名不存在"))
            return (chain, [], steps, ERROR_NXDOMAIN, "NXDOMAIN",
                    f"域名不存在：{current}")
        if cn_code in (ERROR_TIMEOUT, ERROR_RESOLVER_UNREACH,
                       ERROR_SERVFAIL, ERROR_REFUSED):
            steps.append(DnsTraceStep(
                query_name=current, query_type="CNAME",
                status=cn_code, answer_summary=ERROR_LABELS.get(cn_code, cn_code)))
            return (chain, [], steps, cn_code, cn_rcode,
                    ERROR_LABELS.get(cn_code, cn_code))

        # 2) No CNAME at current → query the requested A/AAAA there.
        _, a_answers, a_code, a_rcode, a_ttl, a_sum = _query_once(
            resolver, current, qtype)
        if a_code == ERROR_OK and a_answers:
            steps.append(DnsTraceStep(
                query_name=current, query_type=qtype,
                status=ERROR_OK, ttl=a_ttl, answer_summary=a_sum))
            return (chain, a_answers, steps, ERROR_OK, a_rcode,
                    f"解析成功，共 {len(a_answers)} 条 {qtype} 记录")
        if a_code == ERROR_NXDOMAIN:
            steps.append(DnsTraceStep(
                query_name=current, query_type=qtype,
                status=ERROR_NXDOMAIN, answer_summary="域名不存在"))
            return (chain, [], steps, ERROR_NXDOMAIN, "NXDOMAIN",
                    f"域名不存在：{current}")
        if a_code == ERROR_NO_ANSWER:
            steps.append(DnsTraceStep(
                query_name=current, query_type=qtype,
                status=ERROR_NO_ANSWER, answer_summary="无匹配记录"))
            return (chain, [], steps, ERROR_NO_ANSWER, a_rcode,
                    f"{current} 上无 {qtype} 记录")
        # Timeouts / SERVFAIL / REFUSED / unknown — propagate.
        steps.append(DnsTraceStep(
            query_name=current, query_type=qtype,
            status=a_code, answer_summary=a_sum))
        return chain, [], steps, a_code, a_rcode, a_sum

    return (chain, [], steps, ERROR_CNAME_TOO_DEEP, "",
            f"CNAME 链超过 {_MAX_CNAME_DEPTH} 层，疑似配置错误")


# ── Sync entry point ────────────────────────────────────────────────────

def run_dns_diag(req: DnsDiagRequest) -> DnsDiagResult:
    """Synchronous query — intended for tests and ad-hoc CLI use.

    Production UI must use run_dns_diag_async() to keep the Tk loop
    responsive and to obey the global single-task semaphore.

    Note: this sync path does NOT acquire DIAG_TASK_SEM.  Callers that
    care about mutex enforcement should use the async runner.
    """
    err = validate_dns_request(req)
    if err:
        return DnsDiagResult(target=req.target, qtype=req.qtype,
                             resolver="", success=False,
                             rcode="", elapsed_ms=0.0,
                             message=err)

    # Phase 3B: req.nameserver may be None / empty (system default) or
    # an IP literal; both _make_resolver and _resolver_label tolerate
    # either and produce a consistent label for the result snapshot.
    ns_snapshot = (req.nameserver or "").strip()
    resolver = _make_resolver(req.timeout_s, ns_snapshot or None)
    resolver_lbl = _resolver_label(resolver, ns_snapshot or None)
    started = time.monotonic()

    qtype = req.qtype
    if qtype in ("A", "AAAA") and req.trace_chain:
        chain, answers, steps, code, rcode, msg = _walk_cname_chain(
            resolver, req.target, qtype)
    else:
        # Direct query, no chain following.  For CNAME / MX / NS the
        # answer set IS the result; for A/AAAA with trace_chain=False
        # we still return the direct answer (CNAME absorption is the
        # resolver's job in that case).
        _, answers, code, rcode, ttl, summary = _query_once(
            resolver, req.target.rstrip("."), qtype)
        chain = []
        steps = [DnsTraceStep(
            query_name=req.target.rstrip("."), query_type=qtype,
            status=code, ttl=ttl, answer_summary=summary)]
        msg = summary if code == ERROR_OK else summary
        if code == ERROR_OK:
            msg = f"解析成功，共 {len(answers)} 条 {qtype} 记录"

    elapsed_ms = (time.monotonic() - started) * 1000.0

    return DnsDiagResult(
        target      = req.target,
        qtype       = qtype,
        resolver    = resolver_lbl,
        success     = (code == ERROR_OK and bool(answers)),
        rcode       = rcode or ("NOERROR" if code == ERROR_OK else ""),
        elapsed_ms  = round(elapsed_ms, 1),
        cname_chain = chain,
        answers     = answers,
        trace_steps = steps,
        message     = msg,
        nameserver  = ns_snapshot,
    )


# ── Phase 3C-4: authority-trace engine ──────────────────────────────────
#
# Goal: simulate what a recursive resolver would do, but expose every
# step.  Starting at the IPv4 root hints we ask each NS for the next
# zone label down (RD=0), follow the AUTHORITY referral, and stop at
# the apex where the AA bit (or the answer itself) tells us we've
# reached the authoritative server for the queried name.
#
# Why dnspython low-level (dns.message + dns.query.udp) instead of the
# high-level Resolver: the high-level path either sends RD=1 (defeats
# the whole exercise) or, with RD=0, hands us a single answer object
# without exposing the AUTHORITY / ADDITIONAL sections we need to walk
# referrals.  Going low-level costs ~20 lines of glue but gives us
# verbatim control of the wire format AND clean per-hop timing.
#
# We do NOT honour DNSSEC RRSIG / DS / NSEC chains — that's 3C-5.

def _normalize_qname(name: str) -> str:
    """Lower-case, ensure trailing dot — canonical form for dnspython
    comparisons and hop bookkeeping.  Returns "" for None / empty so
    downstream "if qname" gates work.
    """
    if not name:
        return ""
    n = name.strip().lower()
    if not n.endswith("."):
        n += "."
    return n


def _zone_labels_top_down(qname: str) -> list:
    """For "www.example.com." return ["com.", "example.com.", "www.example.com."].

    Empty / root returns []; single-label returns [single + "."].
    Used to drive the iterative walk: we ask each successive zone
    label until we reach the apex.
    """
    n = _normalize_qname(qname).rstrip(".")
    if not n:
        return []
    parts = n.split(".")
    zones: list = []
    for i in range(len(parts)):
        zones.append(".".join(parts[len(parts) - 1 - i:]) + ".")
    return zones


def _udp_query_rd0(qname: str, qtype: str, server_ip: str,
                   timeout_s: float):
    """Send one RD=0 UDP query, return (response_or_None, rtt_ms,
    error_code, message).

    Errors map to our usual ERROR_* constants so the hop renderer can
    reuse the existing ERROR_LABELS table.  rtt_ms is -1.0 when no
    response landed (timeout / socket error) so the UI can render "—".
    """
    import dns.message
    import dns.query
    import dns.flags
    import dns.exception
    try:
        q = dns.message.make_query(qname, qtype)
        # Clear the RD bit so the server cannot transparently recurse
        # on our behalf — we WANT to see the referral, not the final
        # answer that a recursive server would have fetched.
        q.flags &= ~dns.flags.RD
    except Exception as exc:
        return None, -1.0, ERROR_INVALID_DOMAIN, f"构造查询失败：{exc}"

    t0 = time.monotonic()
    try:
        resp = dns.query.udp(q, server_ip, timeout=timeout_s)
    except dns.exception.Timeout:
        rtt = (time.monotonic() - t0) * 1000.0
        return None, rtt, ERROR_TIMEOUT, "UDP/53 查询超时"
    except OSError as exc:
        # Includes "Network is unreachable", DNS port-blocked firewalls,
        # raw socket permission issues.  All boil down to "we cannot
        # reach this resolver via UDP/53"; surface as RESOLVER_UNREACH
        # so the UI can hint at firewall / proxy issues.
        rtt = (time.monotonic() - t0) * 1000.0
        return None, rtt, ERROR_RESOLVER_UNREACH, f"网络不可达：{exc}"
    except Exception as exc:
        rtt = (time.monotonic() - t0) * 1000.0
        return None, rtt, ERROR_UNKNOWN, f"{type(exc).__name__}: {exc}"

    rtt = (time.monotonic() - t0) * 1000.0
    return resp, rtt, ERROR_OK, ""


def _udp_query_rd0_retry(qname: str, qtype: str, server_ip: str,
                          timeout_s: float, retries: int = 1):
    """Phase 3C-4 bug-fix: retry-aware wrapper around _udp_query_rd0.

    Public-internet UDP/53 is best-effort; a single dropped packet on
    an intermediate-zone NS query would silently kill the whole
    authority trace.  Retry ONLY on timeout (NXDOMAIN / SERVFAIL /
    REFUSED are deterministic — retrying just adds latency without
    changing the outcome).  Each retry uses the full per-hop budget;
    this is fine because the happy path never triggers a retry.
    """
    resp, rtt, ec, msg = _udp_query_rd0(qname, qtype, server_ip, timeout_s)
    if ec != ERROR_TIMEOUT or retries <= 0:
        return resp, rtt, ec, msg
    # One more shot — same server, fresh socket.  Total rtt reported
    # is the LAST attempt's rtt so the displayed timing reflects the
    # one that actually answered (or the second timeout's budget).
    for _ in range(retries):
        resp, rtt, ec, msg = _udp_query_rd0(qname, qtype, server_ip, timeout_s)
        if ec != ERROR_TIMEOUT:
            return resp, rtt, ec, msg
    return resp, rtt, ec, msg


def _resp_rcode_text(resp) -> str:
    """Pull rcode name from a dnspython response, "" if unavailable."""
    try:
        import dns.rcode
        return dns.rcode.to_text(resp.rcode())
    except Exception:
        return ""


def _extract_referral(resp) -> tuple:
    """Parse AUTHORITY / ADDITIONAL into (referral_ns, glue_map, glue_lines).

    referral_ns  list[str] — NS hostnames carried in AUTHORITY (dot-
                 normalised, lower-cased).
    glue_map     dict[str, list[str]] — NS hostname → list of IPv4/IPv6
                 strings from ADDITIONAL.  Lookup-friendly for "do we
                 have glue for this NS?".
    glue_lines   list[str] — "ns1.x. → 1.2.3.4" pre-formatted for the
                 UI tree's per-hop glue display.

    Empty resp → all empty; same for a response that contains no NS
    rrsets (e.g. a final authoritative answer — caller can detect that
    via the empty referral_ns).
    """
    referral_ns: list = []
    glue_map: dict = {}
    glue_lines: list = []
    if resp is None:
        return referral_ns, glue_map, glue_lines

    try:
        import dns.rdatatype
    except Exception:
        return referral_ns, glue_map, glue_lines

    try:
        for rrset in (resp.authority or []):
            if rrset.rdtype == dns.rdatatype.NS:
                for rdata in rrset:
                    name = _normalize_qname(str(rdata.target))
                    if name and name not in referral_ns:
                        referral_ns.append(name)
    except Exception:
        pass

    try:
        for rrset in (resp.additional or []):
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                host = _normalize_qname(str(rrset.name))
                ips = glue_map.setdefault(host, [])
                for rdata in rrset:
                    try:
                        ip = rdata.address
                    except Exception:
                        ip = str(rdata)
                    if ip and ip not in ips:
                        ips.append(ip)
                        glue_lines.append(
                            f"{host.rstrip('.')} → {ip}")
    except Exception:
        pass

    return referral_ns, glue_map, glue_lines


def _extract_answer_rrsets(resp, qname: str, qtype: str) -> list:
    """Pull answer rrsets matching qname/qtype (or any CNAME on qname).

    Returns the raw rrsets so callers can decide whether to harvest
    DnsAnswer or to follow a CNAME.  Lowercase + dot-normalised name
    matching — dnspython sometimes mis-cases names depending on the
    wire encoding.
    """
    out: list = []
    if resp is None:
        return out
    try:
        import dns.rdatatype
    except Exception:
        return out
    want_qname = _normalize_qname(qname)
    want_type = qtype.upper()
    cname_type = dns.rdatatype.CNAME
    target_type = dns.rdatatype.from_text(want_type)
    try:
        for rrset in (resp.answer or []):
            rrset_name = _normalize_qname(str(rrset.name))
            if rrset_name != want_qname:
                continue
            if rrset.rdtype == target_type or rrset.rdtype == cname_type:
                out.append(rrset)
    except Exception:
        pass
    return out


def _has_aa(resp) -> bool:
    """True if the response is AUTHORITATIVE (AA bit set)."""
    if resp is None:
        return False
    try:
        import dns.flags
        return bool(resp.flags & dns.flags.AA)
    except Exception:
        return False


def _format_answer_summary(answers: list) -> str:
    """3-then-+N truncation shared with the single-mode answer summary.

    Empty list → "" so the hop's primary line carries the result label.
    """
    if not answers:
        return ""
    vals = [a.value for a in answers[:3]]
    summary = ", ".join(vals)
    if len(answers) > 3:
        summary += f"…(+{len(answers) - 3})"
    return summary


def _format_referral_summary(referral_ns: list) -> str:
    """Compact one-line referral hint, first 2 NS names + count."""
    if not referral_ns:
        return ""
    cleaned = [n.rstrip(".") for n in referral_ns]
    head = ", ".join(cleaned[:2])
    if len(cleaned) > 2:
        head += f"…(+{len(cleaned) - 2})"
    return f"→ NS {head}"


def _system_resolve_ns_a(name: str, timeout_s: float) -> list:
    """Resolve an NS hostname's A records via the SYSTEM recursive
    resolver — Phase 3C-4's glue-missing fallback (decision B).

    Returns a list of IP strings (possibly empty).  Always uses the
    system default resolver: trace_auth's "iterative" promise applies
    to the QUERIED zones, not to the borrowed NS lookup, which we
    explicitly flag in hop.message so the operator knows we briefly
    diverged from the pure walk.

    AAAA is intentionally NOT requested here — v1 walks the IPv4 root
    chain, mixing v6 NS IPs into the next-hop selection would be a
    surprise.  3C-5 / dual-stack scope can add AAAA.
    """
    try:
        import dns.resolver
    except Exception:
        return []
    try:
        r = dns.resolver.Resolver()
        r.timeout  = timeout_s
        r.lifetime = timeout_s
        ans = r.resolve(name, "A", raise_on_no_answer=False)
        rrset = getattr(ans, "rrset", None)
        if rrset is None:
            return []
        ips: list = []
        for rdata in rrset:
            try:
                ip = rdata.address
            except Exception:
                continue
            if ip and ip not in ips:
                ips.append(ip)
        return ips
    except Exception:
        return []


def _pick_root_servers() -> list:
    """Return the ordered list of root (name, ip) candidates the
    walker will try for hop 0.  Centralised so unit tests can patch.
    """
    return list(_ROOT_IPV4_HINTS[:_ROOT_TRY_LIMIT])


def _build_final_answers_from_rrsets(qname: str, qtype: str,
                                     rrsets: list) -> list:
    """Materialise the final hop's rrsets into DnsAnswer objects.

    Reuses _extract_answers for per-qtype shaping.  Walks all matching
    rrsets in order — usually 1 rrset per qtype + optional CNAME, so
    callers see CNAMEs first then the (rare) extra type answers.
    """
    out: list = []
    if not rrsets:
        return out
    for rrset in rrsets:
        try:
            import dns.rdatatype
            rrset_qt = dns.rdatatype.to_text(rrset.rdtype).upper()
        except Exception:
            rrset_qt = qtype.upper()
        out.extend(_extract_answers(qname.rstrip("."), rrset_qt, rrset))
    return out


def _cname_target_from_rrsets(rrsets: list) -> str:
    """Pull the CNAME target out of the first CNAME rrset, or "" when
    none of the supplied rrsets carry one.  Lower-cased + dot-stripped
    so the caller can feed it straight back into _zone_labels_top_down.
    """
    try:
        import dns.rdatatype
    except Exception:
        return ""
    for rrset in rrsets or []:
        if rrset.rdtype == dns.rdatatype.CNAME:
            try:
                for rdata in rrset:
                    tgt = str(rdata.target).rstrip(".").lower()
                    if tgt:
                        return tgt
            except Exception:
                continue
    return ""


def run_dns_auth_trace(
        req: DnsDiagRequest,
        cancel_check: Optional[Callable[[], bool]] = None,
) -> DnsAuthResult:
    """Phase 3C-4 — synchronous authority-trace walk.

    cancel_check: optional zero-arg predicate.  Called between every
    hop AND after the glue-borrow fallback; when it returns True we
    return a partial DnsAuthResult with success=False and rcode=
    ERROR_CANCELLED.  The async wrapper (run_dns_diag_async) treats
    that as "discard, do not persist" by substituting the standard
    cancelled DnsDiagResult sentinel — see _build_cancelled there.

    Algorithm:
      1) Validate / clamp request.
      2) Start at IPv4 root.  For each zone label top-down (starting
         from TLD), send NS query to the current zone-NS list.
         Record one DnsAuthHop per send.
      3) On AUTHORITY referral: harvest NS list + glue from ADDITIONAL,
         pick first usable IP, advance to next zone.  If no glue,
         borrow ONE system-recursive lookup of the NS hostname per
         missing-NS event (decision B in the agreed plan); flag the
         hop's message accordingly.
      4) When the zone walk has consumed every label of the target
         name, query the final qtype at the current NS.  Detect:
           - authoritative answer of qtype → success.
           - CNAME (and qtype ∈ A/AAAA) → record CNAME hop, then
             re-iterate from root for the CNAME target's zone, then
             query qtype there.  At most ONE such follow per request
             (decision A); subsequent CNAMEs are reported as-is.
           - Other rcodes → fail with rcode label.
      5) Global _MAX_AUTH_HOPS cap: any hop append that would push
         past the cap stops the walk with ERROR_AUTH_MAX_HOPS.

    Returns a DnsAuthResult with whatever hops were collected up to
    the stopping condition (success OR first hard failure).  message
    is always non-empty so UIs can render the conclusion box
    unconditionally.
    """
    # ── Validation + clamps ─────────────────────────────────────────
    err = validate_dns_request(req)
    if err:
        return DnsAuthResult(
            target=req.target, qtype=req.qtype, hops=[],
            final_answers=[], success=False, rcode="",
            elapsed_ms=0.0, message=err)

    target = _normalize_qname(req.target)
    qtype  = (req.qtype or "A").upper()
    timeout_s = max(_MIN_AUTH_HOP_TIMEOUT_S, float(req.timeout_s or 2.0))
    max_hops  = max(4, min(_MAX_AUTH_HOPS,
                            int(getattr(req, "auth_max_hops",
                                        _MAX_AUTH_HOPS))))

    started = time.monotonic()
    hops: list = []
    cname_chain: list = []
    final_answers: list = []
    success = False
    final_rcode = ""
    final_msg = ""

    def _cancelled() -> bool:
        try:
            return bool(cancel_check and cancel_check())
        except Exception:
            return False

    def _make_cancelled_result(elapsed_started: float) -> DnsAuthResult:
        ems = (time.monotonic() - elapsed_started) * 1000.0
        return DnsAuthResult(
            target=req.target, qtype=qtype, hops=list(hops),
            final_answers=list(final_answers), success=False,
            rcode=ERROR_CANCELLED, elapsed_ms=round(ems, 1),
            message=ERROR_LABELS[ERROR_CANCELLED],
            cname_chain=list(cname_chain))

    def _push_hop(h: DnsAuthHop) -> bool:
        """Append a hop; return False if we hit the global cap (caller
        should stop and surface ERROR_AUTH_MAX_HOPS).  Cap check is
        BEFORE the append so we never store the +1 hop that triggered
        the cap — the UI shows the last actually-attempted hop."""
        if len(hops) >= max_hops:
            return False
        hops.append(h)
        return True

    def _walk_from_root(walk_target: str,
                        terminal_qtype: str) -> tuple:
        """Inner walker — reused for the main target AND the optional
        CNAME-follow second pass.  Returns
        (final_answers, final_rcode, final_msg, ok, stop)
        where `stop` is True when we hit the hop cap (caller should
        not attempt further work).
        """
        walk_target = _normalize_qname(walk_target)
        target_zones = _zone_labels_top_down(walk_target)
        if not target_zones:
            return ([], "", "目标域名为空", False, False)

        # Hop 0 — root.  Try ROOT_TRY_LIMIT candidates sequentially
        # until one answers; record each attempt as its own hop so the
        # operator sees the fallback decisions.
        current_servers: list = []
        current_zone = "."
        root_resp = None
        for root_name, root_ip in _pick_root_servers():
            if _cancelled():
                return ([], "", "", False, False)
            resp, rtt, ec, msg = _udp_query_rd0_retry(
                target_zones[0], "NS", root_ip, timeout_s)
            if ec == ERROR_OK and resp is not None:
                ref_ns, glue_map, glue_lines = _extract_referral(resp)
                # If the response carries NS in ANSWER but not in
                # AUTHORITY, treat it as an effective referral.  This
                # happens when (a) the queried zone is itself in
                # bailiwick (root being asked about "com." literally
                # is the authoritative answer for "com.'s NS"); (b)
                # the network upstream of us is a transparent
                # recursive proxy that absorbed the iterative answer
                # and returned the final NS set itself.  Either way
                # the NS list is usable for advancing the walk.
                # Surface case (b) in hop.message so an operator
                # diagnosing a "weird trace" sees the hint.
                ans_rrsets = _extract_answer_rrsets(
                    resp, target_zones[0], "NS")
                hijacked_hint = ""
                if not ref_ns and ans_rrsets:
                    try:
                        import dns.rdatatype as _rdt
                        for rrset in ans_rrsets:
                            if rrset.rdtype == _rdt.NS:
                                for rdata in rrset:
                                    n = _normalize_qname(str(rdata.target))
                                    if n and n not in ref_ns:
                                        ref_ns.append(n)
                    except Exception:
                        pass
                    # RA bit set on a root response is a strong tell
                    # for a hijacking recursive proxy (real root
                    # servers never advertise RA).
                    try:
                        import dns.flags as _fl
                        if resp.flags & _fl.RA:
                            hijacked_hint = (
                                "上游似有 DNS 拦截：根响应含 ANSWER+RA，"
                                "已按 ANSWER 中的 NS 继续追踪")
                    except Exception:
                        pass
                summary = _format_referral_summary(ref_ns) or "→ (无 referral)"
                ok = bool(ref_ns)
                hop = DnsAuthHop(
                    hop_index=len(hops) + 1,
                    zone=current_zone,
                    qname=target_zones[0],
                    qtype="NS",
                    server_host=root_name,
                    server_ip=root_ip,
                    rcode=_resp_rcode_text(resp) or "NOERROR",
                    rtt_ms=round(rtt, 1),
                    success=ok or (not ref_ns and _has_aa(resp)),
                    answer_summary=summary,
                    referral_ns=list(ref_ns),
                    glue=list(glue_lines),
                    message=hijacked_hint,
                )
                if not _push_hop(hop):
                    return ([], "", "", False, True)
                root_resp = resp
                # Resolve next-hop servers from this root response.
                current_servers = _pick_next_servers_from_referral(
                    ref_ns, glue_map, hop, timeout_s)
                if not current_servers:
                    return ([], hop.rcode, "无法从 root referral 提取下一跳 IP",
                            False, False)
                # Advance current_zone to the TLD level so the next
                # hop's label reflects whose NS we're now talking to.
                # Without this, hop 2 would still show zone="." even
                # though we're at the gtld NS asking about SLDs.
                current_zone = target_zones[0]
                break
            else:
                hop = DnsAuthHop(
                    hop_index=len(hops) + 1,
                    zone=current_zone,
                    qname=target_zones[0],
                    qtype="NS",
                    server_host=root_name,
                    server_ip=root_ip,
                    rcode="",
                    rtt_ms=round(rtt if rtt >= 0 else -1, 1),
                    success=False,
                    answer_summary=msg or "查询失败",
                    error_code=ec or ERROR_UNKNOWN,
                    message=(msg or "root 查询失败，自动尝试下一个根服务器"),
                )
                if not _push_hop(hop):
                    return ([], "", "", False, True)
        if root_resp is None:
            return ([], "",
                    "所有根服务器均无响应（请检查 UDP/53 出网）",
                    False, False)

        # ── Iterate down the zone chain ─────────────────────────────
        # Start at index 1 because index 0 was answered by root.  Each
        # iteration asks the CURRENT zone's NS for the NEXT label down.
        # When current_zone covers the entire target, we break out and
        # run the FINAL hop (qtype query).
        for zi in range(1, len(target_zones)):
            if _cancelled():
                return ([], "", "", False, False)
            next_zone = target_zones[zi]
            # Try the picked NS list in order until one answers.
            resp = None
            chosen_host = ""
            chosen_ip = ""
            rtt = -1.0
            ec = ERROR_UNKNOWN
            err_msg = "无可用 NS"
            for (host, ip) in current_servers:
                if _cancelled():
                    return ([], "", "", False, False)
                resp, rtt, ec, err_msg = _udp_query_rd0_retry(
                    next_zone, "NS", ip, timeout_s)
                chosen_host, chosen_ip = host, ip
                if ec == ERROR_OK and resp is not None:
                    break
            if ec != ERROR_OK or resp is None:
                hop = DnsAuthHop(
                    hop_index=len(hops) + 1,
                    zone=current_zone,
                    qname=next_zone,
                    qtype="NS",
                    server_host=chosen_host,
                    server_ip=chosen_ip,
                    rcode="",
                    rtt_ms=round(rtt if rtt >= 0 else -1, 1),
                    success=False,
                    answer_summary=err_msg or "查询失败",
                    error_code=ec or ERROR_UNKNOWN,
                    message=err_msg or "无可用 NS",
                )
                _push_hop(hop)
                return ([], "", err_msg or "权威追踪在中间跳失败",
                        False, False)

            rcode = _resp_rcode_text(resp) or "NOERROR"
            if rcode == "NXDOMAIN":
                hop = DnsAuthHop(
                    hop_index=len(hops) + 1,
                    zone=current_zone,
                    qname=next_zone,
                    qtype="NS",
                    server_host=chosen_host,
                    server_ip=chosen_ip,
                    rcode=rcode,
                    rtt_ms=round(rtt, 1),
                    success=False,
                    answer_summary="域名不存在",
                    error_code=ERROR_NXDOMAIN,
                    message=f"{next_zone.rstrip('.')} 不存在",
                )
                _push_hop(hop)
                return ([], rcode, f"{next_zone.rstrip('.')} 不存在",
                        False, False)
            if rcode == "SERVFAIL":
                hop = DnsAuthHop(
                    hop_index=len(hops) + 1,
                    zone=current_zone,
                    qname=next_zone,
                    qtype="NS",
                    server_host=chosen_host,
                    server_ip=chosen_ip,
                    rcode=rcode,
                    rtt_ms=round(rtt, 1),
                    success=False,
                    answer_summary="解析器 SERVFAIL",
                    error_code=ERROR_SERVFAIL,
                    message=f"{chosen_host or chosen_ip} 返回 SERVFAIL",
                )
                _push_hop(hop)
                return ([], rcode, "权威链中出现 SERVFAIL",
                        False, False)

            ref_ns, glue_map, glue_lines = _extract_referral(resp)
            ans_rrsets = _extract_answer_rrsets(resp, next_zone, "NS")

            # If the authoritative NS returns the NS records directly
            # (rare but valid for the zone apex query), treat that as
            # the referral too — extract NS names from the ANSWER.
            if not ref_ns and ans_rrsets:
                try:
                    import dns.rdatatype
                    for rrset in ans_rrsets:
                        if rrset.rdtype == dns.rdatatype.NS:
                            for rdata in rrset:
                                n = _normalize_qname(str(rdata.target))
                                if n and n not in ref_ns:
                                    ref_ns.append(n)
                except Exception:
                    pass

            # Phase 3C-4 bug-fix (apex fallthrough): when the NS query
            # for `next_zone` returns NOERROR with no NS records, the
            # current zone IS the authoritative apex and `next_zone`
            # is an in-zone name (e.g. `www.baidu.com` under the
            # `baidu.com` zone, where `www` is just an A record, not
            # a delegation point).  Don't fail — treat this hop as a
            # success-with-pivot, leave current_servers/current_zone
            # alone, and break out so the final-qtype hop fires
            # against the apex NS (where the actual answer lives).
            #
            # Detection prefers the AA flag (definitive: server is
            # authoritative for the queried name) and falls back to
            # plain NOERROR — some implementations omit AA on
            # NO_ANSWER replies, but absence of NXDOMAIN/SERVFAIL plus
            # absence of any NS rrsets is a strong-enough signal.
            apex_pivot = (not ref_ns) and rcode == "NOERROR"
            apex_aa = apex_pivot and _has_aa(resp)
            hop_success = bool(ref_ns) or apex_pivot
            if apex_pivot:
                pivot_note = ("已到权威 zone（AA 置位）" if apex_aa
                              else "已到权威 zone")
                summary = (f"{pivot_note}，跳过下探，直接查 "
                           f"{terminal_qtype}")
                hop_msg = (f"{next_zone.rstrip('.')} 在 "
                           f"{current_zone.rstrip('.') or '.'} zone 内，"
                           f"无需进一步 referral")
            else:
                summary = (_format_referral_summary(ref_ns)
                           or "(无 referral，疑似已到权威)")
                hop_msg = ""
            hop = DnsAuthHop(
                hop_index=len(hops) + 1,
                zone=current_zone,
                qname=next_zone,
                qtype="NS",
                server_host=chosen_host,
                server_ip=chosen_ip,
                rcode=rcode,
                rtt_ms=round(rtt, 1),
                success=hop_success,
                answer_summary=summary,
                referral_ns=list(ref_ns),
                glue=list(glue_lines),
                message=hop_msg,
            )
            if not _push_hop(hop):
                return ([], "", "", False, True)

            if apex_pivot:
                # Stop descending — current_servers already point at
                # the authoritative NS for walk_target.  Final-qtype
                # hop below runs unchanged.
                break

            if not ref_ns:
                # Non-NOERROR (REFUSED / NOTAUTH / FORMERR …) with no
                # NS records.  Genuine "we can't go any further".
                return ([], rcode,
                        f"无法继续下探：{next_zone.rstrip('.')} 未返回 NS",
                        False, False)

            current_servers = _pick_next_servers_from_referral(
                ref_ns, glue_map, hop, timeout_s)
            if not current_servers:
                # Glue borrow also failed (decision B exhausted).
                hop.error_code = ERROR_GLUE_MISSING
                hop.message = (hop.message
                               or "referral 缺少 glue 且系统解析未成功")
                hop.success = False
                return ([], rcode, "referral 无可用 NS IP",
                        False, False)
            current_zone = next_zone

        # ── Final hop: ask the apex NS for the target qtype ─────────
        if _cancelled():
            return ([], "", "", False, False)
        resp = None
        chosen_host = ""
        chosen_ip = ""
        rtt = -1.0
        ec = ERROR_UNKNOWN
        err_msg = "无可用权威 NS"
        for (host, ip) in current_servers:
            if _cancelled():
                return ([], "", "", False, False)
            resp, rtt, ec, err_msg = _udp_query_rd0_retry(
                walk_target, terminal_qtype, ip, timeout_s)
            chosen_host, chosen_ip = host, ip
            if ec == ERROR_OK and resp is not None:
                break

        if ec != ERROR_OK or resp is None:
            hop = DnsAuthHop(
                hop_index=len(hops) + 1,
                zone=current_zone,
                qname=walk_target,
                qtype=terminal_qtype,
                server_host=chosen_host,
                server_ip=chosen_ip,
                rcode="",
                rtt_ms=round(rtt if rtt >= 0 else -1, 1),
                success=False,
                answer_summary=err_msg or "查询失败",
                error_code=ec or ERROR_UNKNOWN,
                message=err_msg or "权威 NS 不响应",
            )
            _push_hop(hop)
            return ([], "", err_msg or "权威 NS 无响应",
                    False, False)

        rcode = _resp_rcode_text(resp) or "NOERROR"
        ans_rrsets = _extract_answer_rrsets(resp, walk_target, terminal_qtype)
        answers = _build_final_answers_from_rrsets(
            walk_target, terminal_qtype, ans_rrsets)
        cname_target = (_cname_target_from_rrsets(ans_rrsets)
                        if terminal_qtype in ("A", "AAAA")
                        else "")

        # If we got CNAME but no terminal qtype answer, classify as
        # "got CNAME, may need follow".  Otherwise the answers list
        # already holds the qtype rrset (possibly empty for NO_ANSWER).
        try:
            import dns.rdatatype
            tgt_dnstype = dns.rdatatype.from_text(terminal_qtype)
            has_target = any(rr.rdtype == tgt_dnstype for rr in ans_rrsets)
        except Exception:
            has_target = bool(answers)

        if has_target and answers:
            hop = DnsAuthHop(
                hop_index=len(hops) + 1,
                zone=current_zone,
                qname=walk_target,
                qtype=terminal_qtype,
                server_host=chosen_host,
                server_ip=chosen_ip,
                rcode=rcode,
                rtt_ms=round(rtt, 1),
                success=True,
                answer_summary=_format_answer_summary(answers),
                message=(f"权威 NS 返回 {len(answers)} 条 "
                         f"{terminal_qtype} 记录"
                         + ("（含 CNAME）" if cname_target else "")),
            )
            _push_hop(hop)
            return (answers, rcode,
                    f"权威追踪成功，{len(answers)} 条 "
                    f"{terminal_qtype} 记录", True, False)

        if cname_target:
            # CNAME-only answer: surface as a successful intermediate
            # hop so the tree shows the alias clearly; caller decides
            # whether to do the one-step follow.
            hop = DnsAuthHop(
                hop_index=len(hops) + 1,
                zone=current_zone,
                qname=walk_target,
                qtype=terminal_qtype,
                server_host=chosen_host,
                server_ip=chosen_ip,
                rcode=rcode,
                rtt_ms=round(rtt, 1),
                success=True,
                answer_summary=f"CNAME → {cname_target}",
                message="权威返回 CNAME（将从 root 重新追踪目标）",
            )
            _push_hop(hop)
            return ([], rcode,
                    f"权威返回 CNAME → {cname_target}",
                    False, False)

        if rcode == "NXDOMAIN":
            ec_code, label = ERROR_NXDOMAIN, "域名不存在"
        elif rcode == "SERVFAIL":
            ec_code, label = ERROR_SERVFAIL, "解析器 SERVFAIL"
        elif rcode == "REFUSED":
            ec_code, label = ERROR_REFUSED, "解析器拒绝"
        else:
            ec_code, label = ERROR_NO_ANSWER, "权威 NS 无匹配记录"
        hop = DnsAuthHop(
            hop_index=len(hops) + 1,
            zone=current_zone,
            qname=walk_target,
            qtype=terminal_qtype,
            server_host=chosen_host,
            server_ip=chosen_ip,
            rcode=rcode,
            rtt_ms=round(rtt, 1),
            success=False,
            answer_summary=label,
            error_code=ec_code,
            message=label,
        )
        _push_hop(hop)
        return ([], rcode, label, False, False)

    # ── Drive the main walk ─────────────────────────────────────────
    final_answers, final_rcode, final_msg, success, stopped = \
        _walk_from_root(target, qtype)

    if _cancelled():
        return _make_cancelled_result(started)

    if stopped:
        ems = (time.monotonic() - started) * 1000.0
        return DnsAuthResult(
            target=req.target, qtype=qtype, hops=list(hops),
            final_answers=[], success=False,
            rcode=ERROR_AUTH_MAX_HOPS,
            elapsed_ms=round(ems, 1),
            message=(f"已达跳数上限 {max_hops}，停止追踪"),
            cname_chain=list(cname_chain),
        )

    # ── Optional CNAME follow (decision A: one step) ────────────────
    if (not success) and qtype in ("A", "AAAA") and hops:
        # Pick up the last hop's answer_summary to find the CNAME we
        # just learned about.  We accept the follow only if the last
        # hop succeeded and explicitly carried "CNAME → target".
        last = hops[-1]
        if (last.success
                and last.answer_summary.startswith("CNAME → ")
                and len(hops) < max_hops):
            cname_target = last.answer_summary[len("CNAME → "):].strip()
            if cname_target:
                cname_chain = [target.rstrip("."), cname_target]
                if _cancelled():
                    return _make_cancelled_result(started)
                follow_answers, follow_rcode, follow_msg, \
                    follow_ok, follow_stopped = _walk_from_root(
                        cname_target, qtype)
                if follow_stopped:
                    ems = (time.monotonic() - started) * 1000.0
                    return DnsAuthResult(
                        target=req.target, qtype=qtype,
                        hops=list(hops), final_answers=[],
                        success=False, rcode=ERROR_AUTH_MAX_HOPS,
                        elapsed_ms=round(ems, 1),
                        message=(f"CNAME 跟随时已达跳数上限 {max_hops}，"
                                 "停止追踪"),
                        cname_chain=list(cname_chain),
                    )
                if follow_ok:
                    success = True
                    final_answers = follow_answers
                    final_rcode = follow_rcode
                    final_msg = (
                        f"CNAME → {cname_target}；权威追踪成功，"
                        f"{len(follow_answers)} 条 {qtype} 记录")
                else:
                    final_rcode = follow_rcode or ERROR_AUTH_TRACE_FAILED
                    final_msg = (
                        f"CNAME → {cname_target}；跟随仍失败："
                        f"{follow_msg or '未取得目标记录'}")

    if _cancelled():
        return _make_cancelled_result(started)

    ems = (time.monotonic() - started) * 1000.0
    if not final_msg:
        final_msg = ("权威追踪成功" if success
                     else "权威追踪失败")

    return DnsAuthResult(
        target=req.target, qtype=qtype, hops=list(hops),
        final_answers=list(final_answers),
        success=bool(success),
        rcode=final_rcode or (
            "NOERROR" if success else ERROR_AUTH_TRACE_FAILED),
        elapsed_ms=round(ems, 1),
        message=final_msg,
        cname_chain=list(cname_chain),
    )


def _pick_next_servers_from_referral(
        referral_ns: list, glue_map: dict,
        hop: DnsAuthHop, timeout_s: float) -> list:
    """Translate a referral_ns + glue map into an ordered (host, ip)
    list usable for the next hop.

    Strategy:
      1) For every NS name in referral_ns, take its glue IPs (in glue
         insertion order).  Glue is the cheap path — no extra round-
         trips required.
      2) If after walking all NS names we have ZERO IPs, fall back to
         decision B: borrow the SYSTEM recursive resolver to look up
         the first NS hostname's A record.  Annotate the hop so the
         operator sees that the walk briefly diverged from "pure
         iterative".  Budget is _AUTH_GLUE_BORROW_BUDGET; we only
         borrow once per missing-glue event.
      3) If we still have no IPs, return [] — caller fails the hop
         with ERROR_GLUE_MISSING.
    """
    out: list = []
    for name in referral_ns:
        ips = glue_map.get(name) or []
        for ip in ips:
            entry = (name.rstrip("."), ip)
            if entry not in out:
                out.append(entry)
    if out:
        return out

    # No in-bailiwick glue — decision B borrow.
    borrows_left = _AUTH_GLUE_BORROW_BUDGET
    for name in referral_ns:
        if borrows_left <= 0:
            break
        borrows_left -= 1
        ips = _system_resolve_ns_a(name.rstrip("."), timeout_s)
        for ip in ips:
            entry = (name.rstrip("."), ip)
            if entry not in out:
                out.append(entry)
        if out:
            # Annotate the hop so the tree view can show "glue 缺失 →
            # 借助系统解析获得 X" instead of the operator wondering why
            # the next hop ip suddenly comes from nowhere.
            borrowed = ", ".join(ip for _, ip in out)
            hop.message = (hop.message + ("；" if hop.message else "")
                           + f"glue 缺失 → 借系统解析得 {borrowed}")
            break

    return out


# ── Phase 3C-5: DNSSEC validation engine ────────────────────────────────
#
# Design contract (in order of importance):
#   1.  TRUST ANCHOR.  The validator NEVER trusts the resolver's AD bit
#       and NEVER fetches a fresh trust anchor at run time.  The only
#       thing it inherently trusts is `_ROOT_KSK_2017_DNSKEY` baked
#       into this source file.  Compromising that constant compromises
#       the validator — there is no other privileged input.
#   2.  TRANSPORT-ONLY RESOLVER.  The configured resolver is used purely
#       to fetch DNSKEY / DS / target rrsets WITH the EDNS DO bit and
#       the CD bit set.  CD=1 asks the resolver to deliver bogus data
#       too — without it a misbehaving validator-resolver would refuse
#       to forward signature-failing rrsets and we'd see SERVFAIL where
#       we actually want to see the BOGUS verdict.
#   3.  FOUR-STATE VERDICT.  status is one of secure / insecure / bogus
#       / indeterminate (Q2 confirmed by user).  CN domain reality means
#       INSECURE is the common case; the UI surfaces it in grey, not
#       red.  BOGUS is the actual incident signal; INDETERMINATE is the
#       "we couldn't tell" bucket (network / unsupported case).
#   4.  CHAIN TRANSPARENCY.  Every DnsSecLink in result.chain is
#       rendered.  Even on early INSECURE we still emit the partially-
#       walked chain so the operator sees WHERE the trust collapsed —
#       common operator question on a CN domain is "未签名是在 com.
#       还是在 example.com.?", and the chain answers that directly.
#
# The validator deliberately keeps imports of dns.dnssec / cryptography
# inside the function body — same lazy-import discipline as the rest of
# the file, so a missing cryptography wheel only breaks DNSSEC mode and
# not the whole diagnostic window.


# Phase 3C-5: EDNS payload size for DNSSEC queries.  DNS Flag Day 2020
# recommends 1232 as the safe maximum that survives IPv6 PMTU + tunnel
# overhead without UDP fragmentation.  dnspython will TC-fallback to
# TCP automatically when a DNSKEY rrset exceeds this (root + several
# TLDs do, with ~2 KB DNSKEY responses).
_DNSSEC_EDNS_PAYLOAD = 1232

# Lower-bound clamp on operator-supplied timeout — DNSSEC needs a
# DNSKEY/DS pair per zone plus the leaf query, so an aggressive
# 0.2 s budget would burn the whole slot on the root DNSKEY alone.
# 0.8 s gives the resolver room for the typical TCP fallback path on
# DNSKEY without ballooning the worst-case run.
_DNSSEC_MIN_TIMEOUT_S = 0.8


class _DnsSecAbort(Exception):
    """Raised internally when a DNSSEC sub-fetch cannot complete and
    the caller should turn the run into INDETERMINATE.

    Carries the operator-facing Chinese message verbatim.  We use a
    custom exception (rather than a tuple return) because the chain
    walk has 6+ branch points where any of them could short-circuit
    and threading "did we abort?" through tuple returns gets ugly fast.
    """
    pass


def _root_anchor_rrset():
    """Build an rrset containing JUST the embedded KSK-2017 DNSKEY.

    This is the SOLE root of trust.  When we validate the root
    DNSKEY rrset's RRSIG we use ONLY this single-record rrset as the
    key source — including the full fetched rrset would let an
    attacker who injected a rogue DNSKEY + RRSIG pair claim success,
    because dns.dnssec.validate accepts any RRSIG whose key tag
    points to any DNSKEY in the keyring.

    Cached on the function object after first call so repeated
    DNSSEC runs don't re-parse the base64 every time.
    """
    cached = getattr(_root_anchor_rrset, "_cache", None)
    if cached is not None:
        return cached
    import dns.rrset
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.name
    rd = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.DNSKEY,
        _ROOT_KSK_2017_DNSKEY_RDATA)
    # ttl=0 is fine — the anchor RR is never sent on the wire, only
    # used as the keys-dict source for dns.dnssec.validate().
    rrset = dns.rrset.from_rdata(dns.name.from_text("."), 0, rd)
    _root_anchor_rrset._cache = rrset
    return rrset


def _make_dnssec_resolver(timeout_s: float,
                           nameserver: Optional[str] = None):
    """Build a dnspython Resolver tuned for DNSSEC validation.

    Two non-default knobs vs _make_resolver:
      • use_edns(0, dns.flags.DO, _DNSSEC_EDNS_PAYLOAD) — required so
        the resolver actually includes RRSIG records in its responses.
        Without DO=1 we'd get bare rrsets and have nothing to validate.
      • r.flags |= dns.flags.CD — checking-disabled.  Tells the
        resolver "don't filter on your own validation outcome, give
        me everything including bogus data".  We're doing our own
        check; we WANT to see the failing data.

    The dnspython Resolver.flags attribute is settable from 2.0+ —
    we set it via attribute rather than via _flags so the public API
    is the one used.  If a future dnspython removes the attribute the
    AttributeError will surface immediately in tests and tell us to
    switch to a low-level dns.message.make_query path.
    """
    import dns.resolver
    import dns.flags
    r = dns.resolver.Resolver()
    r.timeout  = timeout_s
    r.lifetime = timeout_s
    r.use_edns(0, dns.flags.DO, _DNSSEC_EDNS_PAYLOAD)
    # RD (recursion-desired) + CD (checking-disabled).  No AD/RA on
    # the request side — those are response bits.
    try:
        r.flags = dns.flags.RD | dns.flags.CD
    except AttributeError:
        # Very old dnspython — fall back to whatever default it has.
        # DO=1 still ensures RRSIGs come through, just without CD=1
        # we may see SERVFAIL on a validator-resolver's BOGUS path.
        pass
    ns = (nameserver or "").strip()
    if ns:
        r.nameservers = [ns]
    return r


def _dnssec_lookup(resolver, name: str, qtype: str):
    """Fetch (response, error_code, message) via the configured resolver.

    Returns the raw response Message rather than dnspython's Answer
    wrapper so callers can pick rrsets out of the .answer section
    even on NO_ANSWER / NXDOMAIN — DNSSEC validation needs the FULL
    response, not just the success-path rrset.

    Mapping:
      NOERROR + non-empty answer      → (resp, ERROR_OK, "")
      NOERROR + empty answer (NoAnswer)→ (resp, ERROR_NO_ANSWER, msg)
      NXDOMAIN                         → (None_or_resp, ERROR_NXDOMAIN, msg)
      timeout / unreachable / unknown  → (None,         ERROR_*,        msg)
    """
    import dns.resolver
    import dns.exception
    import dns.rdatatype
    try:
        ans = resolver.resolve(name, qtype, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN as exc:
        # dnspython 2.4+ NXDOMAIN exposes .response() when available;
        # we fall back gracefully if the attribute is absent.
        resp = None
        try:
            resp = exc.response(dns.name.from_text(name))
        except Exception:
            pass
        return resp, ERROR_NXDOMAIN, f"{name} 不存在"
    except dns.resolver.NoNameservers as exc:
        m = str(exc).lower()
        if "servfail" in m:
            return None, ERROR_SERVFAIL, f"{name} {qtype}: 解析器返回 SERVFAIL"
        if "refused" in m:
            return None, ERROR_REFUSED, f"{name} {qtype}: 解析器拒绝查询"
        return None, ERROR_RESOLVER_UNREACH, f"{name} {qtype}: 所有解析器均无应答"
    except dns.exception.Timeout:
        return None, ERROR_TIMEOUT, f"{name} {qtype}: 查询超时"
    except Exception as exc:
        return None, ERROR_UNKNOWN, f"{name} {qtype}: {type(exc).__name__}: {exc}"

    resp = getattr(ans, "response", None)
    if resp is None:
        return None, ERROR_UNKNOWN, f"{name} {qtype}: 无响应消息"

    try:
        target_type = dns.rdatatype.from_text(qtype.upper())
    except Exception:
        target_type = None

    has_answer = False
    if target_type is not None:
        for rrset in (resp.answer or []):
            if rrset.rdtype == target_type:
                has_answer = True
                break
            if rrset.rdtype == dns.rdatatype.CNAME:
                # CNAME in answer means the resolver may have followed
                # the alias; still counts as "we got something useful".
                has_answer = True
                break
    if not has_answer:
        return resp, ERROR_NO_ANSWER, f"{name} 无 {qtype} 记录"
    return resp, ERROR_OK, ""


def _find_rrset_and_rrsig(resp, name: str, qtype: str):
    """Pull (data_rrset, rrsig_rrset) for the (name, qtype) pair out of
    resp.answer.  Both may be None.

    Name comparison is dot-stripped + case-insensitive — dnspython
    sometimes returns the question casing back as-is, sometimes
    canonicalises; we normalise so a mixed-case operator input still
    matches.
    """
    if resp is None or not getattr(resp, "answer", None):
        return None, None
    import dns.rdatatype
    target_name = name.rstrip(".").lower()
    try:
        target_type = dns.rdatatype.from_text(qtype.upper())
    except Exception:
        return None, None
    data_rrset = None
    rrsig_rrset = None
    for rrset in resp.answer:
        rrset_name = str(rrset.name).rstrip(".").lower()
        if rrset_name != target_name:
            continue
        if rrset.rdtype == target_type:
            data_rrset = rrset
        elif (rrset.rdtype == dns.rdatatype.RRSIG
              and getattr(rrset, "covers", 0) == target_type):
            rrsig_rrset = rrset
    return data_rrset, rrsig_rrset


def _dnssec_has_ns_records(resp, zone: str) -> bool:
    """True when `resp` carries NS rrsets for `zone` in ANSWER or AUTHORITY."""
    if resp is None:
        return False
    import dns.rdatatype
    zone_norm = zone.rstrip(".").lower()
    try:
        sections = list(resp.answer or []) + list(resp.authority or [])
        for rrset in sections:
            if rrset.rdtype != dns.rdatatype.NS:
                continue
            rrset_name = str(rrset.name).rstrip(".").lower()
            if rrset_name == zone_norm and len(rrset) > 0:
                return True
    except Exception:
        pass
    return False


def _dnssec_is_delegation_point(resolver, zone: str) -> bool:
    """True when `zone` is a child delegation (NS exists at this name).

    NOERROR + no NS means the name is an in-zone record (e.g. ``www``
    under ``google.com``), not a zone cut — same apex-pivot semantics
    as trace_auth (see run_authority_trace hop ~2129-2144).
    """
    ns_resp, ns_ec, _ = _dnssec_lookup(resolver, zone, "NS")
    if ns_ec == ERROR_NXDOMAIN:
        return False
    return _dnssec_has_ns_records(ns_resp, zone)


def _zone_labels_root_to_leaf(qname: str) -> list:
    """For "www.example.com" return [".", "com.", "example.com.", "www.example.com."].

    Root is always position 0 so the chain walk starts there
    unconditionally.  Empty input returns just ["."].  Used as the
    iteration spine for the DS/DNSKEY chain walk.
    """
    n = (qname or "").strip().rstrip(".").lower()
    out: list = ["."]
    if not n:
        return out
    parts = n.split(".")
    for i in range(len(parts)):
        out.append(".".join(parts[len(parts) - 1 - i:]) + ".")
    return out


def _follow_cname_for_dnssec(resolver, target: str, qtype: str
                              ) -> tuple:
    """Phase 3C-5 — chase CNAMEs to find the canonical leaf name.

    Decision Q3 (user-confirmed): we reuse _MAX_CNAME_DEPTH=10 from
    the single-mode walker but DO NOT validate intermediate CNAME
    rrsets individually.  The chain is only used to identify which
    leaf zone's signing key should validate the final qtype rrset.

    Mechanism: issue a single resolver.resolve(qtype) which the
    resolver will recurse through the CNAME chain on our behalf; we
    then walk the resulting answer section ourselves to extract the
    canonical name.  This is cheaper than re-querying each step
    (one round-trip total instead of N).

    Returns (canonical_name, cname_chain, error_code, message).
      canonical_name      lowercased, no trailing dot.
      cname_chain         e.g. ["www.example.com", "edge.cdn.com"]
                          or just [target] when no chasing happened.
      error_code/message  ERROR_OK on success, otherwise an
                          ERROR_CNAME_* / ERROR_NXDOMAIN / … code.

    For non-A/AAAA qtypes (or when target already resolves directly),
    canonical_name == target and cname_chain == [target].
    """
    target_norm = target.rstrip(".").lower()
    if qtype.upper() not in ("A", "AAAA"):
        return target_norm, [target_norm], ERROR_OK, ""

    resp, ec, msg = _dnssec_lookup(resolver, target_norm, qtype)
    # NO_ANSWER is fine here — the name exists, just lacks records of
    # this type.  We still record it as "no chain followed" so the
    # subsequent validation can build the chain for target itself
    # (and discover the actual leaf state).
    if ec in (ERROR_TIMEOUT, ERROR_RESOLVER_UNREACH, ERROR_SERVFAIL,
              ERROR_REFUSED, ERROR_UNKNOWN, ERROR_NXDOMAIN):
        return target_norm, [target_norm], ec, msg
    if resp is None:
        return target_norm, [target_norm], ec or ERROR_UNKNOWN, msg

    import dns.rdatatype
    # Build a (name → CNAME-target) map walking the answer section.
    cname_by_name: dict = {}
    for rrset in (resp.answer or []):
        if rrset.rdtype != dns.rdatatype.CNAME:
            continue
        nm = str(rrset.name).rstrip(".").lower()
        try:
            tgt = str(rrset[0].target).rstrip(".").lower()
        except Exception:
            continue
        if nm and tgt:
            cname_by_name[nm] = tgt

    chain = [target_norm]
    seen = {target_norm}
    current = target_norm
    depth = 0
    while current in cname_by_name and depth < _MAX_CNAME_DEPTH:
        nxt = cname_by_name[current]
        if nxt in seen:
            return current, chain, ERROR_CNAME_LOOP, f"CNAME 链回环：{nxt}"
        chain.append(nxt)
        seen.add(nxt)
        current = nxt
        depth += 1
    if current in cname_by_name and depth >= _MAX_CNAME_DEPTH:
        return current, chain, ERROR_CNAME_TOO_DEEP, (
            f"CNAME 链超过 {_MAX_CNAME_DEPTH} 层，疑似配置错误")
    return current, chain, ERROR_OK, ""


def _algorithm_label_from_rrset(dnskey_rrset) -> str:
    """Best-effort human label for the algorithms present in a DNSKEY
    rrset.  Returns e.g. "RSA/SHA-256" for the typical case.
    """
    if dnskey_rrset is None:
        return ""
    names = {
        5:  "RSA/SHA-1",
        7:  "RSASHA1-NSEC3",
        8:  "RSA/SHA-256",
        10: "RSA/SHA-512",
        13: "ECDSA P-256/SHA-256",
        14: "ECDSA P-384/SHA-384",
        15: "Ed25519",
        16: "Ed448",
    }
    algs = set()
    try:
        for rd in dnskey_rrset:
            algs.add(getattr(rd, "algorithm", None))
    except Exception:
        pass
    pretty = [names.get(a, f"alg {a}") for a in algs if a is not None]
    return ", ".join(sorted(set(pretty))) if pretty else ""


def _verify_root_dnskey(resolver, link: DnsSecLink) -> tuple:
    """Fetch + verify the root DNSKEY rrset against the embedded anchor.

    Returns (trusted_dnskey_rrset, status_hint, message).
      trusted_dnskey_rrset – when not None, callers may use it as the
                             trust source for validating com./TLD DS.
      status_hint          – "ok" | "bogus" | "indeterminate".
      message              – Chinese explainer, populated on every
                             non-ok branch; empty on success.

    Side effect: mutates `link` in place — sets has_dnskey / dnskey_ok
    / algorithm / note so the caller can append it to the chain list
    without a second pass.
    """
    import dns.dnssec
    import dns.name
    import dns.rdatatype

    link.has_ds = False   # root has no parent → no DS by definition.
    resp, ec, msg = _dnssec_lookup(resolver, ".", "DNSKEY")
    if ec != ERROR_OK or resp is None:
        link.note = f"获取根 DNSKEY 失败：{msg}"
        return None, "indeterminate", link.note

    dnskey_rrset, rrsig_rrset = _find_rrset_and_rrsig(resp, ".", "DNSKEY")
    if dnskey_rrset is None or rrsig_rrset is None:
        link.note = "根 DNSKEY 或 RRSIG 缺失"
        return None, "bogus", link.note

    link.has_dnskey = True

    # Verify the embedded KSK is in the fetched DNSKEY set.  We compare
    # by key tag (cheap + dnspython-supported) AND by full rdata
    # equality (catches the edge case of two keys sharing a tag).
    anchor_rrset = _root_anchor_rrset()
    try:
        anchor_rdata = list(anchor_rrset)[0]
    except Exception:
        link.note = "无法解析内嵌根信任锚（请联系开发者）"
        return None, "indeterminate", link.note
    try:
        anchor_tag = dns.dnssec.key_id(anchor_rdata)
    except Exception:
        anchor_tag = _ROOT_KSK_2017_KEY_TAG

    found_anchor = False
    try:
        for rd in dnskey_rrset:
            try:
                tag = dns.dnssec.key_id(rd)
            except Exception:
                tag = None
            if tag == anchor_tag and rd == anchor_rdata:
                found_anchor = True
                break
    except Exception:
        pass

    if not found_anchor:
        link.note = (
            f"根 DNSKEY 不含内嵌信任锚（KSK key-tag={anchor_tag}）；"
            "可能是根 KSK 已轮换，需更新源码内的信任锚常量")
        return None, "bogus", link.note

    # Validate the root DNSKEY rrset's RRSIG against the SINGLE
    # anchor-only keyring (NOT the full fetched rrset — see
    # _root_anchor_rrset docstring).
    try:
        dns.dnssec.validate(
            dnskey_rrset, rrsig_rrset,
            {dns.name.from_text("."): anchor_rrset})
    except Exception as exc:
        link.note = f"根 DNSKEY RRSIG 验证失败：{exc}"
        return None, "bogus", link.note

    link.dnskey_ok = True
    link.algorithm = _algorithm_label_from_rrset(dnskey_rrset)
    link.note = "信任锚 OK"
    return dnskey_rrset, "ok", ""


def _verify_zone_link(resolver, zone: str,
                      parent_trusted_keys, link: DnsSecLink) -> tuple:
    """Fetch + verify ONE zone link (non-root) from its parent's DNSKEY.

    Returns (zone_trusted_dnskey_rrset_or_None, status_hint, message).
      status_hint ∈ {"ok", "contained", "insecure", "bogus", "indeterminate"}.

    Algorithm:
      1.  Query parent for child's DS rrset (the resolver does the
          recursion; we just need the answer + RRSIG).
      2.  If no DS rrset returned → distinguish delegation vs in-zone
          leaf: only real zone cuts (NS present) are INSECURE; a NODATA
          DS at a non-delegation suffix (e.g. ``www`` under a signed
          parent) returns ``contained`` so the walk stops with the
          parent's trusted keys and terminal RRSIG validation proceeds.
      3.  Validate DS RRSIG using parent_trusted_keys.  Cryptographic
          failure → BOGUS.
      4.  Query child's own DNSKEY rrset.
      5.  Find a DNSKEY whose hash matches one of the DS records
          (dns.dnssec.make_ds).  No match → BOGUS.
      6.  Validate DNSKEY RRSIG using a SINGLE-record keyring built
          from the matched DNSKEY.  Failure → BOGUS.
      7.  Success — return the full DNSKEY rrset as the new trusted
          key source for downstream zones.

    `link` is mutated in place with has_ds / ds_ok / has_dnskey /
    dnskey_ok / algorithm / note.
    """
    import dns.dnssec
    import dns.name
    import dns.rrset

    zone_name = dns.name.from_text(zone)

    # ── 1) DS at zone ──────────────────────────────────────────────
    ds_resp, ds_ec, ds_msg = _dnssec_lookup(resolver, zone, "DS")
    if ds_ec == ERROR_NXDOMAIN:
        link.note = f"{zone.rstrip('.')} 不存在（父 zone 返回 NXDOMAIN）"
        return None, "bogus", link.note
    if ds_ec in (ERROR_TIMEOUT, ERROR_RESOLVER_UNREACH, ERROR_UNKNOWN,
                 ERROR_SERVFAIL, ERROR_REFUSED):
        link.note = f"获取 {zone.rstrip('.')} 的 DS 失败：{ds_msg}"
        return None, "indeterminate", link.note

    ds_rrset, ds_rrsig = _find_rrset_and_rrsig(ds_resp, zone, "DS")
    if ds_rrset is None:
        link.has_ds = False
        if not _dnssec_is_delegation_point(resolver, zone):
            link.note = "叶名位于已信任 zone 内（非 delegation）"
            return None, "contained", link.note
        link.note = "无 DS（未签名）"
        return None, "insecure", link.note

    link.has_ds = True
    if ds_rrsig is None:
        link.note = f"{zone.rstrip('.')} 的 DS 缺少 RRSIG（疑似中间盒子剥离）"
        return None, "bogus", link.note

    try:
        dns.dnssec.validate(ds_rrset, ds_rrsig, parent_trusted_keys)
    except Exception as exc:
        link.note = f"{zone.rstrip('.')} 的 DS RRSIG 验证失败：{exc}"
        return None, "bogus", link.note

    # ── 2) DNSKEY at zone ──────────────────────────────────────────
    key_resp, key_ec, key_msg = _dnssec_lookup(resolver, zone, "DNSKEY")
    if key_ec in (ERROR_TIMEOUT, ERROR_RESOLVER_UNREACH, ERROR_UNKNOWN,
                  ERROR_SERVFAIL, ERROR_REFUSED):
        link.note = f"获取 {zone.rstrip('.')} 的 DNSKEY 失败：{key_msg}"
        return None, "indeterminate", link.note
    dnskey_rrset, dnskey_rrsig = _find_rrset_and_rrsig(
        key_resp, zone, "DNSKEY")
    if dnskey_rrset is None or dnskey_rrsig is None:
        link.note = (f"{zone.rstrip('.')} 已被父 zone 签名（有 DS），"
                     "但本 zone 未返回 DNSKEY/RRSIG — 签名链断裂")
        return None, "bogus", link.note
    link.has_dnskey = True

    # ── 3) DS ↔ DNSKEY hash match ──────────────────────────────────
    matched_ksk = None
    matched_digest = 0
    for ds_rd in ds_rrset:
        try:
            ds_digest_type = getattr(ds_rd, "digest_type", 0)
        except Exception:
            ds_digest_type = 0
        for key_rd in dnskey_rrset:
            try:
                computed = dns.dnssec.make_ds(
                    zone_name, key_rd, ds_digest_type)
            except Exception:
                continue
            if computed == ds_rd:
                matched_ksk = key_rd
                matched_digest = ds_digest_type
                break
        if matched_ksk is not None:
            break

    if matched_ksk is None:
        link.note = (f"{zone.rstrip('.')} 的 DNSKEY 与父 zone 的 DS "
                     "摘要均不匹配（可能 KSK 已轮换或签名被篡改）")
        return None, "bogus", link.note

    link.ds_ok = True
    link.algorithm = _DS_DIGEST_NAMES.get(
        matched_digest, f"摘要算法 {matched_digest}")

    # ── 4) DNSKEY rrset's RRSIG verified against matched KSK only ──
    matched_rrset = dns.rrset.from_rdata(
        zone_name, dnskey_rrset.ttl, matched_ksk)
    try:
        dns.dnssec.validate(
            dnskey_rrset, dnskey_rrsig,
            {zone_name: matched_rrset})
    except Exception as exc:
        # KSK matched DS but couldn't sign its own DNSKEY rrset —
        # possible RRSIG expiry or algorithm mismatch.
        link.note = (f"{zone.rstrip('.')} 的 DNSKEY RRSIG 验证失败："
                     f"{exc}")
        return None, "bogus", link.note

    link.dnskey_ok = True
    # Promote to "OK" only after both halves passed; mention the
    # algorithm so the row reads naturally even on success.
    link.note = (f"DS → DNSKEY ✓（{link.algorithm}）"
                 if link.algorithm else "DS → DNSKEY ✓")
    return dnskey_rrset, "ok", ""


def _validate_terminal_rrset(resolver, canonical: str, qtype: str,
                              trusted_keys: dict) -> tuple:
    """Final step — fetch + validate the target rrset.

    Returns
      (answers, rrsig_ok, ad_flag, status, message).
        answers      list[DnsAnswer]; populated even on BOGUS so the
                     operator can see WHICH records failed.
        rrsig_ok     True iff at least one RRSIG validated.
        ad_flag      AD bit on the resolver response (informational).
                     None when no usable response came back.
        status       "secure" / "bogus" / "indeterminate".  Never
                     "insecure" — that branch is decided upstream by
                     a missing DS, not here.
        message      Chinese-language explainer; non-empty.
    """
    import dns.dnssec
    import dns.flags

    resp, ec, msg = _dnssec_lookup(resolver, canonical, qtype)
    if ec in (ERROR_TIMEOUT, ERROR_RESOLVER_UNREACH, ERROR_UNKNOWN,
              ERROR_SERVFAIL, ERROR_REFUSED):
        return [], False, None, "indeterminate", (
            f"获取 {canonical} 的 {qtype} 记录失败：{msg}")
    if ec == ERROR_NXDOMAIN:
        # NSEC proof not implemented in v1 → indeterminate.
        return [], False, None, "indeterminate", (
            f"{canonical} 不存在；DNSSEC NSEC 证明未实现，"
            "无法判定 NXDOMAIN 是否被篡改")

    ad_flag = None
    if resp is not None:
        try:
            ad_flag = bool(resp.flags & dns.flags.AD)
        except Exception:
            ad_flag = None

    data_rrset, rrsig_rrset = _find_rrset_and_rrsig(resp, canonical, qtype)
    if data_rrset is None:
        return [], False, ad_flag, "indeterminate", (
            f"{canonical} 无 {qtype} 记录；NSEC 证明未实现，无法验签")

    answers = _extract_answers(canonical, qtype, data_rrset)
    if rrsig_rrset is None:
        # Chain says signed, but no RRSIG on the leaf rrset.
        return answers, False, ad_flag, "bogus", (
            f"{canonical} 的 {qtype} 记录缺少 RRSIG — "
            "签名链虽完整但 leaf 未签名，疑似中间盒子剥离")

    try:
        dns.dnssec.validate(data_rrset, rrsig_rrset, trusted_keys)
    except Exception as exc:
        return answers, False, ad_flag, "bogus", (
            f"{canonical} 的 {qtype} RRSIG 验证失败：{exc}")

    return answers, True, ad_flag, "secure", (
        f"DNSSEC 验证通过，{len(answers)} 条 {qtype} 记录")


def run_dnssec_validate(
        req: DnsDiagRequest,
        cancel_check: Optional[Callable[[], bool]] = None,
) -> DnsSecResult:
    """Phase 3C-5 — synchronous DNSSEC validation entry point.

    Algorithm (top level):
      0)  Validate the request; lazy-import dns.dnssec to surface a
          clean "cryptography wheel missing" error rather than a
          deferred ModuleNotFoundError later.
      1)  Build a DO+CD resolver (system default or operator IP).
      2)  Chase CNAMEs for A/AAAA → canonical leaf name.  Other
          qtypes use the target verbatim.  Save the walk into
          result.cname_chain so the UI can display it like single
          mode.
      3)  Walk zone labels root → leaf.  Verify root via embedded
          anchor; verify each subsequent zone via parent's DNSKEY
          set + DS digest match.  Missing DS at a real delegation
          cut = INSECURE; missing DS at a non-delegation suffix
          (``contained``) stops the walk with parent keys so the
          leaf rrset can still be validated.
      4)  If chain is fully trusted, validate the leaf qtype rrset.
          BOGUS on signature failure; SECURE on success.
      5)  Across all branches, populate answers when available and
          ad_flag from the final response.

    cancel_check: zero-arg predicate polled between zone verifications
    AND before each network round-trip.  When True we abandon and
    return a result with status=indeterminate + rcode=ERROR_CANCELLED-
    equivalent; the async wrapper detects rcode==ERROR_CANCELLED and
    substitutes the unified ERROR_CANCELLED DnsDiagResult sentinel so
    the UI's terminal-rendering branches stay consistent across
    single/compare/trace_auth/dnssec.
    """
    # ── 0) Validation & lazy import ─────────────────────────────────
    err = validate_dns_request(req)
    if err:
        return DnsSecResult(
            target=req.target, qtype=req.qtype,
            resolver="", nameserver=(req.nameserver or "").strip(),
            status="indeterminate",
            chain=[], answers=[], rrsig_ok=False, ad_flag=None,
            elapsed_ms=0.0, message=err)

    try:
        import dns.dnssec  # noqa: F401
        import dns.name    # noqa: F401
        import dns.rrset   # noqa: F401
        import dns.flags   # noqa: F401
        import dns.rdatatype  # noqa: F401
    except ImportError as exc:
        return DnsSecResult(
            target=req.target, qtype=req.qtype,
            resolver="", nameserver=(req.nameserver or "").strip(),
            status="indeterminate",
            chain=[], answers=[], rrsig_ok=False, ad_flag=None,
            elapsed_ms=0.0,
            message=(f"DNSSEC 验证依赖缺失：{exc}。"
                     "请确认 dnspython / cryptography 已安装。"))

    def _cancelled() -> bool:
        try:
            return bool(cancel_check and cancel_check())
        except Exception:
            return False

    ns_snapshot = (req.nameserver or "").strip()
    qtype = (req.qtype or "A").upper()
    timeout_s = max(_DNSSEC_MIN_TIMEOUT_S, float(req.timeout_s or 2.0))

    started = time.monotonic()

    def _build(status, message, chain=None, answers=None,
               rrsig_ok=False, ad_flag=None, cname_chain=None,
               resolver_lbl="", canonical=None) -> DnsSecResult:
        ems = (time.monotonic() - started) * 1000.0
        return DnsSecResult(
            target=req.target, qtype=qtype,
            resolver=resolver_lbl,
            nameserver=ns_snapshot,
            status=status,
            chain=list(chain or []),
            answers=list(answers or []),
            rrsig_ok=bool(rrsig_ok),
            ad_flag=ad_flag,
            elapsed_ms=round(ems, 1),
            message=message or "",
            cname_chain=list(cname_chain or []))

    # ── 1) Resolver factory ────────────────────────────────────────
    try:
        resolver = _make_dnssec_resolver(timeout_s,
                                         ns_snapshot or None)
        resolver_lbl = _resolver_label(resolver, ns_snapshot or None)
    except Exception as exc:
        return _build(
            "indeterminate",
            f"无法初始化 DNSSEC 解析器：{type(exc).__name__}: {exc}")

    if _cancelled():
        # Reuse the standard cancelled sentinel string so the async
        # wrapper can substitute the canonical DnsDiagResult shape.
        out = _build(
            "indeterminate",
            ERROR_LABELS.get(ERROR_CANCELLED, "已取消"),
            resolver_lbl=resolver_lbl)
        # Sentinel: callers detect this via message text + the
        # explicit rcode-like flag we embed in the result's chain
        # marker.  We piggyback on a single empty link with note ==
        # cancelled — the async layer only looks at run-level
        # cancel_check.is_set() anyway, so this is purely defensive.
        return out

    # ── 2) CNAME chase (A/AAAA only) ───────────────────────────────
    canonical, cname_chain, c_ec, c_msg = _follow_cname_for_dnssec(
        resolver, req.target, qtype)
    if c_ec == ERROR_NXDOMAIN:
        return _build(
            "indeterminate",
            f"{req.target} 不存在；DNSSEC NXDOMAIN 证明（NSEC）未实现",
            cname_chain=cname_chain, resolver_lbl=resolver_lbl)
    if c_ec in (ERROR_CNAME_LOOP, ERROR_CNAME_TOO_DEEP):
        return _build(
            "indeterminate", c_msg,
            cname_chain=cname_chain, resolver_lbl=resolver_lbl)
    if c_ec in (ERROR_TIMEOUT, ERROR_RESOLVER_UNREACH, ERROR_SERVFAIL,
                ERROR_REFUSED, ERROR_UNKNOWN):
        return _build(
            "indeterminate", c_msg or "DNSSEC 预查询失败",
            cname_chain=cname_chain, resolver_lbl=resolver_lbl)

    if _cancelled():
        return _build("indeterminate",
                      ERROR_LABELS.get(ERROR_CANCELLED, "已取消"),
                      cname_chain=cname_chain,
                      resolver_lbl=resolver_lbl)

    # ── 3) Walk zone labels root → leaf, verifying each link ───────
    zones = _zone_labels_root_to_leaf(canonical)
    chain: list = []
    trusted_keys: dict = {}
    insecure_at: Optional[str] = None
    bogus_at: Optional[str] = None
    indeterminate_at: Optional[str] = None

    import dns.name as _dnsname
    for zi, zone in enumerate(zones):
        if _cancelled():
            return _build("indeterminate",
                          ERROR_LABELS.get(ERROR_CANCELLED, "已取消"),
                          chain=chain, cname_chain=cname_chain,
                          resolver_lbl=resolver_lbl)
        link = DnsSecLink(zone=zone)
        if zi == 0:
            new_keys, hint, hmsg = _verify_root_dnskey(resolver, link)
            chain.append(link)
            if hint != "ok":
                if hint == "bogus":
                    bogus_at = zone
                else:
                    indeterminate_at = zone
                # Hard stop on root failure — without a root anchor
                # nothing downstream is verifiable.
                break
            trusted_keys[_dnsname.from_text(".")] = new_keys
            continue

        new_keys, hint, hmsg = _verify_zone_link(
            resolver, zone, trusted_keys, link)
        chain.append(link)
        if hint == "ok":
            trusted_keys[_dnsname.from_text(zone)] = new_keys
            continue
        if hint == "contained":
            # Leaf lives inside an already-trusted zone; stop the walk
            # and validate the terminal rrset with current keys.
            break
        if hint == "insecure":
            insecure_at = zone
            break
        if hint == "bogus":
            bogus_at = zone
            break
        # indeterminate
        indeterminate_at = zone
        break

    # ── 4) Verdict + leaf rrset ────────────────────────────────────
    if bogus_at is not None:
        # Don't even attempt the leaf — the chain is already broken,
        # any leaf "validation" would be against an untrusted key.
        # But we DO try to fetch the answer rrset (without validating)
        # so the operator sees what records the resolver is returning.
        leaf_resp, _, _ = _dnssec_lookup(resolver, canonical, qtype)
        ad_flag = None
        answers: list = []
        if leaf_resp is not None:
            try:
                ad_flag = bool(leaf_resp.flags & dns.flags.AD)
            except Exception:
                ad_flag = None
            leaf_rrset, _ = _find_rrset_and_rrsig(
                leaf_resp, canonical, qtype)
            if leaf_rrset is not None:
                answers = _extract_answers(canonical, qtype, leaf_rrset)
        last = chain[-1] if chain else None
        msg = (last.note if (last and last.note)
               else f"{bogus_at.rstrip('.')} DNSSEC 链验证失败")
        return _build("bogus", msg,
                      chain=chain, answers=answers, rrsig_ok=False,
                      ad_flag=ad_flag, cname_chain=cname_chain,
                      resolver_lbl=resolver_lbl)

    if indeterminate_at is not None:
        last = chain[-1] if chain else None
        msg = (last.note if (last and last.note)
               else "DNSSEC 验证未能完成（网络或配置异常）")
        return _build("indeterminate", msg,
                      chain=chain, cname_chain=cname_chain,
                      resolver_lbl=resolver_lbl)

    if insecure_at is not None:
        # Chain stopped at insecure_at.  Still fetch and display the
        # leaf rrset (without RRSIG validation) — useful for the
        # operator to see what's being served.
        leaf_resp, _, _ = _dnssec_lookup(resolver, canonical, qtype)
        ad_flag = None
        answers = []
        if leaf_resp is not None:
            try:
                ad_flag = bool(leaf_resp.flags & dns.flags.AD)
            except Exception:
                ad_flag = None
            leaf_rrset, _ = _find_rrset_and_rrsig(
                leaf_resp, canonical, qtype)
            if leaf_rrset is not None:
                answers = _extract_answers(canonical, qtype, leaf_rrset)
        msg = (f"{insecure_at.rstrip('.')} 未签署 DS（zone 未部署 DNSSEC），"
               "其下记录无法验证，但答案本身可供参考")
        return _build("insecure", msg,
                      chain=chain, answers=answers, rrsig_ok=False,
                      ad_flag=ad_flag, cname_chain=cname_chain,
                      resolver_lbl=resolver_lbl)

    if _cancelled():
        return _build("indeterminate",
                      ERROR_LABELS.get(ERROR_CANCELLED, "已取消"),
                      chain=chain, cname_chain=cname_chain,
                      resolver_lbl=resolver_lbl)

    # Chain fully trusted — validate the leaf rrset.
    answers, rrsig_ok, ad_flag, leaf_status, leaf_msg = \
        _validate_terminal_rrset(resolver, canonical, qtype, trusted_keys)
    return _build(leaf_status, leaf_msg,
                  chain=chain, answers=answers, rrsig_ok=rrsig_ok,
                  ad_flag=ad_flag, cname_chain=cname_chain,
                  resolver_lbl=resolver_lbl)


# ── Phase 3C-1: compare-mode helpers ────────────────────────────────────

def _answer_key_set(r: DnsDiagResult) -> set:
    """Hashable answer-set used for cross-resolver equality.

    Per agreed §2 semantics, the keys are qtype-specific so we never
    misjudge a structural difference (preference, case) as an equality:
      A / AAAA   → raw IP string
      CNAME / NS → lowercased target, trailing-dot stripped
      MX         → (preference:int, lowercased target)
      <other>    → fall back to the raw `value` string

    The comparison is intentionally STRUCTURAL not RTT/TTL — TTL is a
    cache-age detail that varies normally between resolvers and would
    flood the verdict with false-negatives if treated as authoritative.
    """
    out: set = set()
    if r is None or not r.answers:
        return out
    for a in r.answers:
        qt  = (a.qtype or "").upper()
        val = (a.value or "")
        if qt in ("A", "AAAA"):
            out.add(val)
        elif qt in ("CNAME", "NS"):
            out.add(val.rstrip(".").lower())
        elif qt == "MX":
            # value looks like "10 mail.example.com"; preference is also
            # surfaced on the answer object — prefer the int, but fall
            # back to splitting if for some reason it's None.
            pref = a.preference
            target = val
            if pref is None:
                parts = val.split(" ", 1)
                if len(parts) == 2:
                    try: pref = int(parts[0])
                    except ValueError: pref = None
                    target = parts[1]
            out.add((pref if pref is not None else -1,
                     target.rstrip(".").lower()))
        else:
            out.add(val)
    return out


def _chain_signature(r: DnsDiagResult) -> tuple:
    """Lowercased, dot-stripped CNAME chain — used for the optional hint.

    Returning a tuple keeps it directly equality-comparable across the
    two sides without further normalisation.
    """
    if r is None or not r.cname_chain:
        return tuple()
    return tuple((n or "").rstrip(".").lower() for n in r.cname_chain)


# ── Phase 3C-1.5: diff-first compare UI helpers ─────────────────────────
#
# These produce a JSON-serialisable matrix shape used by both the C and
# Web compare renderers.  Living next to _answer_key_set is intentional:
# the diff-row keys MUST stay structurally identical to the verdict
# keys, otherwise a row could light up green while build_compare_conclusion
# said "not equal" (or vice-versa).  If you ever revise _answer_key_set
# without touching _answer_entry_map you're shipping a UI bug.

def _answer_entry_map(r: Optional[DnsDiagResult]) -> dict:
    """Map structural key → display info, keyed identically to _answer_key_set.

    Each value carries the human-facing `display` string (preserved
    verbatim from the original DnsAnswer so the operator sees exactly
    what the resolver returned), `qtype`, and `ttl` (used to render
    "✓ TTL N" in the diff matrix).
    """
    out: dict = {}
    if r is None or not r.answers:
        return out
    for a in r.answers:
        qt  = (a.qtype or "").upper()
        val = a.value or ""
        if qt in ("A", "AAAA"):
            key = val
        elif qt in ("CNAME", "NS"):
            key = val.rstrip(".").lower()
        elif qt == "MX":
            pref = a.preference
            target = val
            if pref is None:
                parts = val.split(" ", 1)
                if len(parts) == 2:
                    try: pref = int(parts[0])
                    except ValueError: pref = None
                    target = parts[1]
            key = (pref if pref is not None else -1,
                   target.rstrip(".").lower())
        else:
            key = val
        out[key] = {"display": val, "qtype": qt, "ttl": a.ttl}
    return out


def _diff_cell_for_key(key, amap: dict,
                       side: Optional[DnsDiagResult]) -> dict:
    """One cell in the compare diff matrix.

    Semantics:
      key present in side  → ✓ with TTL.
      key absent, side succeeded otherwise → ✗ 缺失 (this resolver
        is missing the record the other side has).
      key absent, side failed wholesale → "—" (the absence is not
        meaningful — the side never produced any answers at all).
    """
    if key in amap:
        ttl = amap[key].get("ttl")
        text = f"✓ TTL {ttl}" if ttl is not None else "✓"
        return {"text": text, "ok": True}
    if side is not None and side.success:
        return {"text": "✗ 缺失", "ok": False}
    return {"text": "—", "ok": False}


def _diff_cell_for_empty_side(side: Optional[DnsDiagResult]) -> dict:
    """Cell text for the synthetic '(解析状态)' row when no answers exist.

    Distinguishes "succeeded but the zone is empty for this qtype" from
    "the resolver couldn't even reach a verdict" — the operator needs
    both labels to triage.
    """
    if side is None:
        return {"text": "—", "ok": False}
    if side.success:
        return {"text": "✓ 无记录", "ok": True}
    code  = first_failing_step_code(side) or side.rcode or ""
    label = ERROR_LABELS.get(code, code) or side.message or "失败"
    return {"text": f"✗ {label}", "ok": False}


def build_compare_diff_matrix(sides: list) -> dict:
    """Phase 3C-3 — N-column diff matrix shared by Web and C-side renderers.

    Output shape (v2):
      {
        "side_labels": [
          {"key": "system", "label": "172.20.10.1"},
          {"key": "r1",     "label": "8.8.8.8"},
          {"key": "r2",     "label": "1.1.1.1"}
        ],
        "rows": [
          {
            "display": "103.235.46.102",
            "qtype":   "A",
            "cells": {
              "system": {"text": "✓ TTL 60", "ok": True},
              "r1":     {"text": "✓ TTL 59", "ok": True},
              "r2":     {"text": "✗ 缺失",   "ok": False}
            }
          }, …
        ]
      }

    Row sort order: lexicographic on str(key) — stable so re-running
    on the same domain produces the same row order even when the
    answer order coming off the wire shuffles.

    Backward compatibility:
      When `sides` has length 2, each row additionally carries
      redundant top-level `system` / `custom` keys (copies of
      cells['system'] / cells['r1']) so the Phase 3C-1.5 JS fallback
      (`_dnsCompareDiffFromSides`) keeps rendering even if it never
      learns about `cells`.  This shim only kicks in for 2-side runs
      because v1 callers were never built to handle N > 2 anyway.

    Empty input (sides == []) returns a degenerate shape with no
    columns and no rows — callers should treat this as "nothing to
    diff" and skip rendering entirely.
    """
    if not sides:
        return {"side_labels": [], "rows": []}

    # ── 1) Side labels (ordered) ────────────────────────────────────
    side_labels: list = []
    for s in sides:
        # Fall back to a placeholder so an empty label never blanks out
        # a column header (would look like a layout bug).
        lbl = (s.label or "").strip() or _default_side_label(s)
        side_labels.append({"key": s.key, "label": lbl})

    # ── 2) Per-side answer-entry maps ───────────────────────────────
    maps: dict = {s.key: _answer_entry_map(s.result) for s in sides}

    # ── 3) Row keys: union across all sides, deterministic order ────
    seen: dict = {}
    for s in sides:
        for key, ent in maps[s.key].items():
            # First side wins for display fields — keeps "value column"
            # consistent across sides (different resolvers might
            # capitalise / dot-suffix differently, e.g. CNAME targets).
            seen.setdefault(key, ent)

    rows: list[dict] = []
    is_two = (len(sides) == 2)
    sys_key = sides[0].key
    cus_key = sides[1].key if is_two else None

    if not seen:
        # No side has any answers — synthesise a single "解析状态" row
        # so the UI doesn't render an empty table.
        cells = {
            s.key: _diff_cell_for_empty_side(s.result) for s in sides
        }
        row = {
            "display": "（解析状态）",
            "qtype":   "",
            "cells":   cells,
        }
        if is_two:
            row["system"] = cells[sys_key]
            row["custom"] = cells[cus_key]
        rows.append(row)
    else:
        for key in sorted(seen.keys(), key=lambda k: str(k)):
            ent = seen[key]
            cells = {
                s.key: _diff_cell_for_key(key, maps[s.key], s.result)
                for s in sides
            }
            row = {
                "display": ent["display"],
                "qtype":   ent["qtype"],
                "cells":   cells,
            }
            if is_two:
                row["system"] = cells[sys_key]
                row["custom"] = cells[cus_key]
            rows.append(row)

    return {"side_labels": side_labels, "rows": rows}


def _default_side_label(side: "DnsCompareSide") -> str:
    """Best-effort label for a side whose `.label` is empty.

    Used when build_compare_diff_matrix is given a side with a blank
    label (e.g. cancelled mid-way before resolver IP was captured).
    Picks the resolver string from the inner DnsDiagResult, then falls
    back to a key-derived placeholder.
    """
    try:
        if side.result is not None:
            r = side.result.resolver
            if r:
                return r
    except Exception:
        pass
    if side.key == "system":
        return "系统默认"
    return f"解析器 {side.key}"


# ── 3C-1.5 compatibility shim ──────────────────────────────────────
# `build_compare_diff_rows(system, custom)` was the 3C-1.5 entry point;
# both the C-side window and Web renderers have been migrated to call
# build_compare_diff_matrix(sides) directly in 3C-3, but we keep this
# 2-arg wrapper around so any external caller (tests, third-party
# integrations) that imported it survives the rename.  Output is the
# v2 matrix shape — callers reading the old `side_labels: {...}` dict
# form will need a one-line update, but the row-level `system`/`custom`
# shims keep most renderers working unchanged.

def build_compare_diff_rows(
        system: Optional[DnsDiagResult],
        custom: Optional[DnsDiagResult]) -> dict:
    """Backward-compat wrapper — delegates to build_compare_diff_matrix.

    Returns the v2 N-column matrix shape; 2 sides will additionally
    carry the legacy row-level `system`/`custom` keys for renderers
    that haven't migrated.  Side keys are hardcoded "system"/"custom"
    to mirror the 3C-1.5 column identifiers exactly.
    """
    sys_side = DnsCompareSide(
        key="system",
        label=(system.resolver if system else "") or "系统默认",
        result=system,  # type: ignore[arg-type]
    )
    cus_side = DnsCompareSide(
        key="custom",
        label=(custom.resolver if custom else "") or "自定义",
        result=custom,  # type: ignore[arg-type]
    )
    return build_compare_diff_matrix([sys_side, cus_side])


def _ttl_set(r: DnsDiagResult) -> set:
    """TTLs of all answers — for the "TTL 不同" advisory hint."""
    if r is None or not r.answers:
        return set()
    return {a.ttl for a in r.answers if a.ttl is not None}


def build_compare_conclusion(*args) -> tuple:
    """Pure verdict function — no side effects, no I/O.

    Signature is polymorphic for backward compatibility:
      build_compare_conclusion(sides_list)            # 3C-3 N-side
      build_compare_conclusion(system, custom)        # 3C-1 2-side

    Decision table (3C-3, generalised from 3C-1's table):
      1) ALL sides .success == False  → success=False, "全失败" text.
      2) Mixed success / failure       → success=False, asymmetric text.
      3) All sides succeeded:
           a) every side's answer-key set equals side 0's
              → success=True, "答案一致（N 条）"
           b) at least one side diverges
              → success=False, "答案不一致" + list of disagreeing labels.
      4) Advisory annotations (do NOT flip success):
           - any two sides' CNAME chain signatures differ
             → append "（CNAME 链不同）"
           - any two sides' TTL sets differ
             → append "（TTL 不同）"

    Returns (success_bool, conclusion_string).
    Conclusion is ALWAYS non-empty so callers can use it directly as
    the persisted `message` column without a None-check.
    """
    # Polymorphic argument handling.
    if len(args) == 1 and isinstance(args[0], list):
        sides = args[0]
    elif len(args) == 2:
        # Legacy 2-side path — synthesise two DnsCompareSide entries
        # with the canonical 3C-1 keys so renderers expecting them
        # unchanged stay happy.
        system, custom = args
        sides = [
            DnsCompareSide(
                key="system",
                label=(system.resolver if system else "") or "系统默认",
                result=system,
            ),
            DnsCompareSide(
                key="custom",
                label=(custom.resolver if custom else "") or "自定义",
                result=custom,
            ),
        ]
    else:
        raise TypeError(
            "build_compare_conclusion expects either a list of "
            "DnsCompareSide or (system, custom) DnsDiagResults")

    if not sides:
        return False, "无可对比的解析结果"

    ok_flags = [bool(s.result and s.result.success) for s in sides]
    succ_sides = [s for s, ok in zip(sides, ok_flags) if ok]
    fail_sides = [s for s, ok in zip(sides, ok_flags) if not ok]

    # ── Advisory note collection (chain / TTL drift) ────────────────
    # We check pairwise against side 0 — if side 0 disagrees with ANY
    # other side, the note fires.  Cheaper than full set-of-sets and
    # produces the same boolean verdict for the user.
    notes: list = []
    base_chain = _chain_signature(sides[0].result)
    if any(_chain_signature(s.result) != base_chain for s in sides[1:]):
        notes.append("CNAME 链不同")
    if all(ok_flags):
        base_ttl = _ttl_set(sides[0].result)
        if base_ttl and any(
                _ttl_set(s.result) and _ttl_set(s.result) != base_ttl
                for s in sides[1:]):
            notes.append("TTL 不同")

    def _annotate(base: str) -> str:
        return base + (f"（{'，'.join(notes)}）" if notes else "")

    def _lbl(side: DnsCompareSide) -> str:
        return (side.label or "").strip() or _default_side_label(side)

    # ── Case 1: every side failed ───────────────────────────────────
    # NXDOMAIN-on-all is an "agreed verdict" but still an operational
    # failure (the name doesn't resolve anywhere), so we keep
    # success=False to avoid masking the issue.
    if not succ_sides:
        parts = []
        for s in sides:
            rc = (s.result.rcode if s.result else "") or "—"
            parts.append(f"{_lbl(s)} → {rc}")
        return False, _annotate("所有解析器均失败：" + "；".join(parts))

    # ── Case 2: mixed — some sides succeeded, some failed ───────────
    if fail_sides:
        ok_lbls  = "、".join(_lbl(s) for s in succ_sides)
        bad_parts = []
        for s in fail_sides:
            rc = (s.result.rcode if s.result else "") or "—"
            bad_parts.append(f"{_lbl(s)} → {rc}")
        msg = (f"结果不一致：{ok_lbls} 解析成功；"
               f"{'；'.join(bad_parts)}")
        return False, _annotate(msg)

    # ── Case 3: all sides succeeded — structural answer-set compare ─
    key_sets = [_answer_key_set(s.result) for s in sides]
    base_set = key_sets[0]
    if all(ks == base_set for ks in key_sets[1:]):
        return True, _annotate(f"答案一致（{len(base_set)} 条）")

    # ── Case 3b: keys diverge ───────────────────────────────────────
    # For 2 sides the 3C-1 text "vs X [v1] vs Y [v2]" still reads;
    # for 3+ sides we just name which columns disagree with the
    # baseline.  Full per-cell breakdown lives in the diff matrix —
    # the conclusion text only needs to point the operator at it.
    if len(sides) == 2:
        # Preserve the 3C-1 "list-the-values" form for 2-side runs so
        # operators don't notice a regression on the most common path.
        def _fmt(side: DnsCompareSide) -> str:
            r = side.result
            vs = [a.value for a in (r.answers or [])][:5] if r else []
            s_ = "、".join(vs) if vs else "（空）"
            if r and len(r.answers) > 5:
                s_ += f"…(+{len(r.answers) - 5})"
            return s_
        msg = (f"答案不一致：{_lbl(sides[0])} [{_fmt(sides[0])}] "
               f"vs {_lbl(sides[1])} [{_fmt(sides[1])}]")
        return False, _annotate(msg)

    # 3+ sides — point at disagreeing columns.
    diff_lbls = [
        _lbl(s) for s, ks in zip(sides[1:], key_sets[1:]) if ks != base_set
    ]
    msg = (f"答案不一致：{_lbl(sides[0])} 与 "
           f"{'、'.join(diff_lbls)} 在答案集合上存在分歧；详见对比表")
    return False, _annotate(msg)


def _compose_compare_side(target: str, qtype: str, timeout_s: float,
                          trace_chain: bool, key: str,
                          ip_or_none: Optional[str]) -> "DnsCompareSide":
    """Run one side of a compare and wrap it in a DnsCompareSide.

    `ip_or_none == None` → system side (no nameserver override).
    Label is derived from the resolver actually used (`result.resolver`),
    falling back to the operator-typed IP for custom sides so the column
    header always shows what the operator asked for.
    """
    sub_req = DnsDiagRequest(
        target=target, qtype=qtype, timeout_s=timeout_s,
        trace_chain=bool(trace_chain),
        nameserver=ip_or_none, mode="single")
    sub = run_dns_diag(sub_req)
    if ip_or_none:
        # Custom side: prefer the operator-typed IP for the label so it
        # matches the chip exactly, even if dnspython normalises the
        # address representation.
        label = ip_or_none
    else:
        # System side: show the resolver dnspython actually used (often
        # the OS-configured DNS), with a friendly fallback.
        label = sub.resolver or "系统默认"
    return DnsCompareSide(key=key, label=label, result=sub)


def run_dns_compare(req: DnsDiagRequest) -> DnsCompareResult:
    """Synchronous compare entry — system side first, then each custom IP.

    Returns a fully-populated DnsCompareResult even when one or more
    sub-queries failed (their individual DnsDiagResults carry the
    failure detail; the conclusion text and top-level .success reflect
    the verdict).

    Intentional design choices (3C-3 evolution of 3C-1's contract):
      • One fresh _make_resolver() per side — never re-use one with
        a swapped .nameservers list, because dnspython may cache state
        between calls (in particular response signatures and current
        retry index) and we want each side to start from a clean slate.
      • Sequential, not parallel — see module docstring.  This means
        elapsed_ms ≈ Σ side.elapsed_ms; callers comparing compare-mode
        "耗时" against single-mode "耗时" should expect roughly Nx the
        latency for an N-side run.
      • trace_chain copied to every side verbatim — if A/AAAA + trace
        is on for one side and off for another, _answer_key_set would
        compare terminal IPs against leading CNAMEs and almost always
        disagree.  Lockstep is the only sane contract.
      • Side keys are "system" (always first) then "r1" / "r2" / "r3"
        in input order — stable identifiers usable as JS object keys
        and as Tk widget-dict lookup keys without escaping.
    """
    err = validate_dns_request(req)
    if err:
        # Return a synthetic "empty" result with the validation message —
        # keeps the API uniform so callers don't need to special-case
        # validation failures.  Empty side list signals "no data"; the
        # conclusion text carries the validator's user-facing error.
        return DnsCompareResult(
            target      = req.target,
            qtype       = req.qtype,
            trace_chain = bool(req.trace_chain),
            nameservers = [],
            sides       = [],
            success     = False,
            conclusion  = err,
            elapsed_ms  = 0.0,
        )

    custom_ips = _normalize_compare_nameservers(req)

    t0 = time.monotonic()
    sides: list = [_compose_compare_side(
        req.target, req.qtype, req.timeout_s, req.trace_chain,
        key="system", ip_or_none=None)]
    for idx, ip in enumerate(custom_ips, start=1):
        sides.append(_compose_compare_side(
            req.target, req.qtype, req.timeout_s, req.trace_chain,
            key=f"r{idx}", ip_or_none=ip))
    elapsed_ms = (time.monotonic() - t0) * 1000.0

    ok, conclusion = build_compare_conclusion(sides)
    return DnsCompareResult(
        target      = req.target,
        qtype       = req.qtype,
        trace_chain = bool(req.trace_chain),
        nameservers = list(custom_ips),
        sides       = sides,
        success     = ok,
        conclusion  = conclusion,
        elapsed_ms  = round(elapsed_ms, 1),
    )


# ── Async runner + DiagTask ─────────────────────────────────────────────

class DnsDiagTask:
    """Handle to a running DNS diagnostic — call .cancel() to stop.

    DNS queries don't spawn subprocesses (dnspython does socket I/O on
    the calling thread), so cancel only flips the Event; the worker
    checks between queries.  A query already in-flight will finish
    (up to its timeout) before we exit — there's no clean dnspython
    interrupt path, but timeouts are bounded.
    """
    def __init__(self):
        self._cancel = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def cancel(self):
        self._cancel.set()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


def run_dns_diag_async(
        req: DnsDiagRequest,
        on_done:  Optional[Callable] = None,
        on_error: Optional[Callable[[str], None]] = None,
        data_store=None,
        target_id: Optional[str] = None,
) -> DnsDiagTask:
    """Run a DNS diagnostic on a background thread.

    on_done(result)   – fired with the final result.  In `single` mode
                        this is a DnsDiagResult (Phase 3B contract);
                        in `compare` mode it is a DnsCompareResult.
                        Callers that don't statically know which mode
                        was requested can isinstance-check, or use the
                        dns_run_to_dict helper which dispatches for
                        them.  on_done's type signature is therefore
                        intentionally loose (no generic param), so a
                        single callback can serve both modes.
    on_error(message) – fired on validation failure OR semaphore busy
                        (these two cases never produce a result)

    data_store + target_id – optional persistence hook (Phase 3A).  When
    data_store is non-None and the result is NOT a cancellation, the
    result is persisted to dns_diagnostic_history BEFORE on_done fires
    so a UI callback that immediately opens the history list sees the
    new row.  target_id may be None (ad-hoc diag, not tied to a node).
    Both default to None so the sync path / tests stay zero-config.

    Phase 3C-1 cancel timing for compare mode (single mode unchanged):
      sem acquire → cancel-check → run system →
                    cancel-check (the v1 interrupt point) →
                    run custom → build verdict → persist → on_done
    Hitting cancel at either of those checkpoints yields the same
    synthetic ERROR_CANCELLED DnsDiagResult as the single path, and
    persistence is SKIPPED — partially-completed compares would just
    confuse the history list ("system=ok, custom=?").

    Returns a DnsDiagTask handle; call handle.cancel() to abort.
    """
    err = validate_dns_request(req)
    if err:
        if on_error:
            on_error(err)
        return DnsDiagTask()

    task = DnsDiagTask()
    mode_sel = getattr(req, "mode", "single") or "single"
    is_compare    = (mode_sel == "compare")
    is_trace_auth = (mode_sel == "trace_auth")
    is_dnssec     = (mode_sel == "dnssec")

    def _build_cancelled() -> DnsDiagResult:
        # Synthetic "cancelled" result so the UI layer can render a
        # consistent terminal state for stop-mid-query.  Web layer
        # detects rcode == ERROR_CANCELLED and maps task.status to
        # "cancelled"; C-side dns_diag_window has a matching branch.
        #
        # Compare mode reuses THIS same DnsDiagResult-shaped sentinel
        # rather than a synthetic DnsCompareResult — because both UI
        # layers already key off rcode == ERROR_CANCELLED for terminal
        # rendering, and shipping a Compare-shaped cancelled payload
        # would require parallel cancelled-state code in C / Web.  The
        # `mode` field gets re-attached in on_done's persistence-skip
        # branch so the status endpoint still reports cancelled cleanly.
        return DnsDiagResult(
            target      = req.target,
            qtype       = req.qtype,
            resolver    = "",
            success     = False,
            rcode       = ERROR_CANCELLED,
            elapsed_ms  = 0.0,
            message     = ERROR_LABELS[ERROR_CANCELLED],
            # Cancelled rows never reach the DB (see _persist_dns_result
            # gating below), so the empty nameserver is purely cosmetic
            # for any UI path that does inspect the synthetic result.
            nameserver  = (req.nameserver or "").strip(),
        )

    def _run_single(captured_gen: Optional[int]):
        """Phase 3B path — one query, persist as single.

        captured_gen is the target identity generation snapshot taken
        in _run() before mode dispatch; it propagates through the
        persist helper so a wipe / removal that lands mid-run cleanly
        drops this row.  Same shape applies to compare / trace_auth /
        dnssec variants below.
        """
        if task._cancel.is_set():
            if on_done:
                try: on_done(_build_cancelled())
                except Exception: pass
            return
        try:
            result = run_dns_diag(req)
        except Exception as exc:
            # Belt-and-braces — run_dns_diag handles every dnspython
            # exception we know about, but a stray import error or
            # OS-level socket exception shouldn't crash the thread.
            if on_error:
                on_error(f"DNS 诊断异常：{type(exc).__name__}: {exc}")
            return
        if task._cancel.is_set():
            # User clicked stop while we were resolving — surface a
            # synthetic cancelled result so the UI gets a terminal
            # state instead of staying in "running" forever.  Web
            # _on_done already keeps existing "cancelled" status if
            # /api/dns_diag/cancel was POSTed first, so this is a
            # no-op there; on C-side it triggers the cancelled
            # rendering branch.  Persistence is SKIPPED for the
            # cancelled-result path.
            if on_done:
                try: on_done(_build_cancelled())
                except Exception: pass
            return
        # Persist BEFORE invoking on_done so a UI callback that
        # immediately opens the history list sees the new row.
        # data_store can be None in test / sync paths — no-op then.
        # ERROR_CANCELLED is excluded above so any result reaching
        # this point is a legitimate completion (success or named
        # failure such as NXDOMAIN / NO_ANSWER / TIMEOUT…).
        if data_store is not None:
            _persist_dns_result(data_store, result, req.trace_chain,
                                target_id, captured_gen)
        if on_done:
            try:
                on_done(result)
            except Exception:
                pass

    def _run_compare(captured_gen: Optional[int]):
        """Phase 3C-3 path — sequential system → r1 → … → rN; cancel between sides.

        Mirrors _run_single's error-handling, cancel-checking and
        persist-before-on_done ordering, just with N halves.  Interrupt
        points: BEFORE each side and AFTER the last side (N+1 total).
        Neither dnspython resolve() call is itself interruptible
        (timeouts are bounded so the worst case after Stop is one more
        `timeout_s` worth of blocking before we observe the flag).

        Cancellation semantics (D1 in 3C-3 plan): a cancel observed at
        ANY checkpoint discards the entire compare — no partial result
        is rendered or persisted.  A partial row in history would just
        confuse the operator (was that an authoritative "system found
        no records" or "we never got to ask r2"?), and the partial-side
        rendering path would need to flow through the C / Web cancelled
        branches, which were never built for compare-shaped payloads.
        Phase 3C-3.1 (post-cap-bump to N≥5) may revisit if operators ask.
        """
        if task._cancel.is_set():
            if on_done:
                try: on_done(_build_cancelled())
                except Exception: pass
            return

        custom_ips = _normalize_compare_nameservers(req)
        # validate_dns_request has already approved the request — but
        # belt and braces: if the list is somehow empty we can't run a
        # compare, so surface as an error and bail.
        if not custom_ips:
            if on_error:
                on_error("对比模式至少需要 1 个对照解析器")
            return

        t0 = time.monotonic()
        sides: list = []
        try:
            sides.append(_compose_compare_side(
                req.target, req.qtype, req.timeout_s, req.trace_chain,
                key="system", ip_or_none=None))
        except Exception as exc:
            if on_error:
                on_error(f"DNS 对比（系统侧）异常：{type(exc).__name__}: {exc}")
            return

        # Walk the custom IPs sequentially, cancel-checking between
        # each.  We check BEFORE the next resolve fires so a Stop click
        # observed at side-K interrupts immediately rather than waiting
        # for side-K's own timeout.
        for idx, ip in enumerate(custom_ips, start=1):
            if task._cancel.is_set():
                if on_done:
                    try: on_done(_build_cancelled())
                    except Exception: pass
                return
            try:
                sides.append(_compose_compare_side(
                    req.target, req.qtype, req.timeout_s, req.trace_chain,
                    key=f"r{idx}", ip_or_none=ip))
            except Exception as exc:
                if on_error:
                    on_error(f"DNS 对比（{ip}）异常："
                             f"{type(exc).__name__}: {exc}")
                return

        # Final cancel check — operator clicked Stop during the LAST
        # resolve.  Same handling: synthetic cancelled, no persist.
        if task._cancel.is_set():
            if on_done:
                try: on_done(_build_cancelled())
                except Exception: pass
            return

        elapsed_ms = (time.monotonic() - t0) * 1000.0
        ok, conclusion = build_compare_conclusion(sides)
        compare = DnsCompareResult(
            target      = req.target,
            qtype       = req.qtype,
            trace_chain = bool(req.trace_chain),
            nameservers = list(custom_ips),
            sides       = sides,
            success     = ok,
            conclusion  = conclusion,
            elapsed_ms  = round(elapsed_ms, 1),
        )

        if data_store is not None:
            _persist_dns_compare(data_store, compare, target_id,
                                 captured_gen)
        if on_done:
            try:
                on_done(compare)
            except Exception:
                pass

    def _run_auth_trace(captured_gen: Optional[int]):
        """Phase 3C-4 path — authority-trace walk; cancel between hops.

        Cancellation contract (decision A — reuse the existing
        DnsDiagResult-shaped ERROR_CANCELLED sentinel):

          The worker passes task._cancel.is_set as the cancel_check
          predicate to run_dns_auth_trace.  When the engine observes
          the flag it returns a partial DnsAuthResult with
          rcode=ERROR_CANCELLED — but we DO NOT forward THAT to the
          UI.  Instead we substitute the same DnsDiagResult sentinel
          that single/compare modes use (_build_cancelled), so the
          C/Web terminal-rendering branches keep working unchanged
          (both already special-case isinstance(result, DnsDiagResult)
          + rcode == ERROR_CANCELLED).  The status endpoint still
          reports mode=trace_auth so the web placeholder can pick the
          right cancelled wording before the result lands.

          Persistence is SKIPPED in the cancelled path — a half-walked
          delegation chain in history would confuse the operator more
          than no row at all.
        """
        if task._cancel.is_set():
            if on_done:
                try: on_done(_build_cancelled())
                except Exception: pass
            return

        try:
            result = run_dns_auth_trace(
                req, cancel_check=task._cancel.is_set)
        except Exception as exc:
            if on_error:
                on_error(
                    f"权威追踪异常：{type(exc).__name__}: {exc}")
            return

        if task._cancel.is_set() or result.rcode == ERROR_CANCELLED:
            # Either the engine saw cancel mid-walk, OR the operator
            # clicked Stop after the walk completed but before this
            # code ran.  Either way: substitute the canonical
            # DnsDiagResult cancelled sentinel; skip persistence.
            if on_done:
                try: on_done(_build_cancelled())
                except Exception: pass
            return

        if data_store is not None:
            _persist_dns_auth(data_store, result, target_id, captured_gen)

        if on_done:
            try:
                on_done(result)
            except Exception:
                pass

    def _run_dnssec(captured_gen: Optional[int]):
        """Phase 3C-5 path — single DNSSEC validation; cancel between zones.

        Cancellation contract (matches trace_auth — decision A reused):

          The worker passes task._cancel.is_set as cancel_check to
          run_dnssec_validate.  The engine returns control on cancel
          with status=indeterminate; we then ALSO observe
          task._cancel.is_set() ourselves on the way out and, when set,
          discard the engine's result and substitute the standard
          DnsDiagResult-shaped ERROR_CANCELLED sentinel so the C/Web
          terminal-rendering branches stay consistent across all four
          modes.

          Persistence is SKIPPED on cancel — a half-walked DNSSEC chain
          is just confusing in the history list (operator can't tell
          if INSECURE-at-com. was "really" or "cancel mid-walk").
        """
        if task._cancel.is_set():
            if on_done:
                try: on_done(_build_cancelled())
                except Exception: pass
            return

        try:
            result = run_dnssec_validate(
                req, cancel_check=task._cancel.is_set)
        except Exception as exc:
            if on_error:
                on_error(
                    f"DNSSEC 验证异常：{type(exc).__name__}: {exc}")
            return

        if task._cancel.is_set():
            # User clicked Stop mid-walk OR after engine returned but
            # before this code ran — either way, substitute the
            # canonical cancelled sentinel.  Skip persistence.
            if on_done:
                try: on_done(_build_cancelled())
                except Exception: pass
            return

        if data_store is not None:
            _persist_dns_dnssec(data_store, result, target_id,
                                captured_gen)

        if on_done:
            try:
                on_done(result)
            except Exception:
                pass

    def _run():
        if not DIAG_TASK_SEM.acquire(blocking=False):
            if on_error:
                on_error("当前有诊断任务正在进行，请稍后再试")
            return
        try:
            # Capture target identity generation once, after the
            # semaphore is acquired but before mode dispatch.  All
            # four runners receive the same snapshot so a wipe /
            # removal that lands between this point and the persist
            # call drops the row regardless of which mode is running
            # (3C-3 compare / 3C-4 trace_auth / 3C-5 dnssec previously
            # bypassed the generation check that 3B single already
            # honoured).
            captured_gen = (data_store.current_target_generation(target_id)
                             if (data_store is not None and target_id is not None)
                             else None)
            if is_dnssec:
                _run_dnssec(captured_gen)
            elif is_trace_auth:
                _run_auth_trace(captured_gen)
            elif is_compare:
                _run_compare(captured_gen)
            else:
                _run_single(captured_gen)
        finally:
            DIAG_TASK_SEM.release()

    task._thread = threading.Thread(target=_run, daemon=True,
                                     name="dns-diag")
    task._thread.start()
    return task


def _persist_dns_result(data_store, result: DnsDiagResult,
                        trace_chain: bool,
                        target_id: Optional[str],
                        captured_generation: Optional[int] = None) -> None:
    """Hand the DNS result to DataStore.  Wrapped in broad except so a
    DB write failure can NEVER kill the diagnostic — the UI must still
    see the result even if persistence fails.

    trace_chain comes from the originating request (it's a query-time
    flag, not part of the result), captured via run_dns_diag_async's
    closure on req.trace_chain.

    captured_generation: snapshot from the start of the async task,
    forwarded to record_dns_diag_result so the write is skipped when
    the target identity changed mid-run (wipe / removal).
    """
    try:
        data_store.record_dns_diag_result(
            target_id     = target_id,
            domain        = result.target,
            qtype         = result.qtype,
            trace_chain   = bool(trace_chain),
            resolver      = result.resolver or None,
            success       = bool(result.success),
            rcode         = result.rcode or None,
            elapsed_ms    = result.elapsed_ms,
            answer_count  = len(result.answers),
            error_summary = first_failing_step_code(result) or "",
            message       = result.message or "",
            details       = dns_result_to_dict(result),
            captured_generation = captured_generation,
        )
    except Exception:
        pass


def _persist_dns_compare(data_store, compare: DnsCompareResult,
                         target_id: Optional[str],
                         captured_generation: Optional[int] = None) -> None:
    """Phase 3C-3 persistence — folds an N-side compare into the SAME
    dns_diagnostic_history table as single / 2-side compare runs, no
    schema bump.

    Field mapping (3C-3 evolution of 3C-1 §3.7):
      resolver      → "系统 vs <ip0>" for 2 sides (3C-1 format).
                       "系统 vs <ip0>,+K" for 3+ sides where K is the
                       count of EXTRA custom resolvers — keeps the
                       history-list column self-explanatory in one
                       glance.  Full list lives in details_json.
      success       → compare.success              — structural verdict.
      rcode         → "NOERROR"   if compare.success
                      "MISMATCH"  if all sides succeeded but disagreed
                      otherwise   first-failing-side rcode (for the
                       "rcode != NOERROR" filter to keep working).
      elapsed_ms    → compare.elapsed_ms           — total wall time.
      answer_count  → max across all sides — the biggest count is the
                       most informative one for a list-row glance.
      error_summary → "mismatch" on disagree-success / first failing
                       side's error code otherwise.
      message       → compare.conclusion.
      details_json  → dns_compare_to_dict(...)     — full N-side
                       snapshot (compare_version=2, sides=[...],
                       nameservers=[...]).  Old 2-side keys
                       (system/custom/nameserver) are also written for
                       backward compat with pre-3C-3 readers.
    """
    try:
        sides = list(compare.sides or [])
        # Bail silently if there's nothing to persist — the engine
        # should never reach here with empty sides (cancelled / validation
        # paths short-circuit before us), but we don't want a stray bad
        # input to throw and kill the worker thread.
        if not sides:
            return

        ok_flags = [bool(s.result and s.result.success) for s in sides]
        all_ok = all(ok_flags)

        if compare.success:
            rcode = "NOERROR"
            err_sum = ""
        elif all_ok:
            # All sides individually OK but verdict said the answer sets
            # diverge.  MISMATCH is the legacy 3C-1 sentinel — preserved
            # so existing history-list filters keep matching.
            rcode = "MISMATCH"
            err_sum = "mismatch"
        else:
            # At least one side failed — surface the first failing rcode
            # in side order (system → r1 → r2 → …).  Mirrors the 3C-1
            # "baseline first" tie-break.
            first_fail = next(
                (s.result for s, ok in zip(sides, ok_flags) if not ok),
                None)
            rcode = (first_fail.rcode if first_fail else "") or ""
            err_sum = first_failing_step_code(first_fail) if first_fail else ""

        n_ans = max((len(s.result.answers) if s.result else 0)
                    for s in sides)

        # 3C-3 D5 — "系统 vs X" for 2 sides (preserves 3C-1 readout
        # exactly), "系统 vs X,+K" otherwise (e.g. "系统 vs 8.8.8.8,+2").
        nss = list(compare.nameservers or [])
        if not nss:
            resolver_lbl = "系统 vs 自定义"
        elif len(nss) == 1:
            resolver_lbl = f"系统 vs {nss[0]}"
        else:
            resolver_lbl = f"系统 vs {nss[0]},+{len(nss) - 1}"

        data_store.record_dns_diag_result(
            target_id     = target_id,
            domain        = compare.target,
            qtype         = compare.qtype,
            trace_chain   = bool(compare.trace_chain),
            resolver      = resolver_lbl,
            success       = bool(compare.success),
            rcode         = rcode or None,
            elapsed_ms    = compare.elapsed_ms,
            answer_count  = n_ans,
            error_summary = err_sum,
            message       = compare.conclusion or "",
            details       = dns_compare_to_dict(compare),
            captured_generation = captured_generation,
        )
    except Exception:
        pass


def _persist_dns_auth(data_store, result: DnsAuthResult,
                      target_id: Optional[str],
                      captured_generation: Optional[int] = None) -> None:
    """Phase 3C-4 persistence — fold an authority-trace into the SAME
    dns_diagnostic_history table as single / compare runs.  Schema
    unchanged (decision per 3C-4 plan §9).

    Field mapping:
      resolver      → "权威追踪" — single fixed label so the history
                       list column is instantly recognisable.  The
                       per-hop NS detail lives in details_json.
      success       → result.success.
      rcode         → result.rcode (NOERROR on success / engine error
                       code on failure / first failing hop's rcode on
                       transit failures).
      elapsed_ms    → result.elapsed_ms (wall time across all hops).
      answer_count  → len(result.final_answers).  0 for any failure
                       branch — the operator already sees the failure
                       label in `rcode`, double-counting here would
                       just inflate the column.
      error_summary → first failing hop's error_code, or "" on success.
      message       → result.message.
      details_json  → dns_auth_to_dict(...) — the canonical payload
                       used by replay + downstream renderers.
    """
    try:
        first_fail = next(
            (h for h in (result.hops or []) if not h.success), None)
        err_sum = (first_fail.error_code if first_fail else "") or ""
        data_store.record_dns_diag_result(
            target_id     = target_id,
            domain        = result.target,
            qtype         = result.qtype,
            # trace_chain is conceptually irrelevant for an authority
            # trace (we walk delegation, not CNAME); record False so
            # the history list's any-trace_chain-display path stays
            # consistent ("CNAME 链未展开" wouldn't make sense here).
            trace_chain   = False,
            resolver      = "权威追踪",
            success       = bool(result.success),
            rcode         = result.rcode or None,
            elapsed_ms    = result.elapsed_ms,
            answer_count  = len(result.final_answers or []),
            error_summary = err_sum,
            message       = result.message or "",
            details       = dns_auth_to_dict(result),
            captured_generation = captured_generation,
        )
    except Exception:
        pass


def _persist_dns_dnssec(data_store, result: DnsSecResult,
                        target_id: Optional[str],
                        captured_generation: Optional[int] = None) -> None:
    """Phase 3C-5 persistence — fold a DNSSEC run into the SAME
    dns_diagnostic_history table as single / compare / trace_auth.
    Schema unchanged (decision per 3C-5 plan §9).

    Field mapping:
      resolver      → "DNSSEC" for system-default runs (mirrors how
                       trace_auth uses "权威追踪" as a fixed badge),
                       "DNSSEC · <ip>" when the operator chose a
                       custom resolver — the IP carries forward to
                       the history list's resolver column at a
                       glance.  Full transport detail in details_json.
      success       → result.success — strict SECURE-only mapping
                       (decision Q2).  History list pill therefore
                       reads "成功" only when SECURE; INSECURE rows
                       show "失败" to match the boolean, but the
                       per-row DNSSEC status badge (added by the C/Web
                       history list renderers) carries the real four-
                       state nuance so the operator never reads the
                       red pill as "incident".
      rcode         → upper-cased four-state status ("SECURE",
                       "INSECURE", "BOGUS", "INDETERMINATE").
                       Re-using the rcode column for the verdict
                       label (cf. compare mode's "MISMATCH") keeps the
                       history filter on rcode != NOERROR distinguishing
                       INSECURE/BOGUS rows without a schema bump.
      elapsed_ms    → result.elapsed_ms (total wall time).
      answer_count  → len(result.answers) — populated even on
                       INSECURE / BOGUS so the operator still sees
                       "yes, the resolver returned 3 records".
      error_summary → ERROR_DNSSEC_INSECURE / _BOGUS /
                       _INDETERMINATE — gives the history list a
                       short tag distinct from the verdict label;
                       empty on SECURE.
      message       → result.message.
      details_json  → dnssec_to_dict(...) — full chain + answers +
                       cname_chain.  Used by C/Web replay paths.
    """
    try:
        status = (result.status or "indeterminate").upper()
        ns = (result.nameserver or "").strip()
        resolver_lbl = "DNSSEC" if not ns else f"DNSSEC · {ns}"

        if result.status == "secure":
            err_sum = ""
        elif result.status == "insecure":
            err_sum = ERROR_DNSSEC_INSECURE
        elif result.status == "bogus":
            err_sum = ERROR_DNSSEC_BOGUS
        else:
            err_sum = ERROR_DNSSEC_INDETERMINATE

        data_store.record_dns_diag_result(
            target_id     = target_id,
            domain        = result.target,
            qtype         = result.qtype,
            # trace_chain is conceptually unused for DNSSEC (engine
            # handles CNAME chasing internally to find the leaf zone);
            # record False so the history list's chain-display path
            # stays consistent with trace_auth.
            trace_chain   = False,
            resolver      = resolver_lbl,
            success       = bool(result.success),
            rcode         = status,
            elapsed_ms    = result.elapsed_ms,
            answer_count  = len(result.answers or []),
            error_summary = err_sum,
            message       = result.message or "",
            details       = dnssec_to_dict(result),
            captured_generation = captured_generation,
        )
    except Exception:
        pass


def first_failing_step_code(result: DnsDiagResult) -> Optional[str]:
    """Return the error_code of the first failing trace step, if any.

    Public helper used by both the C-side window (status-bar label on
    failure) and the persistence hook (error_summary column).  Returns
    None when every step succeeded — callers should default to "".
    """
    for s in result.trace_steps:
        if s.status and s.status != ERROR_OK:
            return s.status
    return None


# ── Human-readable error labels (UI helper) ─────────────────────────────

ERROR_LABELS: dict[str, str] = {
    ERROR_OK:               "成功",
    ERROR_TIMEOUT:          "超时",
    ERROR_NXDOMAIN:         "域名不存在",
    ERROR_NO_ANSWER:        "无匹配记录",
    ERROR_SERVFAIL:         "解析器 SERVFAIL",
    ERROR_REFUSED:          "解析器拒绝",
    ERROR_RESOLVER_UNREACH: "解析器不可达",
    ERROR_INVALID_DOMAIN:   "域名格式错误",
    ERROR_CANCELLED:        "已取消",
    ERROR_CNAME_LOOP:       "CNAME 链回环",
    ERROR_CNAME_TOO_DEEP:   "CNAME 链过深",
    ERROR_AUTH_MAX_HOPS:    "权威追踪跳数超限",
    ERROR_GLUE_MISSING:     "referral 缺少 glue 且 NS 主机名无法解析",
    ERROR_AUTH_TRACE_FAILED:"权威追踪失败",
    ERROR_DNSSEC_INSECURE:    "DNSSEC 未签名（INSECURE）",
    ERROR_DNSSEC_BOGUS:       "DNSSEC 签名错误（BOGUS）",
    ERROR_DNSSEC_INDETERMINATE: "DNSSEC 验证未完成（INDETERMINATE）",
    ERROR_UNKNOWN:          "未知错误",
}
