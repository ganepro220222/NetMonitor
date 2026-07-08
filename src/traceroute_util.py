"""
traceroute_util.py
==================
Shared traceroute helper extracted from `web_server.py`.

Previously this lived inline at `web_server.py:58` so only the web layer
could call it.  C-side diagnostics (e.g. the new "追踪此 IP" button in
the DNS diag window) need the same hop-parsing logic — duplicating it
would drift fast.  Moved here verbatim; `web_server.py` now imports it.

[Critical implementation notes preserved from original site]
  Previous versions used CREATE_NO_WINDOW + shell=True.
  On Windows this combination breaks pipe inheritance: cmd.exe is created
  without a console, stdout/stderr pipes are not properly inherited, and
  result.stdout comes back as b"". The exception handler then returns the
  single "break" hop that was confusing users.

  Fix: use STARTUPINFO.dwFlags |= STARTF_USESHOWWINDOW + SW_HIDE.
  This hides the console window while keeping pipe inheritance intact.
  Also: full path to tracert.exe, -w 1000 (shorter probe timeout),
  120-second subprocess timeout, improved hop line parser.
"""
from __future__ import annotations

import os
import platform
import re
import subprocess


def run_traceroute(ip: str, max_hops: int = 30, *, wait_ms: int = 1000) -> list:
    """
    Run the system traceroute and return a list of hop dicts.

    Windows notes:
      • Uses STARTUPINFO (STARTF_USESHOWWINDOW + SW_HIDE) to suppress
        the console window. DO NOT use CREATE_NO_WINDOW with shell=True —
        that breaks pipe inheritance and gives empty output.
      • Full path to tracert.exe avoids PATH issues in daemon threads.
      • -w wait_ms (default 1000 ms) per probe; worst case for 20 hops:
        20 × 3 probes × wait_ms — urgent auto-traces pass a shorter wait.
      • GBK decoding first because Chinese Windows tracert outputs GBK.
    """
    wait_ms = max(200, min(5000, int(wait_ms)))
    is_win = platform.system().lower() == "windows"
    raw = b""

    try:
        if is_win:
            sysroot   = os.environ.get("SystemRoot", "C:\\Windows")
            tracert   = os.path.join(sysroot, "System32", "tracert.exe")
            if not os.path.isfile(tracert):
                tracert = "tracert"   # fallback to PATH

            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE

            result = subprocess.run(
                [tracert, "-d", "-h", str(max_hops), "-w", str(wait_ms), ip],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=120, startupinfo=si)
            raw = result.stdout + result.stderr

        else:
            result = subprocess.run(
                ["traceroute", "-n", "-m", str(max_hops), "-w", "2", ip],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=120)
            raw = result.stdout + result.stderr

        if not raw:
            return [{"hop": 1, "ip": None, "hostname": None, "rtt_ms": None,
                     "status": "break",
                     "error": f"tracert returned no output (exit={result.returncode})"}]

        for enc in (["gbk", "cp936", "utf-8"] if is_win else ["utf-8", "latin-1"]):
            try:
                output = raw.decode(enc)
                break
            except (UnicodeDecodeError, LookupError):
                continue
        else:
            output = raw.decode("utf-8", errors="replace")

    except subprocess.TimeoutExpired as exc:
        partial = b""
        if exc.stdout: partial += exc.stdout
        if exc.stderr: partial += exc.stderr
        if partial:
            output = partial.decode("gbk" if is_win else "utf-8", errors="replace")
        else:
            return [{"hop": 1, "ip": None, "hostname": None, "rtt_ms": None,
                     "status": "break", "error": "traceroute timed out (no partial output)"}]

    except Exception as exc:
        return [{"hop": 1, "ip": None, "hostname": None, "rtt_ms": None,
                 "status": "break", "error": f"{type(exc).__name__}: {exc}"}]

    # ── Parse output ──────────────────────────────────────────────────
    hops = []
    for line in output.replace("\r", "").split("\n"):
        line = line.strip()
        m = re.match(r"^(\d+)\s+", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest    = line[m.end():]

        has_ms     = bool(re.search(r"\d+\s*ms", rest, re.I))
        asterisks  = rest.count("*")
        is_timeout = asterisks >= 3 and not has_ms

        if is_timeout:
            hops.append({"hop": hop_num, "ip": None, "hostname": None,
                         "rtt_ms": None, "status": "timeout_raw"})
        else:
            rtt_m = re.search(r"[<]?(\d+(?:\.\d+)?)\s*ms", rest, re.I)
            rtt   = float(rtt_m.group(1)) if rtt_m else None

            # IPv4 in brackets: "hostname [x.x.x.x]"
            # IPv6 in brackets: "hostname [2001:db8::1]" (Windows tracert)
            # Bracketed IP form.  Windows tracert uses [ip] when DNS
            # reverse-lookup ran; macOS/BSD traceroute uses (ip).  Match
            # both bracket styles so the parser stays cross-platform.
            # (Linux run path uses -n which suppresses DNS, so neither
            # bracket nor paren form appears there -- but accepting (ip)
            # is cheap defensive coding for future-proofing.)
            _IP_PAT = (r"[\[\(](\d{1,3}(?:\.\d{1,3}){3}|"
                       r"[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})[\]\)]")
            br_m = re.search(_IP_PAT, rest)
            # Bare IP form.  Windows tracert lays the IP at line end
            # ("1  1ms 1ms 1ms 1.1.1.1") so the old anchor was \s*$.
            # Linux traceroute -n puts the IP right after the hop number
            # ("1  1.1.1.1  1.23 ms 1.56 ms 1.49 ms") -- mid-line, not
            # at end.  Anchor on whitespace/string boundary on BOTH sides
            # so both formats match; this also avoids false positives on
            # hostname tokens like 'edge-10.0.0.1.example.com' (the
            # trailing dot fails the right-side \s|$ check).
            _BARE = (r"(?:^|\s)(\d{1,3}(?:\.\d{1,3}){3}|"
                     r"[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?:\s|$)")
            bare_m = re.search(_BARE, rest)
            # ICMP-unreachable from an intermediate router: the hop
            # DID respond and carries an IP, but Windows tracert appends
            # a "报告: ..." (CN) or "reports: ..." (EN) annotation
            # AFTER the IP, so the IP sits mid-line and _BARE's $-anchor
            # misses it.  Anchor on the keyword to keep this fallback
            # conservative: refuses to fire on lines without the
            # explicit unreachable annotation, avoiding false matches on
            # IP-looking substrings inside hostnames.  The captured reason
            # text is stashed in the hop's `error` field so summarize_break
            # can render the actionable wording instead of the misleading
            # "断点无响应".
            _UNREACH = (r"\b(\d{1,3}(?:\.\d{1,3}){3}|"
                        r"[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})"
                        # Allow ']' between IP and keyword so a line like
                        # 'router.lan [192.168.1.1]  reports: ...' (DNS-on)
                        # still matches.  Pure '\s+' would fail because the
                        # ']' sits right after the IP.  Currently the codebase
                        # uses tracert -d which suppresses DNS so brackets
                        # don't appear -- this widening is defensive, future-
                        # proofing for if/when DNS resolution becomes an option.
                        r"[\]\s]+\s*(报告|reports?)\s*[:：]\s*(.+?)\s*$")
            unreach_m = re.search(_UNREACH, rest)

            # Extract the ICMP-unreachable reason text FIRST, independent
            # of which branch ends up supplying hop_ip.  Previously this
            # extraction lived inside the elif unreach_m: branch, which
            # meant a bracketed-IP line that also carried 'reports: ...'
            # would let br_m grab the IP first, silently dropping the
            # reason.  Decoupling here ensures the reason is captured
            # whenever the keyword is present, no matter the IP form.
            unreach_reason = None
            if unreach_m:
                unreach_reason = (unreach_m.group(2) + ": "
                                  + unreach_m.group(3).rstrip("。.")).strip()

            if br_m:
                hop_ip = br_m.group(1)
                pre    = rest[:br_m.start()].strip()
                words  = pre.split()
                host   = (words[-1]
                          if words and not re.match(r"^[\d.*\s]+$", words[-1])
                          else None)
            elif unreach_m:
                # MUST come before bare_m: the broadened _BARE now matches
                # mid-line IPs, so on an unreachable line like
                #   '2  2ms 2ms 2ms 202.96.1.1  report: ...'
                # bare_m would otherwise grab the IP first.  unreach_m's
                # IP capture group is identical so dispatching here keeps
                # behaviour unchanged for non-bracketed lines.
                hop_ip = unreach_m.group(1)
                host   = None
            elif bare_m:
                hop_ip = bare_m.group(1)
                host   = None
            else:
                hop_ip = None
                host   = None

            hop_rec = {
                "hop":      hop_num,
                "ip":       hop_ip,
                "hostname": host,
                "rtt_ms":   round(rtt, 1) if rtt is not None else None,
                "status":   "timeout_raw" if not hop_ip else "ok",
            }
            if unreach_reason:
                # Definitively THE break point: known IP + explicit
                # 'unreachable' reply.  Mark as 'break' directly so the
                # post-loop classifier propagates 'after' to subsequent
                # hops without further special-casing.
                hop_rec["status"] = "break"
                hop_rec["error"]  = unreach_reason
            hops.append(hop_rec)

    if not hops:
        return [{"hop": 1, "ip": None, "hostname": None, "rtt_ms": None,
                 "status": "break",
                 "error": "parsed 0 hops — command ran but output format unexpected"}]

    # Classify timeouts: hops AFTER the last successful hop are real "break";
    # hops BEFORE the last successful one are merely ICMP-filtered routers.
    last_ok = max((i for i, h in enumerate(hops) if h["status"] == "ok"), default=-1)
    found_break = False
    for i, h in enumerate(hops):
        if h["status"] == "timeout_raw":
            h["status"] = "filtered" if i <= last_ok else "break"
        if found_break:
            h["status"] = "after"
        elif h["status"] == "break":
            found_break = True

    return hops
