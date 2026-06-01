"""
diag_sem.py — global single-slot semaphore shared by ALL on-demand diagnostics.

Why one global sem (not per-feature)?
  ICMP diag, DNS diag and ad-hoc traceroute all hit the same physical link
  the user is investigating.  Running two in parallel:
    1. confounds results (the second probe's RTT will reflect the first
       probe's competing bandwidth / NIC queueing)
    2. inflates ping subprocess concurrency, which on Windows is the
       single biggest source of RTT skew (see MAX_TARGETS comment).
  A single Semaphore(1) acquired by every diagnostic entry point makes
  the "one diagnosis at a time, regardless of type" guarantee trivially
  correct without scattering coordination logic across modules.

Acquire rule (every diagnostic feature must follow):
  if not DIAG_TASK_SEM.acquire(blocking=False):
      on_error("当前有诊断任务正在进行，请稍后再试")
      return
  try:
      ...
  finally:
      DIAG_TASK_SEM.release()
"""
from __future__ import annotations

import threading

# Single global slot. Do NOT raise to >1 without revisiting every caller —
# multiple diagnostics in parallel breaks the rationale above.
DIAG_TASK_SEM = threading.Semaphore(1)
