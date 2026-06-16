"""Reliable webhook outbox dispatcher (persistent queue + retry + ordering)."""
from __future__ import annotations

import json
import threading
import time
from typing import Any

# Retry backoff: 5s, 15s, 30s, 60s, 120s, 300s, then every 300s.
BACKOFF_SECONDS = (5, 15, 30, 60, 120, 300)
DISPATCH_INTERVAL_SEC = 2.0
CLOSED_SUMMARY_DELAY_SEC = 60
SENDING_LEASE_SEC = 120.0
COALESCE_EVENTS = frozenset({"alert_reminder", "diagnostic_update"})
REMINDER_MAX_ATTEMPTS = 12
DIAGNOSTIC_MAX_ATTEMPTS = 8


class WebhookDeliveryAborted(Exception):
    """Outbox delivery cancelled by ACK/pause/remove or gate before network send."""


def compute_next_attempt_ts(attempt_count: int, now: float | None = None) -> float:
    """Return the next retry timestamp after a failed attempt."""
    now = now or time.time()
    idx = min(max(attempt_count, 0), len(BACKOFF_SECONDS) - 1)
    return now + BACKOFF_SECONDS[idx]


def max_attempts_for_event(event: str) -> int:
    """0 means retry until delivered or dropped by gate/coalesce."""
    if event in COALESCE_EVENTS:
        return REMINDER_MAX_ATTEMPTS if event == "alert_reminder" else DIAGNOSTIC_MAX_ATTEMPTS
    return 0


class WebhookOutboxDispatcher:
    """Background dispatcher: fetch due rows, gate-check, send, retry."""

    def __init__(self, alert_manager):
        self._am = alert_manager
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        ds = self._am._data_store
        if ds is not None:
            ds.recover_orphaned_sending_webhook_outbox()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="webhook-outbox-dispatch")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def wake(self) -> None:
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            if self._wake.wait(timeout=DISPATCH_INTERVAL_SEC):
                self._wake.clear()
            if self._stop.is_set():
                break
            try:
                self._tick()
            except Exception as e:
                print(f"[WebhookOutbox] dispatch error: {e}")

    def _tick(self) -> None:
        am = self._am
        ds = am._data_store
        if ds is None or not am._webhook_configured():
            return
        now = time.time()
        ds.recover_stale_sending_webhook_outbox(now, SENDING_LEASE_SEC)
        ds.drop_red_blocked_closed_summary(now, CLOSED_SUMMARY_DELAY_SEC)
        rows = ds.fetch_deliverable_webhook_outbox(now, limit=50)
        for row in rows:
            self._deliver_one(row, now)

    def _deliver_one(self, row: dict, now: float) -> None:
        ds = self._am._data_store
        delivery_id = row["delivery_id"]
        if not ds.claim_webhook_outbox(delivery_id, now):
            return

        prepared = self._am.prepare_outbox_delivery(row, now)
        if prepared is None:
            ds.finish_webhook_outbox(
                delivery_id, state="dropped_stale", error="gate_or_rebuild",
                now=now, only_if_sending=True)
            return

        if not self._am.outbox_row_gate_ok(row):
            ds.finish_webhook_outbox(
                delivery_id, state="dropped_stale", error="gate_or_rebuild",
                now=now, only_if_sending=True)
            return

        event, target, ip, status, message, extra, meta = prepared
        url = (self._am._config.get_setting("webhook_url") or "").strip()
        attempt = int(row.get("attempt_count") or 0) + 1
        gate = self._am.outbox_row_gate(row)
        try:
            self._am._send_webhook(
                url, event, target, ip, status, message,
                meta.get("event_ts_str", ""),
                extra,
                event_ts=meta.get("event_ts"),
                queued_ts=row.get("first_queued_ts"),
                sent_ts=now,
                attempt=attempt,
                delivery_id=delivery_id,
                gate=gate,
            )
        except WebhookDeliveryAborted:
            ds.finish_webhook_outbox(
                delivery_id, state="dropped_stale", error="gate_or_rebuild",
                now=now, only_if_sending=True)
            return
        except Exception as e:
            self._handle_failure(row, now, str(e))
            return

        if not self._am.outbox_row_gate_ok(row):
            ds.finish_webhook_outbox(
                delivery_id, state="dropped_stale", error="gate_or_rebuild",
                now=now, only_if_sending=True)
            return

        ds.finish_webhook_outbox(
            delivery_id, state="delivered", error="", now=now,
            attempt_count=attempt, only_if_sending=True)

    def _handle_failure(self, row: dict, now: float, err: str) -> None:
        ds = self._am._data_store
        delivery_id = row["delivery_id"]
        event = row.get("event") or ""
        attempt = int(row.get("attempt_count") or 0) + 1
        max_a = int(row.get("max_attempts") or 0)
        if event == "alert_red" and ds is not None:
            recovery = ds.find_pending_recovery(
                row.get("order_key") or "",
                row.get("incident_id") or "",
            )
            age = now - float(row.get("first_queued_ts") or now)
            if recovery and age >= CLOSED_SUMMARY_DELAY_SEC:
                if ds.finish_webhook_outbox(
                        delivery_id, state="dropped_stale",
                        error="superseded_by_closed_summary", now=now,
                        only_if_sending=True):
                    self.wake()
                return
        if max_a and attempt >= max_a:
            ds.finish_webhook_outbox(
                delivery_id, state="failed_permanent", error=err, now=now,
                attempt_count=attempt, only_if_sending=True)
            return
        next_ts = compute_next_attempt_ts(attempt, now)
        ds.finish_webhook_outbox(
            delivery_id, state="pending", error=err, now=now,
            attempt_count=attempt, next_attempt_ts=next_ts,
            only_if_sending=True)
