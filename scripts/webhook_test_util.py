"""Shared helpers for webhook/outbox regression scripts."""
import os
import sys
import tempfile
import time
import urllib.error
from contextlib import contextmanager
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.data_store import DataStore
from src.webhook_outbox import WebhookOutboxDispatcher

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@contextmanager
def patch_connection_refused():
    """Force webhook HTTP open to fail like connection refused (no fixed port)."""

    def _raise_refused(req, timeout=10):
        raise urllib.error.URLError(
            ConnectionRefusedError(10061, "Connection refused"))

    with patch("src.alert_manager._ORIGINAL_HTTP_OPEN", side_effect=_raise_refused):
        yield


def default_cfg(**overrides):
    targets = overrides.pop("targets", None)
    base = {
        "webhook_url": "http://127.0.0.1:9/hook",
        "webhook_reminder_enabled": True,
        "webhook_reminder_interval_min": 1,
        "webhook_reminder_max_count": 0,
        "webhook_reminder_aggregate_enabled": True,
        "webhook_reminder_aggregate_threshold": 3,
        "webhook_include_trace": False,
        "webhook_trace_update_enabled": False,
    }
    base.update(overrides)

    class _Cfg:
        def get_setting(self, k):
            return base.get(k)

    if targets is not None:
        _Cfg.get_targets = lambda self: list(targets)

    return _Cfg()


def make_alerter(*, ds=None, assets_dir=None, targets=None, **cfg_kw):
    """AlertManager + DataStore + outbox dispatcher for webhook tests."""
    if targets is not None:
        cfg_kw["targets"] = targets
    if assets_dir is None:
        assets_dir = os.path.join(ROOT, "assets")
    if ds is None:
        td = tempfile.mkdtemp()
        ds = DataStore(db_path=os.path.join(td, "t.db"))
        ds._schema_ready.wait(timeout=5)
    a = AlertManager(enabled=False, assets_dir=assets_dir)
    a.set_config(default_cfg(**cfg_kw))
    a.set_data_store(ds)
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)
    return a, disp, ds


def install_push_capture(a, calls, disp=None):
    def _send(url, event, target, ip, status, message, ts_str,
              extra=None, **kw):
        calls.append({
            "event": event, "target": target, "message": message,
            "extra": extra, **kw,
        })

    a._send_webhook = staticmethod(_send)

    def _flush(n=8, delay=0.02):
        d = disp or WebhookOutboxDispatcher(a)
        for _ in range(n):
            d._tick()
            time.sleep(delay)

    return _flush
