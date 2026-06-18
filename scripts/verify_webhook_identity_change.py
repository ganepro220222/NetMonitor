"""Regression: stale webhook outbox rows must not deliver after identity change."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter, install_push_capture


def _row(ds, delivery_id):
    r = next(
        x for x in ds.get_webhook_deliveries(limit=200)
        if x["delivery_id"] == delivery_id)
    d = dict(r)
    d["payload_json"] = json.dumps(d.pop("payload", {}), ensure_ascii=False)
    return d


def _state(ds, delivery_id):
    r = ds._read_conn().execute(
        "SELECT delivery_state, last_error FROM webhook_outbox "
        "WHERE delivery_id=?",
        (delivery_id,)).fetchone()
    return tuple(r) if r else None


def test_reseed_drops_stale_pending_alert_red():
    """Reseed with new label/IP must not deliver old pending alert_red."""
    a, disp, ds = make_alerter(
        targets=[{"id": "t", "label": "OLD", "ip": "10.0.0.1"}])
    calls = []
    install_push_capture(a, calls, disp)
    a.on_status_change("t", "OLD", "10.0.0.1", "red")
    old_did = next(
        r["delivery_id"] for r in ds.get_webhook_deliveries(limit=50)
        if r["target_id"] == "t" and r["event"] == "alert_red")

    a.reseed_webhook_incidents(
        [{"id": "t", "label": "NEW", "ip": "10.0.0.2"}], set())

    class _NewCfg:
        def get_setting(self, k):
            return "http://127.0.0.1:9/hook" if k == "webhook_url" else None

        def get_targets(self):
            return [{"id": "t", "label": "NEW", "ip": "10.0.0.2"}]

    a.set_config(_NewCfg())

    st_before = _state(ds, old_did)
    disp._deliver_one(_row(ds, old_did), time.time())
    sent = [c for c in calls if c.get("delivery_id") == old_did]
    st_after = _state(ds, old_did)

    dropped = st_before == ("dropped_stale", "stale_identity") or (
        st_after[0] == "dropped_stale"
        and "stale_identity" in (st_after[1] or ""))
    not_sent = not sent
    ok = dropped and not_sent
    print(f"  reseed stale identity dropped: {ok}  "
          f"before={st_before} after={st_after} sent={len(sent)}")
    return ok


def test_label_change_blocks_delivery():
    """Label-only edit must block delivering frozen OLD payload."""
    a, disp, ds = make_alerter(
        targets=[{"id": "t", "label": "OLD", "ip": "10.0.0.1"}])
    calls = []
    install_push_capture(a, calls, disp)
    a.on_status_change("t", "OLD", "10.0.0.1", "red")
    old_did = next(
        r["delivery_id"] for r in ds.get_webhook_deliveries(limit=50)
        if r["target_id"] == "t")

    class _Cfg:
        def get_setting(self, k):
            return "http://127.0.0.1:9/hook" if k == "webhook_url" else None

        def get_targets(self):
            return [{"id": "t", "label": "NEW", "ip": "10.0.0.1"}]

    a.set_config(_Cfg())
    ds.bump_target_generation("t")
    a.on_target_identity_changed("t")

    disp._deliver_one(_row(ds, old_did), time.time())
    sent = [c for c in calls if c.get("delivery_id") == old_did]
    st = _state(ds, old_did)
    ok = (
        not sent
        and st[0] == "dropped_stale"
        and "stale_identity" in (st[1] or "")
    )
    print(f"  label change blocks stale delivery: {ok}  state={st}")
    return ok


def test_same_identity_still_delivers():
    """Control: unchanged identity should still deliver pending alert_red."""
    a, disp, ds = make_alerter(
        targets=[{"id": "t", "label": "GW", "ip": "10.0.0.1"}])
    calls = []
    install_push_capture(a, calls, disp)
    a.on_status_change("t", "GW", "10.0.0.1", "red")
    did = next(
        r["delivery_id"] for r in ds.get_webhook_deliveries(limit=50)
        if r["target_id"] == "t")

    disp._deliver_one(_row(ds, did), time.time())
    sent = [c for c in calls if c.get("delivery_id") == did]
    st = _state(ds, did)
    ok = st == ("delivered", "") and sent and sent[0].get("target") == "GW"
    print(f"  same identity delivers: {ok}  state={st} target={sent[0].get('target') if sent else None}")
    return ok


def main():
    results = [
        ("reseed_drop", test_reseed_drops_stale_pending_alert_red()),
        ("label_change", test_label_change_blocks_delivery()),
        ("same_identity", test_same_identity_still_delivers()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All webhook identity change checks passed.")


if __name__ == "__main__":
    main()
