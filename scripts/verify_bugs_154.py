"""Regression: legacy NULL alert ping_type resolves from targets_meta (Bug 154)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.data_store import DataStore
from src.trace_policy import should_request_traceroute

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def _seed_http_open_red(path, tid="T", started=1000.0):
    """Open red alert with NULL ping_type and HTTP targets_meta (v11 legacy)."""
    ds = DataStore(path)
    ds._schema_ready.wait(timeout=5)
    ds.record_ping(
        target_id=tid, label="HTTP node", ip="example.com",
        ping_type="http", ts=started, status="red",
        latency_ms=None, loss_rate=1.0, probe_success=False,
    )
    ds.record_alert(
        target_id=tid, label="HTTP node", ip="example.com",
        ts=started, old_status="green", new_status="red",
        category="availability", ping_type="http",
    )
    ds.flush()
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE alert_events SET ping_type=NULL WHERE target_id=?", (tid,))
    conn.execute(
        "UPDATE targets_meta SET ping_type='http' WHERE target_id=?", (tid,))
    conn.commit()
    conn.close()
    ds.shutdown()
    return ds


def test_get_open_incidents_resolves_http_from_meta():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        _seed_http_open_red(path)
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        open_inc = ds.get_open_incidents(["T"])
        ds.shutdown()
        info = open_inc.get("T", {})
        ok = info.get("ping_type") == "http"
        print(f"Bug154 open incident ping_type from meta -> {ok} info={info}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_explicit_alert_ping_type_wins_over_meta():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        _seed_http_open_red(path)
        conn = sqlite3.connect(path)
        conn.execute(
            "UPDATE alert_events SET ping_type='tcp' WHERE target_id='T'")
        conn.commit()
        conn.close()
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        open_inc = ds.get_open_incidents(["T"])
        ds.shutdown()
        ok = open_inc["T"]["ping_type"] == "tcp"
        print(f"Bug154 explicit alert ping_type wins -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_reseed_trace_policy_not_icmp_for_http_legacy():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        _seed_http_open_red(path)
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        open_inc = ds.get_open_incidents(["T"])
        pt = open_inc["T"]["ping_type"]
        fr = open_inc["T"]["failure_reason"]
        a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
        a.set_data_store(ds)
        a.reseed_webhook_incidents(
            [{"id": "T", "label": "HTTP node", "ip": "example.com"}], set())
        inc = a._webhook_incidents.get("T")
        ds.shutdown()
        ok = (
            pt == "http"
            and not should_request_traceroute(pt, fr)
            and inc is not None
            and inc.ping_type == "http"
            and inc.trace_applicable is False
        )
        print(f"Bug154 reseed HTTP trace_applicable -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_v12_to_v13_migration_backfills_rows():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        _seed_http_open_red(path)
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA user_version=12")
        conn.commit()
        conn.close()
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT ping_type FROM alert_events WHERE target_id='T'"
        ).fetchone()
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        conn.close()
        ds.shutdown()
        ok = row[0] == "http" and ver >= 13
        print(f"Bug154 v12->v13 backfill row -> {ok} ping_type={row[0]} ver={ver}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_v11_legacy_db_migration():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        conn = sqlite3.connect(path)
        conn.executescript("""
            CREATE TABLE alert_events (
                id INTEGER PRIMARY KEY,
                target_id TEXT NOT NULL,
                label TEXT, ip TEXT, ts REAL NOT NULL,
                old_status TEXT, new_status TEXT, category TEXT,
                failure_reason TEXT, incident_id TEXT
            );
            CREATE TABLE targets_meta (
                target_id TEXT PRIMARY KEY,
                label TEXT, ip TEXT, ping_type TEXT, updated_at INTEGER
            );
            CREATE TABLE pings_raw (
                id INTEGER PRIMARY KEY,
                target_id TEXT NOT NULL,
                ts REAL NOT NULL,
                status TEXT NOT NULL,
                latency_ms REAL,
                loss_rate REAL,
                probe_success INTEGER,
                status_code INTEGER,
                failure_reason TEXT,
                ping_type TEXT
            );
            CREATE TABLE pings_hourly (
                id INTEGER PRIMARY KEY,
                target_id TEXT NOT NULL,
                hour_ts INTEGER NOT NULL,
                sample_n INTEGER NOT NULL,
                success_n INTEGER NOT NULL,
                lat_avg REAL, lat_max REAL, lat_min REAL,
                lat_p95 REAL, loss_rate REAL
            );
            CREATE TABLE cum_stats (
                target_id TEXT PRIMARY KEY,
                total INTEGER DEFAULT 0,
                success INTEGER DEFAULT 0,
                lat_avg REAL DEFAULT 0,
                lat_n INTEGER DEFAULT 0,
                updated_at INTEGER
            );
            CREATE TABLE traceroute_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id TEXT NOT NULL,
                label TEXT, ip TEXT, ts REAL NOT NULL,
                hops TEXT, incident_id TEXT
            );
            PRAGMA user_version = 11;
        """)
        conn.execute(
            "INSERT INTO targets_meta VALUES ('T', 'HTTP node', 'example.com', 'http', 1000)"
        )
        conn.execute(
            "INSERT INTO alert_events "
            "(target_id,label,ip,ts,old_status,new_status,category,"
            " failure_reason,incident_id) "
            "VALUES ('T','HTTP node','example.com',1000.0,'green','red',"
            "'availability','','INC-OLD')"
        )
        conn.commit()
        conn.close()

        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        conn = sqlite3.connect(path)
        pt_row = conn.execute(
            "SELECT ping_type FROM alert_events WHERE target_id='T'"
        ).fetchone()
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        conn.close()
        open_inc = ds.get_open_incidents(["T"])
        ds.shutdown()
        ok = (
            pt_row[0] == "http"
            and ver >= 13
            and open_inc["T"]["ping_type"] == "http"
        )
        print(f"Bug154 v11 legacy migration -> {ok} row={pt_row[0]} ver={ver}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_resolve_and_backfill():
    with open(DATA_STORE, encoding="utf-8") as f:
        full = f.read()
    open_block = full.split("def get_open_incidents", 1)[1].split(
        "def get_last_known_statuses", 1)[0]
    mig_block = full.split("# v11 → v12:", 1)[1].split(
        "def _backfill_incident_ids", 1)[0]
    ok = (
        "_resolve_alert_ping_type" in open_block
        and "_backfill_alert_ping_types" in mig_block
        and "v12 → v13" in mig_block
    )
    print(f"Bug154 source resolve + migration backfill -> {ok}")
    return ok


def main():
    results = [
        ("open_meta", test_get_open_incidents_resolves_http_from_meta()),
        ("explicit_wins", test_explicit_alert_ping_type_wins_over_meta()),
        ("reseed_trace", test_reseed_trace_policy_not_icmp_for_http_legacy()),
        ("v12_v13", test_v12_to_v13_migration_backfills_rows()),
        ("v11_mig", test_v11_legacy_db_migration()),
        ("source", test_source_resolve_and_backfill()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 154 checks passed.")


if __name__ == "__main__":
    main()
