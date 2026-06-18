"""Regression: webhook stats/deliveries APIs return stable JSON on DataStore errors."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import WebServer


class _BadDS:
    def get_webhook_delivery_stats(self):
        raise RuntimeError("boom")

    def get_last_webhook_failures(self, limit=5):
        raise RuntimeError("boom")

    def get_webhook_problem_deliveries(self, limit=50):
        raise RuntimeError("boom")

    def get_webhook_deliveries(self, **kwargs):
        raise RuntimeError("boom")


def _fetch_json(client, path):
    resp = client.get(path)
    body = json.loads(resp.get_data(as_text=True))
    return resp.status_code, body


def test_stats_stable_on_exception():
    ws = WebServer(port=0)
    ws._data_store = _BadDS()
    with ws._app.test_client() as client:
        code, body = _fetch_json(client, "/api/webhook/stats")
    ok = (
        code == 200
        and isinstance(body, dict)
        and body.get("stats") == {}
        and body.get("failures") == []
    )
    print(f"webhook stats stable JSON on DS error -> {ok} code={code} body={body}")
    return ok


def test_problem_deliveries_stable_on_exception():
    ws = WebServer(port=0)
    ws._data_store = _BadDS()
    with ws._app.test_client() as client:
        code, body = _fetch_json(
            client, "/api/webhook/deliveries?problem=1&limit=100")
    ok = code == 200 and body == []
    print(f"webhook problem deliveries stable JSON on DS error -> {ok} "
          f"code={code} body={body}")
    return ok


def test_deliveries_stable_on_exception():
    ws = WebServer(port=0)
    ws._data_store = _BadDS()
    with ws._app.test_client() as client:
        code, body = _fetch_json(client, "/api/webhook/deliveries?limit=10")
    ok = code == 200 and body == []
    print(f"webhook deliveries stable JSON on DS error -> {ok} code={code}")
    return ok


def main():
    results = [
        test_stats_stable_on_exception(),
        test_problem_deliveries_stable_on_exception(),
        test_deliveries_stable_on_exception(),
    ]
    if all(results):
        print("PASS verify_webhook_api_exception_stability")
        return 0
    print("FAIL verify_webhook_api_exception_stability")
    return 1


if __name__ == "__main__":
    sys.exit(main())
