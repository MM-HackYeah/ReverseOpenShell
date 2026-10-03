import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from defence.app.exploit import build_vendor_exploit
from defence.app import runner


def test_allowed_vendor_telemetry_is_parsed(monkeypatch, tmp_path):
    monkeypatch.setenv("DEMO_ATTACK_REPORT_PATH", str(tmp_path / "attack-report.json"))
    result = runner.handle(
        {
            "action": "telemetry.read",
            "sensor_id": "A-01",
            "event_id": "evt-1",
            "vendor_document": "flow_lpm: 7.25\n",
        }
    )
    assert result["status"] == "accepted"
    assert result["action"] == "telemetry.read"
    assert result["flow_lpm"] == 7.25


def test_runner_rejects_unsupported_action():
    try:
        runner.handle(
            {
                "action": "telemetry.write",
                "sensor_id": "A-01",
                "event_id": "evt-attack",
                "flow_lpm": 7,
            }
        )
    except ValueError as exc:
        assert str(exc) == "unsupported action"
    else:
        raise AssertionError("runner must reject unsupported ingress actions")


def test_unsafe_vendor_yaml_exploit_succeeds_unconfined(monkeypatch, tmp_path):
    received = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", "0"))
            received.append(self.rfile.read(length))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    canary = tmp_path / "canary.secret"
    setpoint = tmp_path / "setpoint.json"
    report = tmp_path / "attack-report.json"
    canary.write_text("SYNTHETIC-CANARY-NOT-A-REAL-SECRET")
    setpoint.write_text('{"setpoint_lpm":40}')
    monkeypatch.setenv("DEMO_CANARY_PATH", str(canary))
    monkeypatch.setenv("DEMO_SETPOINT_PATH", str(setpoint))
    monkeypatch.setenv("DEMO_ATTACK_REPORT_PATH", str(report))
    monkeypatch.setenv(
        "DEMO_EXFIL_URL", f"http://127.0.0.1:{server.server_port}/collect"
    )
    monkeypatch.setenv("DEMO_EXFIL_TOKEN", "test-collector-token")
    try:
        result = runner.handle(
            {
                "action": "telemetry.read",
                "sensor_id": "A-01",
                "event_id": "evt-exploit",
                "vendor_document": build_vendor_exploit(),
            }
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result["status"] == "parser_compromised"
    assert result["attack_report"] == {
        "secret_read": "succeeded",
        "exfiltration": "sent_http_204",
        "setpoint_write": "succeeded",
    }
    assert sum(map(len, received)) > 0
    assert json.loads(setpoint.read_text()) == {"setpoint_lpm": 9999}
