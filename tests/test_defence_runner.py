from defence.app import runner


def test_allowed_telemetry_action_is_accepted():
    result = runner.handle(
        {
            "action": "telemetry.read",
            "sensor_id": "A-01",
            "event_id": "evt-1",
            "flow_lpm": 7.25,
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
