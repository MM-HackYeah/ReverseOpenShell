import asyncio
import sys
import types

from defence.app.classifier import classify_sensor_event


def test_defence_jev_choice_is_capped_by_allowed_action(monkeypatch):
    monkeypatch.setenv("BACKBOARD_API_KEY", "test-key")
    observed = {}
    install_fake_backboard(monkeypatch, "read", 0.98, observed)

    result = asyncio.run(
        classify_sensor_event(
            "sensor-a",
            "telemetry.read",
            {"vendor_document": "flow_lpm: 7.25\n"},
        )
    )

    assert observed["choices"] == ["untrusted", "read"]
    assert result == ("read", "jev", 0.98)


def test_low_jev_confidence_downgrades_defence_read(monkeypatch):
    monkeypatch.setenv("BACKBOARD_API_KEY", "test-key")
    monkeypatch.setenv("DEFENCE_JEV_MIN_CONFIDENCE", "0.70")
    install_fake_backboard(monkeypatch, "read", 0.25)

    result = asyncio.run(
        classify_sensor_event(
            "sensor-a",
            "telemetry.read",
            {"vendor_document": "flow_lpm: 7.25\n"},
        )
    )

    assert result == ("untrusted", "jev", 0.25)


def test_invalid_jev_result_fails_closed(monkeypatch):
    monkeypatch.setenv("BACKBOARD_API_KEY", "test-key")
    install_fake_backboard(monkeypatch, "write", 0.99)

    result = asyncio.run(
        classify_sensor_event(
            "sensor-a",
            "telemetry.read",
            {"vendor_document": "flow_lpm: 7.25\n"},
        )
    )

    assert result == ("untrusted", "classifier-error", None)


def test_action_without_base_tier_skips_jev(monkeypatch):
    monkeypatch.setenv("BACKBOARD_API_KEY", "test-key")

    result = asyncio.run(
        classify_sensor_event(
            "sensor-a",
            "telemetry.delete",
            {"vendor_document": "flow_lpm: 7.25\n"},
        )
    )

    assert result == ("untrusted", "rules", None)


def install_fake_backboard(monkeypatch, tier, confidence, observed=None):
    class FakeClient:
        def __init__(self, api_key):
            assert api_key == "test-key"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def send_message(self, content, **kwargs):
            assert kwargs["llm_provider"] == "typesafe"
            assert kwargs["stream"] is False
            criteria = kwargs["system_one"]["questions"]["trust_tier"]["criteria"]
            if observed is not None:
                observed["choices"] = list(criteria)
            answer = {"choice": tier}
            if confidence is not None:
                answer["confidence"] = confidence
            return types.SimpleNamespace(
                system_one=types.SimpleNamespace(
                    answers={"trust_tier": answer}
                )
            )

    monkeypatch.setitem(
        sys.modules,
        "backboard",
        types.SimpleNamespace(BackboardClient=FakeClient),
    )
