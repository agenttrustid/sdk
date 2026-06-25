"""Coverage for AgentTrustGuard (public pre-flight check + telemetry wrapper)."""
import pytest
from unittest.mock import MagicMock

from agenttrustid.guard import AgentTrustGuard
from agenttrustid.exceptions import AgentTrustError


@pytest.fixture
def make_guard(monkeypatch):
    def _make(**kwargs):
        # Replace the telemetry reporter so no background flushing happens.
        monkeypatch.setattr("agenttrustid.guard.TelemetryReporter", lambda **kw: MagicMock())
        client = MagicMock()
        guard = AgentTrustGuard(client, agent_id="agt-1", **kwargs)
        return guard, client

    return _make


def _result(allowed=True, reason="", elevation_required=False, approval_id=None):
    r = MagicMock()
    r.allowed = allowed
    r.reason = reason
    r.elevation_required = elevation_required
    r.approval_id = approval_id
    return r


def test_check_allowed_returns_true(make_guard):
    g, client = make_guard()
    client.actions.check.return_value = _result(allowed=True)
    assert g.check("web_search") is True


def test_check_denied_blocks_by_default(make_guard):
    g, client = make_guard()
    client.actions.check.return_value = _result(allowed=False, reason="policy")
    with pytest.raises(AgentTrustError) as ei:
        g.check("delete_file")
    assert ei.value.code == "ACTION_DENIED"


def test_check_denied_elevation_required(make_guard):
    g, client = make_guard()
    client.actions.check.return_value = _result(
        allowed=False, reason="needs approval", elevation_required=True, approval_id="appr-9"
    )
    with pytest.raises(AgentTrustError) as ei:
        g.check("delete_file")
    assert ei.value.code == "ELEVATION_REQUIRED"
    assert ei.value.details.get("approval_id") == "appr-9"


def test_check_denied_no_block_returns_false(make_guard):
    g, client = make_guard(block_on_deny=False)
    client.actions.check.return_value = _result(allowed=False, reason="nope")
    assert g.check("x") is False


def test_check_truncates_long_input_summary(make_guard):
    g, client = make_guard()
    client.actions.check.return_value = _result(allowed=True)
    g.check("t", input_summary="a" * 500)
    assert len(client.actions.check.call_args.kwargs["tool_input_summary"]) == 200


def test_check_guardian_unreachable_raises_when_fail_closed(make_guard):
    g, client = make_guard(fail_open=False)
    client.actions.check.side_effect = RuntimeError("boom")
    with pytest.raises(AgentTrustError) as ei:
        g.check("x")
    assert ei.value.code == "GUARDIAN_UNAVAILABLE"


def test_check_guardian_unreachable_allows_when_fail_open(make_guard):
    g, client = make_guard(fail_open=True)
    client.actions.check.side_effect = RuntimeError("boom")
    assert g.check("x") is True


def test_report_adds_tool_end_event(make_guard):
    g, _ = make_guard()
    g.report("web_search", success=True, duration_ms=1200)
    event = g._telemetry.add_event.call_args[0][0]
    assert event["event_type"] == "tool_end"
    assert event["tool_name"] == "web_search"
    assert event["duration_ms"] == 1200


def test_report_error_includes_error_type(make_guard):
    g, _ = make_guard()
    g.report("web_search", success=False, error_type="Timeout")
    event = g._telemetry.add_event.call_args[0][0]
    assert event["event_type"] == "tool_error"
    assert event["error_type"] == "Timeout"


def test_context_manager_closes(make_guard):
    g, _ = make_guard()
    with g as ctx:
        assert ctx is g
    g._telemetry.close.assert_called_once()


def test_close_flushes_telemetry(make_guard):
    g, _ = make_guard()
    g.close()
    g._telemetry.close.assert_called_once()
