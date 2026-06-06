"""Tests for AgentTrust SDK LangChain Callback Handler"""

import unittest
from unittest.mock import MagicMock, patch
import uuid

from agenttrustid.callback import AgentTrustCallbackHandler
from agenttrustid.exceptions import AgentTrustError
from agenttrustid.models import ActionCheckResult


def make_client(check_result=None, check_error=None):
    """Create a mock AgentTrustClient with actions and telemetry APIs."""
    client = MagicMock()

    if check_error:
        client.actions.check.side_effect = check_error
    else:
        result = check_result or ActionCheckResult(
            allowed=True, check_id="chk-1", confidence=0.92, guard_tier="fast"
        )
        client.actions.check.return_value = result

    client.telemetry.report.return_value = {"accepted": True, "events_processed": 1}
    return client


class TestCallbackInit(unittest.TestCase):
    """Test AgentTrustCallbackHandler initialization."""

    def test_defaults(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1")

        self.assertEqual(handler.agent_id, "agent-1")
        self.assertTrue(handler.block_on_deny)
        self.assertFalse(handler.fail_open)
        self.assertFalse(handler.log_inputs)
        self.assertEqual(handler.max_input_chars, 200)
        self.assertIsNotNone(handler.session_id)

    def test_custom_session_id(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1", session_id="sess-abc")
        self.assertEqual(handler.session_id, "sess-abc")


class TestOnToolStart(unittest.TestCase):
    """Test on_tool_start callback."""

    def test_allowed_tool_proceeds(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1")
        run_id = uuid.uuid4()

        # Should not raise
        handler.on_tool_start(
            serialized={"name": "web_search"},
            input_str="find AI papers",
            run_id=run_id,
        )

        client.actions.check.assert_called_once()
        args = client.actions.check.call_args
        self.assertEqual(args.kwargs["agent_id"], "agent-1")
        self.assertEqual(args.kwargs["tool_name"], "web_search")
        self.assertEqual(args.kwargs["action"], "tool_call")

    def test_denied_tool_raises_when_block_on_deny(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-2", confidence=0.99,
            guard_tier="fast", reason="tool in deny list",
        ))
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1", block_on_deny=True)

        with self.assertRaises(AgentTrustError) as ctx:
            handler.on_tool_start(
                serialized={"name": "rm_rf"},
                input_str="/",
                run_id=uuid.uuid4(),
            )

        self.assertIn("denied", str(ctx.exception).lower())
        self.assertEqual(ctx.exception.code, "ACTION_DENIED")

    def test_denied_tool_no_raise_when_block_off(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-3", confidence=0.99,
            guard_tier="fast", reason="denied",
        ))
        handler = AgentTrustCallbackHandler(
            client, agent_id="agent-1", block_on_deny=False,
        )

        # Should not raise even though denied
        handler.on_tool_start(
            serialized={"name": "rm_rf"},
            input_str="/",
            run_id=uuid.uuid4(),
        )

    def test_guardian_unreachable_fail_closed(self):
        client = make_client(check_error=ConnectionError("timeout"))
        handler = AgentTrustCallbackHandler(
            client, agent_id="agent-1", fail_open=False,
        )

        with self.assertRaises(AgentTrustError) as ctx:
            handler.on_tool_start(
                serialized={"name": "web_search"},
                input_str="test",
                run_id=uuid.uuid4(),
            )

        self.assertEqual(ctx.exception.code, "GUARDIAN_UNAVAILABLE")

    def test_guardian_unreachable_fail_open(self):
        client = make_client(check_error=ConnectionError("timeout"))
        handler = AgentTrustCallbackHandler(
            client, agent_id="agent-1", fail_open=True,
        )

        # Should not raise — fail_open=True
        handler.on_tool_start(
            serialized={"name": "web_search"},
            input_str="test",
            run_id=uuid.uuid4(),
        )

    def test_input_not_logged_by_default(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1", log_inputs=False)

        handler.on_tool_start(
            serialized={"name": "search"},
            input_str="secret query data",
            run_id=uuid.uuid4(),
        )

        args = client.actions.check.call_args
        summary = args.kwargs["tool_input_summary"]
        # Should be char count, not actual content
        self.assertIn("chars", summary)
        self.assertNotIn("secret", summary)

    def test_input_truncated_when_log_inputs_true(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(
            client, agent_id="agent-1", log_inputs=True, max_input_chars=10,
        )

        handler.on_tool_start(
            serialized={"name": "search"},
            input_str="a" * 100,
            run_id=uuid.uuid4(),
        )

        args = client.actions.check.call_args
        summary = args.kwargs["tool_input_summary"]
        self.assertEqual(len(summary), 10)

    def test_records_tool_start_telemetry(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1")

        handler.on_tool_start(
            serialized={"name": "web_search"},
            input_str="test",
            run_id=uuid.uuid4(),
        )

        # Telemetry reporter should have buffered a tool_start event
        self.assertTrue(len(handler._telemetry._buffer) >= 1)
        event = handler._telemetry._buffer[0]
        self.assertEqual(event["event_type"], "tool_start")
        self.assertEqual(event["tool_name"], "web_search")


class TestOnToolEnd(unittest.TestCase):
    """Test on_tool_end callback."""

    def test_records_duration(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1")
        run_id = uuid.uuid4()

        # Start first
        handler.on_tool_start(
            serialized={"name": "search"},
            input_str="test",
            run_id=run_id,
        )

        # End
        handler.on_tool_end(
            output="result",
            run_id=run_id,
            name="search",
        )

        # Should have tool_start + tool_end events
        events = handler._telemetry._buffer
        end_events = [e for e in events if e["event_type"] == "tool_end"]
        self.assertEqual(len(end_events), 1)
        self.assertTrue(end_events[0]["success"])
        self.assertGreaterEqual(end_events[0]["duration_ms"], 0)


class TestOnToolError(unittest.TestCase):
    """Test on_tool_error callback."""

    def test_records_error_type(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1")
        run_id = uuid.uuid4()

        handler.on_tool_start(
            serialized={"name": "db_query"},
            input_str="SELECT *",
            run_id=run_id,
        )

        handler.on_tool_error(
            error=TimeoutError("connection timed out"),
            run_id=run_id,
            name="db_query",
        )

        events = handler._telemetry._buffer
        err_events = [e for e in events if e["event_type"] == "tool_error"]
        self.assertEqual(len(err_events), 1)
        self.assertFalse(err_events[0]["success"])
        self.assertEqual(err_events[0]["error_type"], "TimeoutError")


class TestOnChainEnd(unittest.TestCase):
    """Test on_chain_end callback."""

    def test_flushes_telemetry_on_top_level(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1")

        # Add some events
        handler._telemetry.add_event({"event_type": "tool_start", "tool_name": "test"})
        handler._telemetry.add_event({"event_type": "tool_end", "tool_name": "test"})

        # on_chain_end with no parent → flush
        handler.on_chain_end(
            outputs={"output": "done"},
            run_id=uuid.uuid4(),
            parent_run_id=None,
        )

        # Buffer should be cleared after flush
        self.assertEqual(len(handler._telemetry._buffer), 0)

    def test_does_not_flush_on_nested_chain(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1")

        handler._telemetry.add_event({"event_type": "tool_start", "tool_name": "test"})

        # on_chain_end with parent → don't flush yet
        handler.on_chain_end(
            outputs={"output": "done"},
            run_id=uuid.uuid4(),
            parent_run_id=uuid.uuid4(),
        )

        # Buffer should still have the event
        self.assertEqual(len(handler._telemetry._buffer), 1)


class TestClose(unittest.TestCase):
    """Test handler cleanup."""

    def test_close_flushes_and_stops_timer(self):
        client = make_client()
        handler = AgentTrustCallbackHandler(client, agent_id="agent-1")

        handler._telemetry.add_event({"event_type": "tool_start", "tool_name": "test"})
        handler.close()

        self.assertEqual(len(handler._telemetry._buffer), 0)
        self.assertTrue(handler._telemetry._closed)


if __name__ == "__main__":
    unittest.main()
