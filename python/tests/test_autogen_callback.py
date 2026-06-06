"""Tests for AgentTrust SDK AutoGen Integration"""

import time
import unittest
from unittest.mock import MagicMock, patch

from agenttrustid.autogen_callback import (
    AgentTrustAutoGenToolWrapper,
    AgentTrustAutoGenMiddleware,
    agenttrust_wrap_tool,
    agenttrust_register_tool,
)
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


def sample_tool(query: str) -> str:
    """Search the web for a query."""
    return f"results for: {query}"


class TestAgentTrustAutoGenToolWrapperInit(unittest.TestCase):
    """Test AgentTrustAutoGenToolWrapper initialization."""

    def test_defaults(self):
        client = make_client()
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1"
        )

        self.assertEqual(wrapper.agent_id, "agent-1")
        self.assertEqual(wrapper.tool_name, "sample_tool")
        self.assertTrue(wrapper.block_on_deny)
        self.assertFalse(wrapper.fail_open)
        self.assertEqual(wrapper.max_input_chars, 200)
        self.assertIsNotNone(wrapper.session_id)

    def test_custom_tool_name(self):
        client = make_client()
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1",
            tool_name="custom_search",
        )
        self.assertEqual(wrapper.tool_name, "custom_search")

    def test_custom_session_id(self):
        client = make_client()
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1",
            session_id="sess-abc",
        )
        self.assertEqual(wrapper.session_id, "sess-abc")

    def test_preserves_function_metadata(self):
        client = make_client()
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1"
        )
        self.assertEqual(wrapper.__name__, "sample_tool")
        self.assertIn("Search the web", wrapper.__doc__)


class TestAgentTrustAutoGenToolWrapperCall(unittest.TestCase):
    """Test AgentTrustAutoGenToolWrapper.__call__ execution path."""

    def test_allowed_call_executes_and_returns_result(self):
        client = make_client()
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1"
        )

        result = wrapper("AI news")

        self.assertEqual(result, "results for: AI news")
        client.actions.check.assert_called_once()

    def test_check_called_with_correct_params(self):
        client = make_client()
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1",
            session_id="sess-1",
        )

        wrapper("test query")

        args = client.actions.check.call_args
        self.assertEqual(args.kwargs["agent_id"], "agent-1")
        self.assertEqual(args.kwargs["tool_name"], "sample_tool")
        self.assertEqual(args.kwargs["action"], "tool_call")
        self.assertEqual(args.kwargs["session_id"], "sess-1")

    def test_denied_raises_when_block_on_deny(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-2", confidence=0.99,
            guard_tier="fast", reason="tool blocked",
        ))
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1",
            block_on_deny=True,
        )

        with self.assertRaises(AgentTrustError) as ctx:
            wrapper("test")

        self.assertEqual(ctx.exception.code, "ACTION_DENIED")
        self.assertIn("denied", str(ctx.exception).lower())

    def test_denied_returns_message_when_block_off(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-3", confidence=0.99,
            guard_tier="fast", reason="denied",
        ))
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1",
            block_on_deny=False,
        )

        result = wrapper("test")

        self.assertIn("denied", result.lower())

    def test_guardian_unreachable_fail_closed(self):
        client = make_client(check_error=ConnectionError("timeout"))
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1",
            fail_open=False,
        )

        with self.assertRaises(AgentTrustError) as ctx:
            wrapper("test")

        self.assertEqual(ctx.exception.code, "GUARDIAN_UNAVAILABLE")

    def test_guardian_unreachable_fail_open(self):
        client = make_client(check_error=ConnectionError("timeout"))
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1",
            fail_open=True,
        )

        result = wrapper("test")

        self.assertEqual(result, "results for: test")

    def test_duration_tracking(self):
        client = make_client()

        def slow_tool(q: str) -> str:
            time.sleep(0.05)
            return "done"

        wrapper = AgentTrustAutoGenToolWrapper(
            func=slow_tool, client=client, agent_id="agent-1"
        )

        wrapper("test")

        events = wrapper._telemetry._buffer
        end_events = [e for e in events if e["event_type"] == "tool_end"]
        self.assertEqual(len(end_events), 1)
        self.assertGreaterEqual(end_events[0]["duration_ms"], 40)
        self.assertTrue(end_events[0]["success"])

    def test_input_truncation(self):
        client = make_client()
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1",
            max_input_chars=10,
        )

        wrapper("a" * 500)

        args = client.actions.check.call_args
        summary = args.kwargs["tool_input_summary"]
        self.assertLessEqual(len(summary), 10)

    def test_telemetry_reports_on_success(self):
        client = make_client()
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1"
        )

        wrapper("query")

        events = wrapper._telemetry._buffer
        end_events = [e for e in events if e["event_type"] == "tool_end"]
        self.assertEqual(len(end_events), 1)
        self.assertTrue(end_events[0]["success"])

    def test_telemetry_reports_on_error(self):
        client = make_client()

        def failing_tool(q: str) -> str:
            raise ValueError("bad input")

        wrapper = AgentTrustAutoGenToolWrapper(
            func=failing_tool, client=client, agent_id="agent-1"
        )

        with self.assertRaises(ValueError):
            wrapper("test")

        events = wrapper._telemetry._buffer
        err_events = [e for e in events if e["event_type"] == "tool_error"]
        self.assertEqual(len(err_events), 1)
        self.assertFalse(err_events[0]["success"])
        self.assertEqual(err_events[0]["error_type"], "ValueError")


class TestAtiWrapToolDecorator(unittest.TestCase):
    """Test agenttrust_wrap_tool decorator."""

    def test_decorator_wraps_function(self):
        client = make_client()

        @agenttrust_wrap_tool(client=client, agent_id="agent-1")
        def my_search(query: str) -> str:
            """My search tool."""
            return f"found: {query}"

        result = my_search("AI")

        self.assertEqual(result, "found: AI")
        self.assertEqual(my_search.__name__, "my_search")
        self.assertIn("My search tool", my_search.__doc__)

    def test_decorator_checks_with_guardian(self):
        client = make_client()

        @agenttrust_wrap_tool(client=client, agent_id="agent-1")
        def search(query: str) -> str:
            return query

        search("test")

        client.actions.check.assert_called_once()
        args = client.actions.check.call_args
        self.assertEqual(args.kwargs["tool_name"], "search")

    def test_decorator_denied_raises(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-4", confidence=0.99,
            guard_tier="fast", reason="blocked",
        ))

        @agenttrust_wrap_tool(client=client, agent_id="agent-1", block_on_deny=True)
        def dangerous(cmd: str) -> str:
            return cmd

        with self.assertRaises(AgentTrustError) as ctx:
            dangerous("rm -rf /")

        self.assertEqual(ctx.exception.code, "ACTION_DENIED")

    def test_decorator_denied_returns_message_when_block_off(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-5", confidence=0.99,
            guard_tier="fast", reason="denied",
        ))

        @agenttrust_wrap_tool(client=client, agent_id="agent-1", block_on_deny=False)
        def search(query: str) -> str:
            return query

        result = search("test")

        self.assertIn("denied", result.lower())

    def test_decorator_fail_open(self):
        client = make_client(check_error=ConnectionError("timeout"))

        @agenttrust_wrap_tool(client=client, agent_id="agent-1", fail_open=True)
        def search(query: str) -> str:
            return f"found: {query}"

        result = search("test")

        self.assertEqual(result, "found: test")

    def test_decorator_fail_closed(self):
        client = make_client(check_error=ConnectionError("timeout"))

        @agenttrust_wrap_tool(client=client, agent_id="agent-1", fail_open=False)
        def search(query: str) -> str:
            return query

        with self.assertRaises(AgentTrustError) as ctx:
            search("test")

        self.assertEqual(ctx.exception.code, "GUARDIAN_UNAVAILABLE")

    def test_decorator_custom_tool_name(self):
        client = make_client()

        @agenttrust_wrap_tool(client=client, agent_id="agent-1", tool_name="custom_name")
        def search(query: str) -> str:
            return query

        search("test")

        args = client.actions.check.call_args
        self.assertEqual(args.kwargs["tool_name"], "custom_name")

    def test_decorator_has_close_method(self):
        client = make_client()

        @agenttrust_wrap_tool(client=client, agent_id="agent-1")
        def search(query: str) -> str:
            return query

        search("test")
        self.assertTrue(hasattr(search, "close"))
        self.assertTrue(hasattr(search, "_telemetry"))

        search.close()
        self.assertTrue(search._telemetry._closed)

    def test_decorator_duration_tracking(self):
        client = make_client()

        @agenttrust_wrap_tool(client=client, agent_id="agent-1")
        def slow_tool(query: str) -> str:
            time.sleep(0.05)
            return "done"

        slow_tool("test")

        events = slow_tool._telemetry._buffer
        end_events = [e for e in events if e["event_type"] == "tool_end"]
        self.assertEqual(len(end_events), 1)
        self.assertGreaterEqual(end_events[0]["duration_ms"], 40)

    def test_decorator_input_truncation(self):
        client = make_client()

        @agenttrust_wrap_tool(client=client, agent_id="agent-1", max_input_chars=15)
        def search(query: str) -> str:
            return query

        search("a" * 300)

        args = client.actions.check.call_args
        summary = args.kwargs["tool_input_summary"]
        self.assertLessEqual(len(summary), 15)


class TestAgentTrustAutoGenMiddleware(unittest.TestCase):
    """Test AgentTrustAutoGenMiddleware."""

    def test_on_tool_call_allowed(self):
        client = make_client()
        mw = AgentTrustAutoGenMiddleware(client=client, agent_id="agent-1")

        result = mw.on_tool_call("web_search", "AI news")

        self.assertTrue(result)
        client.actions.check.assert_called_once()

    def test_on_tool_call_denied_raises(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-6", confidence=0.99,
            guard_tier="fast", reason="blocked",
        ))
        mw = AgentTrustAutoGenMiddleware(
            client=client, agent_id="agent-1", block_on_deny=True
        )

        with self.assertRaises(AgentTrustError) as ctx:
            mw.on_tool_call("dangerous_tool")

        self.assertEqual(ctx.exception.code, "ACTION_DENIED")

    def test_on_tool_call_denied_returns_false_when_block_off(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-7", confidence=0.99,
            guard_tier="fast", reason="denied",
        ))
        mw = AgentTrustAutoGenMiddleware(
            client=client, agent_id="agent-1", block_on_deny=False
        )

        result = mw.on_tool_call("search")

        self.assertFalse(result)

    def test_on_tool_result_reports_telemetry(self):
        client = make_client()
        mw = AgentTrustAutoGenMiddleware(client=client, agent_id="agent-1")

        mw.on_tool_result("search", success=True, duration_ms=150)

        events = mw._telemetry._buffer
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "tool_end")
        self.assertEqual(events[0]["duration_ms"], 150)
        self.assertTrue(events[0]["success"])

    def test_on_tool_result_reports_error(self):
        client = make_client()
        mw = AgentTrustAutoGenMiddleware(client=client, agent_id="agent-1")

        mw.on_tool_result(
            "search", success=False, duration_ms=50, error_type="TimeoutError"
        )

        events = mw._telemetry._buffer
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "tool_error")
        self.assertFalse(events[0]["success"])
        self.assertEqual(events[0]["error_type"], "TimeoutError")

    def test_close_flushes_telemetry(self):
        client = make_client()
        mw = AgentTrustAutoGenMiddleware(client=client, agent_id="agent-1")

        mw.on_tool_result("search", success=True, duration_ms=100)
        mw.close()

        self.assertEqual(len(mw._telemetry._buffer), 0)
        self.assertTrue(mw._telemetry._closed)

    def test_context_manager(self):
        client = make_client()

        with AgentTrustAutoGenMiddleware(client=client, agent_id="agent-1") as mw:
            mw.on_tool_result("search", success=True, duration_ms=100)

        self.assertTrue(mw._telemetry._closed)

    def test_input_truncation(self):
        client = make_client()
        mw = AgentTrustAutoGenMiddleware(
            client=client, agent_id="agent-1", max_input_chars=20
        )

        mw.on_tool_call("search", "x" * 500)

        args = client.actions.check.call_args
        summary = args.kwargs["tool_input_summary"]
        self.assertLessEqual(len(summary), 20)


class TestAtiRegisterTool(unittest.TestCase):
    """Test agenttrust_register_tool helper."""

    def test_returns_wrapped_function(self):
        client = make_client()
        agent = MagicMock()
        # Simulate agent without register methods
        del agent.register_for_llm
        del agent.register_for_execution

        wrapped = agenttrust_register_tool(
            agent=agent, func=sample_tool, client=client, agent_id="agent-1"
        )

        self.assertIsInstance(wrapped, AgentTrustAutoGenToolWrapper)
        self.assertEqual(wrapped.tool_name, "sample_tool")

    def test_calls_register_for_llm_if_available(self):
        client = make_client()
        agent = MagicMock()
        # register_for_llm returns a decorator
        agent.register_for_llm.return_value = lambda f: f

        wrapped = agenttrust_register_tool(
            agent=agent, func=sample_tool, client=client, agent_id="agent-1"
        )

        agent.register_for_llm.assert_called_once()

    def test_calls_register_for_execution_if_available(self):
        client = make_client()
        agent = MagicMock()
        agent.register_for_llm.return_value = lambda f: f
        agent.register_for_execution.return_value = lambda f: f

        wrapped = agenttrust_register_tool(
            agent=agent, func=sample_tool, client=client, agent_id="agent-1"
        )

        agent.register_for_execution.assert_called_once()

    def test_custom_description(self):
        client = make_client()
        agent = MagicMock()
        agent.register_for_llm.return_value = lambda f: f

        agenttrust_register_tool(
            agent=agent, func=sample_tool, client=client, agent_id="agent-1",
            description="Custom description",
        )

        args = agent.register_for_llm.call_args
        self.assertEqual(args.kwargs["description"], "Custom description")


class TestAgentTrustAutoGenToolWrapperLifecycle(unittest.TestCase):
    """Test wrapper lifecycle / cleanup."""

    def test_close_flushes_telemetry(self):
        client = make_client()
        wrapper = AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1"
        )

        wrapper("test")
        wrapper.close()

        self.assertEqual(len(wrapper._telemetry._buffer), 0)
        self.assertTrue(wrapper._telemetry._closed)

    def test_context_manager(self):
        client = make_client()

        with AgentTrustAutoGenToolWrapper(
            func=sample_tool, client=client, agent_id="agent-1"
        ) as wrapper:
            wrapper("test")

        self.assertTrue(wrapper._telemetry._closed)


if __name__ == "__main__":
    unittest.main()
