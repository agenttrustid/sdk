"""Tests for AgentTrust SDK CrewAI Integration"""

import time
import unittest
from unittest.mock import MagicMock, patch

from agenttrustid.crewai_callback import (
    AgentTrustCrewAIToolWrapper,
    AgentTrustCrewAICallback,
    agenttrust_protect_crew,
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


def make_tool(name="web_search", description="Search the web", result="search result"):
    """Create a mock CrewAI tool."""
    tool = MagicMock()
    tool.name = name
    tool.description = description
    tool._run.return_value = result
    return tool


class TestAgentTrustCrewAIToolWrapperInit(unittest.TestCase):
    """Test AgentTrustCrewAIToolWrapper initialization."""

    def test_defaults(self):
        client = make_client()
        tool = make_tool()
        wrapper = AgentTrustCrewAIToolWrapper(tool=tool, client=client, agent_id="agent-1")

        self.assertEqual(wrapper.agent_id, "agent-1")
        self.assertEqual(wrapper.name, "web_search")
        self.assertEqual(wrapper.description, "Search the web")
        self.assertTrue(wrapper.block_on_deny)
        self.assertFalse(wrapper.fail_open)
        self.assertEqual(wrapper.max_input_chars, 200)
        self.assertIsNotNone(wrapper.session_id)

    def test_custom_session_id(self):
        client = make_client()
        tool = make_tool()
        wrapper = AgentTrustCrewAIToolWrapper(
            tool=tool, client=client, agent_id="agent-1", session_id="sess-abc"
        )
        self.assertEqual(wrapper.session_id, "sess-abc")

    def test_proxies_tool_name(self):
        client = make_client()
        tool = make_tool(name="calculator")
        wrapper = AgentTrustCrewAIToolWrapper(tool=tool, client=client, agent_id="agent-1")
        self.assertEqual(wrapper.name, "calculator")


class TestAgentTrustCrewAIToolWrapperRun(unittest.TestCase):
    """Test AgentTrustCrewAIToolWrapper._run execution path."""

    def test_allowed_tool_executes_and_returns_result(self):
        client = make_client()
        tool = make_tool(result="42")
        wrapper = AgentTrustCrewAIToolWrapper(tool=tool, client=client, agent_id="agent-1")

        result = wrapper._run("2+2")

        self.assertEqual(result, "42")
        client.actions.check.assert_called_once()
        tool._run.assert_called_once_with("2+2")

    def test_check_called_with_correct_params(self):
        client = make_client()
        tool = make_tool(name="db_query")
        wrapper = AgentTrustCrewAIToolWrapper(
            tool=tool, client=client, agent_id="agent-1", session_id="sess-1"
        )

        wrapper._run("SELECT * FROM users")

        args = client.actions.check.call_args
        self.assertEqual(args.kwargs["agent_id"], "agent-1")
        self.assertEqual(args.kwargs["tool_name"], "db_query")
        self.assertEqual(args.kwargs["action"], "tool_call")
        self.assertEqual(args.kwargs["session_id"], "sess-1")

    def test_denied_tool_raises_when_block_on_deny(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-2", confidence=0.99,
            guard_tier="fast", reason="tool in deny list",
        ))
        tool = make_tool()
        wrapper = AgentTrustCrewAIToolWrapper(
            tool=tool, client=client, agent_id="agent-1", block_on_deny=True
        )

        with self.assertRaises(AgentTrustError) as ctx:
            wrapper._run("test input")

        self.assertEqual(ctx.exception.code, "ACTION_DENIED")
        self.assertIn("denied", str(ctx.exception).lower())
        # Tool should NOT have been called
        tool._run.assert_not_called()

    def test_denied_tool_returns_message_when_block_off(self):
        client = make_client(ActionCheckResult(
            allowed=False, check_id="chk-3", confidence=0.99,
            guard_tier="fast", reason="denied",
        ))
        tool = make_tool()
        wrapper = AgentTrustCrewAIToolWrapper(
            tool=tool, client=client, agent_id="agent-1", block_on_deny=False
        )

        result = wrapper._run("test input")

        self.assertIn("denied", result.lower())
        tool._run.assert_not_called()

    def test_guardian_unreachable_fail_closed(self):
        client = make_client(check_error=ConnectionError("timeout"))
        tool = make_tool()
        wrapper = AgentTrustCrewAIToolWrapper(
            tool=tool, client=client, agent_id="agent-1", fail_open=False
        )

        with self.assertRaises(AgentTrustError) as ctx:
            wrapper._run("test")

        self.assertEqual(ctx.exception.code, "GUARDIAN_UNAVAILABLE")

    def test_guardian_unreachable_fail_open(self):
        client = make_client(check_error=ConnectionError("timeout"))
        tool = make_tool(result="fallback result")
        wrapper = AgentTrustCrewAIToolWrapper(
            tool=tool, client=client, agent_id="agent-1", fail_open=True
        )

        result = wrapper._run("test")

        self.assertEqual(result, "fallback result")
        tool._run.assert_called_once()

    def test_duration_tracking(self):
        client = make_client()
        # Simulate a tool that takes some time
        def slow_run(*args, **kwargs):
            time.sleep(0.05)
            return "done"

        tool = make_tool()
        tool._run.side_effect = slow_run
        wrapper = AgentTrustCrewAIToolWrapper(tool=tool, client=client, agent_id="agent-1")

        wrapper._run("test")

        # Check telemetry event has duration
        events = wrapper._telemetry._buffer
        end_events = [e for e in events if e["event_type"] == "tool_end"]
        self.assertEqual(len(end_events), 1)
        self.assertGreaterEqual(end_events[0]["duration_ms"], 40)
        self.assertTrue(end_events[0]["success"])

    def test_input_truncation(self):
        client = make_client()
        tool = make_tool()
        wrapper = AgentTrustCrewAIToolWrapper(
            tool=tool, client=client, agent_id="agent-1", max_input_chars=10
        )

        wrapper._run("a" * 500)

        args = client.actions.check.call_args
        summary = args.kwargs["tool_input_summary"]
        self.assertLessEqual(len(summary), 10)

    def test_telemetry_reports_on_success(self):
        client = make_client()
        tool = make_tool(result="ok")
        wrapper = AgentTrustCrewAIToolWrapper(tool=tool, client=client, agent_id="agent-1")

        wrapper._run("query")

        events = wrapper._telemetry._buffer
        end_events = [e for e in events if e["event_type"] == "tool_end"]
        self.assertEqual(len(end_events), 1)
        self.assertTrue(end_events[0]["success"])
        self.assertIn("duration_ms", end_events[0])

    def test_telemetry_reports_on_error(self):
        client = make_client()
        tool = make_tool()
        tool._run.side_effect = ValueError("bad input")
        wrapper = AgentTrustCrewAIToolWrapper(tool=tool, client=client, agent_id="agent-1")

        with self.assertRaises(ValueError):
            wrapper._run("bad")

        events = wrapper._telemetry._buffer
        err_events = [e for e in events if e["event_type"] == "tool_error"]
        self.assertEqual(len(err_events), 1)
        self.assertFalse(err_events[0]["success"])
        self.assertEqual(err_events[0]["error_type"], "ValueError")

    def test_run_delegates_to_internal_run(self):
        client = make_client()
        tool = make_tool(result="via run")
        wrapper = AgentTrustCrewAIToolWrapper(tool=tool, client=client, agent_id="agent-1")

        result = wrapper.run("test")

        self.assertEqual(result, "via run")


class TestAgentTrustCrewAICallback(unittest.TestCase):
    """Test AgentTrustCrewAICallback step-level callbacks."""

    def test_task_start_records_event(self):
        client = make_client()
        cb = AgentTrustCrewAICallback(client=client, agent_id="agent-1")

        cb.on_task_start("research_task")

        events = cb._telemetry._buffer
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "task_start")
        self.assertEqual(events[0]["tool_name"], "research_task")

    def test_task_end_records_event(self):
        client = make_client()
        cb = AgentTrustCrewAICallback(client=client, agent_id="agent-1")

        cb.on_task_end("research_task", success=True)

        events = cb._telemetry._buffer
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "task_end")
        self.assertTrue(events[0]["success"])

    def test_step_duration_tracking(self):
        client = make_client()
        cb = AgentTrustCrewAICallback(client=client, agent_id="agent-1")

        cb.on_step_start("step-1", "thinking")
        time.sleep(0.05)
        cb.on_step_end("step-1", "thinking", success=True)

        events = cb._telemetry._buffer
        end_events = [e for e in events if e["event_type"] == "step_end"]
        self.assertEqual(len(end_events), 1)
        self.assertGreaterEqual(end_events[0]["duration_ms"], 40)

    def test_close_flushes_telemetry(self):
        client = make_client()
        cb = AgentTrustCrewAICallback(client=client, agent_id="agent-1")

        cb.on_task_start("test_task")
        cb.close()

        self.assertEqual(len(cb._telemetry._buffer), 0)
        self.assertTrue(cb._telemetry._closed)


class TestAtiProtectCrew(unittest.TestCase):
    """Test agenttrust_protect_crew helper."""

    def test_wraps_all_agent_tools(self):
        client = make_client()

        tool1 = make_tool(name="search")
        tool2 = make_tool(name="calculator")

        agent = MagicMock()
        agent.tools = [tool1, tool2]

        crew = MagicMock()
        crew.agents = [agent]

        agenttrust_protect_crew(crew, client=client, agent_id="agent-1")

        # Tools should now be wrapped
        self.assertEqual(len(agent.tools), 2)
        self.assertIsInstance(agent.tools[0], AgentTrustCrewAIToolWrapper)
        self.assertIsInstance(agent.tools[1], AgentTrustCrewAIToolWrapper)
        self.assertEqual(agent.tools[0].name, "search")
        self.assertEqual(agent.tools[1].name, "calculator")

    def test_wraps_multiple_agents(self):
        client = make_client()

        agent1 = MagicMock()
        agent1.tools = [make_tool(name="t1")]

        agent2 = MagicMock()
        agent2.tools = [make_tool(name="t2"), make_tool(name="t3")]

        crew = MagicMock()
        crew.agents = [agent1, agent2]

        agenttrust_protect_crew(crew, client=client, agent_id="agent-1")

        self.assertEqual(len(agent1.tools), 1)
        self.assertEqual(len(agent2.tools), 2)
        self.assertIsInstance(agent1.tools[0], AgentTrustCrewAIToolWrapper)
        self.assertIsInstance(agent2.tools[0], AgentTrustCrewAIToolWrapper)

    def test_handles_no_agents(self):
        client = make_client()
        crew = MagicMock()
        crew.agents = []

        # Should not raise
        agenttrust_protect_crew(crew, client=client, agent_id="agent-1")

    def test_handles_no_tools(self):
        client = make_client()
        agent = MagicMock()
        agent.tools = []

        crew = MagicMock()
        crew.agents = [agent]

        # Should not raise
        agenttrust_protect_crew(crew, client=client, agent_id="agent-1")
        self.assertEqual(len(agent.tools), 0)

    def test_shares_session_id(self):
        client = make_client()
        agent = MagicMock()
        agent.tools = [make_tool(name="t1"), make_tool(name="t2")]

        crew = MagicMock()
        crew.agents = [agent]

        agenttrust_protect_crew(
            crew, client=client, agent_id="agent-1", session_id="shared-sess"
        )

        self.assertEqual(agent.tools[0].session_id, "shared-sess")
        self.assertEqual(agent.tools[1].session_id, "shared-sess")


class TestAgentTrustCrewAIToolWrapperLifecycle(unittest.TestCase):
    """Test wrapper lifecycle / cleanup."""

    def test_close_flushes_telemetry(self):
        client = make_client()
        tool = make_tool()
        wrapper = AgentTrustCrewAIToolWrapper(tool=tool, client=client, agent_id="agent-1")

        wrapper._run("test")
        wrapper.close()

        self.assertEqual(len(wrapper._telemetry._buffer), 0)
        self.assertTrue(wrapper._telemetry._closed)

    def test_context_manager(self):
        client = make_client()
        tool = make_tool()

        with AgentTrustCrewAIToolWrapper(
            tool=tool, client=client, agent_id="agent-1"
        ) as wrapper:
            wrapper._run("test")

        self.assertTrue(wrapper._telemetry._closed)


if __name__ == "__main__":
    unittest.main()
