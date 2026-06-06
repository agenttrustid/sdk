"""AgentTrust SDK CrewAI Integration

Wraps CrewAI tools with AgentTrust ID Guardian security checks and telemetry.

Install: pip install agenttrustid[crewai]

Usage:
    from agenttrustid import AgentTrustClient
    from agenttrustid.crewai_callback import AgentTrustCrewAIToolWrapper, agenttrust_protect_crew

    client = AgentTrustClient.from_env()

    # Wrap a single tool
    wrapped = AgentTrustCrewAIToolWrapper(tool=my_tool, client=client, agent_id="agent-123")

    # Or wrap all tools in a crew at once
    agenttrust_protect_crew(crew, client=client, agent_id="agent-123")
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .exceptions import AgentTrustError
from .telemetry import TelemetryReporter

logger = logging.getLogger("agenttrustid.crewai")

try:
    from crewai.tools import BaseTool as _CrewAIBaseTool
except ImportError:
    # Provide a stub so the module can be imported without crewai
    class _CrewAIBaseTool:  # type: ignore[no-redef]
        """Stub — install crewai for real tool support."""
        name: str = ""
        description: str = ""

        def _run(self, *args, **kwargs):
            raise NotImplementedError


class AgentTrustCrewAIToolWrapper:
    """Wraps a CrewAI tool with AgentTrust ID Guardian security checks.

    Before each tool execution, checks with Guardian. After execution,
    reports telemetry (success/failure + duration). On denial, raises
    AgentTrustError (if block_on_deny) or returns a denial message.

    Args:
        tool: CrewAI BaseTool instance to wrap
        client: AgentTrustClient instance (must have api_key set)
        agent_id: Registered agent ID
        session_id: Session ID for correlation (auto-generated if not provided)
        block_on_deny: If True, denied actions raise AgentTrustError (default: True)
        fail_open: If True, allow actions when Guardian is unreachable (default: False)
        max_input_chars: Max characters for input summaries (default: 200)

    Usage:
        from agenttrustid.crewai_callback import AgentTrustCrewAIToolWrapper

        wrapped_tool = AgentTrustCrewAIToolWrapper(
            tool=my_tool,
            client=ati_client,
            agent_id="agent-123",
        )
        # Use wrapped_tool in place of my_tool in your crew
    """

    def __init__(
        self,
        tool,
        client,
        agent_id: str,
        session_id: str = None,
        block_on_deny: bool = True,
        fail_open: bool = False,
        max_input_chars: int = 200,
    ):
        self._tool = tool
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.block_on_deny = block_on_deny
        self.fail_open = fail_open
        self.max_input_chars = max_input_chars

        # Proxy tool identity so CrewAI sees the same name/description
        self.name = getattr(tool, "name", "unknown")
        self.description = getattr(tool, "description", "")

        # Background telemetry reporter
        self._telemetry = TelemetryReporter(
            telemetry_api=client.telemetry,
            agent_id=agent_id,
            session_id=self.session_id,
        )

    # ------------------------------------------------------------------
    # Core execution path
    # ------------------------------------------------------------------

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the wrapped tool with Guardian check and telemetry."""
        tool_name = self.name

        # Build input summary (privacy: truncated)
        raw_input = " ".join(str(a) for a in args)
        if kwargs:
            raw_input += " " + " ".join(f"{k}={v}" for k, v in kwargs.items())
        input_summary = raw_input[: self.max_input_chars] if raw_input else ""

        # 1. Pre-flight Guardian check
        allowed = self._check(tool_name, input_summary)
        if not allowed:
            denial_msg = f"Tool '{tool_name}' denied by AgentTrust ID Guardian"
            if self.block_on_deny:
                raise AgentTrustError(
                    denial_msg,
                    code="ACTION_DENIED",
                    details={"tool_name": tool_name},
                )
            return denial_msg

        # 2. Execute the original tool
        start = time.monotonic()
        success = True
        error_type = None
        try:
            result = self._tool._run(*args, **kwargs)
            return result
        except Exception as exc:
            success = False
            error_type = type(exc).__name__
            raise
        finally:
            # 3. Report telemetry
            duration_ms = int((time.monotonic() - start) * 1000)
            self._report(tool_name, success, duration_ms, error_type)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Public run method — delegates to _run."""
        return self._run(*args, **kwargs)

    # ------------------------------------------------------------------
    # Delegate attribute access so CrewAI sees the original tool metadata
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        """Proxy unknown attributes to the wrapped tool."""
        return getattr(self._tool, name)

    # ------------------------------------------------------------------
    # Guardian check + telemetry helpers
    # ------------------------------------------------------------------

    def _check(self, tool_name: str, input_summary: str) -> bool:
        """Pre-flight check. Returns True if allowed."""
        # Truncate for privacy
        if len(input_summary) > self.max_input_chars:
            input_summary = input_summary[: self.max_input_chars]

        try:
            result = self.client.actions.check(
                agent_id=self.agent_id,
                action="tool_call",
                tool_name=tool_name,
                tool_input_summary=input_summary,
                session_id=self.session_id,
            )
            if not result.allowed:
                logger.warning(
                    "AgentTrust ID denied tool call: tool=%s reason=%s",
                    tool_name,
                    result.reason,
                )
                return False
            return True
        except AgentTrustError:
            raise
        except Exception as e:
            logger.error("AgentTrust ID action-check failed: %s", e)
            if not self.fail_open:
                raise AgentTrustError(
                    f"Guardian unreachable and fail_open=False: {e}",
                    code="GUARDIAN_UNAVAILABLE",
                )
            return True

    def _report(
        self,
        tool_name: str,
        success: bool,
        duration_ms: int,
        error_type: str = None,
    ) -> None:
        """Report telemetry event (fire-and-forget)."""
        try:
            event = {
                "event_type": "tool_end" if success else "tool_error",
                "tool_name": tool_name,
                "duration_ms": duration_ms,
                "success": success,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if error_type:
                event["error_type"] = error_type
            self._telemetry.add_event(event)
        except Exception as e:
            logger.warning("AgentTrust ID telemetry error: %s", e)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Flush telemetry. Call when agent is done."""
        self._telemetry.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        try:
            self._telemetry.close()
        except Exception:
            pass


class AgentTrustCrewAICallback:
    """Step-level callback for CrewAI task/step events.

    Provides hooks that can be attached to a CrewAI Crew to track
    task start/end and step-level telemetry.

    Args:
        client: AgentTrustClient instance
        agent_id: Registered agent ID
        session_id: Session ID for correlation (auto-generated if not provided)

    Usage:
        callback = AgentTrustCrewAICallback(client=ati_client, agent_id="agent-123")
        crew = Crew(agents=[...], tasks=[...])
        # Attach to step hooks manually or use agenttrust_protect_crew
    """

    def __init__(
        self,
        client,
        agent_id: str,
        session_id: str = None,
    ):
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())

        self._telemetry = TelemetryReporter(
            telemetry_api=client.telemetry,
            agent_id=agent_id,
            session_id=self.session_id,
        )
        self._step_starts: Dict[str, float] = {}

    def on_task_start(self, task_name: str) -> None:
        """Called when a CrewAI task starts."""
        self._telemetry.add_event({
            "event_type": "task_start",
            "tool_name": task_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def on_task_end(self, task_name: str, success: bool = True) -> None:
        """Called when a CrewAI task ends."""
        self._telemetry.add_event({
            "event_type": "task_end",
            "tool_name": task_name,
            "success": success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def on_step_start(self, step_id: str, step_name: str = "") -> None:
        """Called when a CrewAI step starts."""
        # Prevent unbounded memory growth
        if len(self._step_starts) > 1000:
            self._step_starts.clear()
        self._step_starts[step_id] = time.monotonic()
        self._telemetry.add_event({
            "event_type": "step_start",
            "tool_name": step_name or step_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def on_step_end(
        self, step_id: str, step_name: str = "", success: bool = True
    ) -> None:
        """Called when a CrewAI step ends."""
        start = self._step_starts.pop(step_id, None)
        duration_ms = int((time.monotonic() - start) * 1000) if start else 0
        self._telemetry.add_event({
            "event_type": "step_end",
            "tool_name": step_name or step_id,
            "duration_ms": duration_ms,
            "success": success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def flush(self) -> None:
        """Flush all buffered telemetry."""
        self._telemetry.flush()

    def close(self) -> None:
        """Flush and close telemetry."""
        self._telemetry.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def agenttrust_protect_crew(
    crew,
    client,
    agent_id: str,
    session_id: str = None,
    block_on_deny: bool = True,
    fail_open: bool = False,
    max_input_chars: int = 200,
) -> None:
    """Wrap all tools in a CrewAI Crew with AgentTrust ID Guardian security.

    Iterates over every agent in the crew and replaces each tool with
    an AgentTrustCrewAIToolWrapper so that all tool calls go through Guardian
    checks and telemetry reporting.

    Args:
        crew: CrewAI Crew instance
        client: AgentTrustClient instance
        agent_id: Registered agent ID
        session_id: Session ID (auto-generated if not provided)
        block_on_deny: If True, denied actions raise AgentTrustError (default: True)
        fail_open: If True, allow when Guardian unreachable (default: False)
        max_input_chars: Max chars for input summaries (default: 200)

    Usage:
        from agenttrustid.crewai_callback import agenttrust_protect_crew

        crew = Crew(agents=[researcher, writer], tasks=[task1, task2])
        agenttrust_protect_crew(crew, client=ati_client, agent_id="agent-123")
        result = crew.kickoff()
    """
    session_id = session_id or str(uuid.uuid4())

    agents = getattr(crew, "agents", []) or []
    for agent in agents:
        tools = getattr(agent, "tools", []) or []
        wrapped_tools = []
        for tool in tools:
            wrapped = AgentTrustCrewAIToolWrapper(
                tool=tool,
                client=client,
                agent_id=agent_id,
                session_id=session_id,
                block_on_deny=block_on_deny,
                fail_open=fail_open,
                max_input_chars=max_input_chars,
            )
            wrapped_tools.append(wrapped)
        agent.tools = wrapped_tools

    logger.info(
        "AgentTrust ID protected %d agent(s) in crew",
        len(agents),
    )
