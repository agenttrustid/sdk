"""AgentTrust SDK LangChain Callback Handler

Intercepts every LangChain tool call and:
1. Checks with Guardian before execution (action-check)
2. Reports telemetry after execution (tool_end / tool_error)

Install: pip install agenttrustid[langchain]

Usage:
    from agenttrustid import AgentTrustClient
    from agenttrustid.callback import AgentTrustCallbackHandler

    client = AgentTrustClient.from_env()
    handler = AgentTrustCallbackHandler(client, agent_id="your-agent-id")

    # Pass to LangChain agent
    agent.invoke({"input": "..."}, config={"callbacks": [handler]})
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from .exceptions import AgentTrustError
from .telemetry import TelemetryReporter

logger = logging.getLogger("agenttrustid.callback")

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    # Provide a stub so the module can be imported without langchain
    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Stub — install langchain-core for real callback support."""
        pass


class AgentTrustCallbackHandler(BaseCallbackHandler):
    """Guardian security for every LangChain tool call.

    Args:
        client: AgentTrustClient instance (must have api_key set)
        agent_id: Registered agent ID
        session_id: Session ID for correlation (auto-generated if not provided)
        block_on_deny: If True, denied actions raise AgentTrustError (default: True)
        fail_open: If True, allow actions when Guardian is unreachable (default: False)
        log_inputs: If True, include truncated tool inputs in telemetry (default: False)
        max_input_chars: Max characters for input summaries (default: 200)
    """

    def __init__(
        self,
        client,
        agent_id: str,
        session_id: str = None,
        block_on_deny: bool = True,
        fail_open: bool = False,
        log_inputs: bool = False,
        max_input_chars: int = 200,
    ):
        super().__init__()
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.block_on_deny = block_on_deny
        self.fail_open = fail_open
        self.log_inputs = log_inputs
        self.max_input_chars = max_input_chars

        # Track tool call start times for duration calculation
        self._tool_starts: Dict[str, float] = {}

        # Background telemetry reporter
        self._telemetry = TelemetryReporter(
            telemetry_api=client.telemetry,
            agent_id=agent_id,
            session_id=self.session_id,
        )

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Optional[list] = None,
        metadata: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts. Checks with Guardian before execution."""
        run_key = str(run_id)
        tool_name = serialized.get("name", "unknown")
        # Prevent unbounded memory growth from orphaned tool starts
        if len(self._tool_starts) > 1000:
            self._tool_starts.clear()
        self._tool_starts[run_key] = time.monotonic()

        # Build input summary (privacy: truncated, optional)
        input_summary = ""
        if self.log_inputs:
            raw = input_str or str(inputs or "")
            input_summary = raw[:self.max_input_chars] if raw else ""
        else:
            # Just send char count, never content
            input_summary = f"[{len(input_str or '')} chars]"

        # 1. Call action-check
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
                if self.block_on_deny:
                    raise AgentTrustError(
                        f"Tool call '{tool_name}' denied by Guardian: {result.reason}",
                        code="ACTION_DENIED",
                        details={
                            "tool_name": tool_name,
                            "check_id": result.check_id,
                            "guard_tier": result.guard_tier,
                        },
                    )
        except AgentTrustError:
            raise  # Re-raise AgentTrust ID denials
        except Exception as e:
            # Guardian unreachable
            logger.error("AgentTrust ID action-check failed: %s", e)
            if not self.fail_open:
                raise AgentTrustError(
                    f"Guardian unreachable and fail_open=False: {e}",
                    code="GUARDIAN_UNAVAILABLE",
                )

        # 2. Record tool_start telemetry
        self._telemetry.add_event({
            "event_type": "tool_start",
            "tool_name": tool_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Optional[list] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes successfully."""
        try:
            run_key = str(run_id)
            start = self._tool_starts.pop(run_key, None)
            duration_ms = int((time.monotonic() - start) * 1000) if start else 0

            # Never log full output (privacy)
            self._telemetry.add_event({
                "event_type": "tool_end",
                "tool_name": kwargs.get("name", "unknown"),
                "duration_ms": duration_ms,
                "success": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as e:
            logger.warning("AgentTrust ID telemetry error in on_tool_end: %s", e)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Optional[list] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool raises an error."""
        try:
            run_key = str(run_id)
            start = self._tool_starts.pop(run_key, None)
            duration_ms = int((time.monotonic() - start) * 1000) if start else 0

            self._telemetry.add_event({
                "event_type": "tool_error",
                "tool_name": kwargs.get("name", "unknown"),
                "duration_ms": duration_ms,
                "success": False,
                "error_type": type(error).__name__,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as e:
            logger.warning("AgentTrust ID telemetry error in on_tool_error: %s", e)

    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Optional[list] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain ends. Flush remaining telemetry."""
        # Only flush on top-level chain end (no parent)
        if parent_run_id is None:
            self._telemetry.flush()

    def close(self) -> None:
        """Flush and close telemetry. Call when agent is done."""
        self._telemetry.close()

    def __del__(self):
        try:
            self._telemetry.close()
        except Exception:
            pass
