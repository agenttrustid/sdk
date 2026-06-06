"""AgentTrust SDK Guard — Simple pre-flight check + telemetry for any agent.

For agents using raw Anthropic/OpenAI SDKs instead of LangChain.

Usage:
    from agenttrustid import AgentTrustClient
    from agenttrustid.guard import AgentTrustGuard

    client = AgentTrustClient.from_env()
    guard = AgentTrustGuard(client, agent_id="your-agent-id")

    # Before tool call
    guard.check("web_search", input_summary="AI news bay area")  # raises AgentTrustError if denied

    # After tool call
    guard.report("web_search", success=True, duration_ms=1200)

    # When done
    guard.close()
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from .exceptions import AgentTrustError
from .telemetry import TelemetryReporter

logger = logging.getLogger("agenttrustid.guard")


class AgentTrustGuard:
    """Simple guard/report wrapper for non-LangChain agents.

    Args:
        client: AgentTrustClient instance
        agent_id: Registered agent ID
        session_id: Session ID (auto-generated if not provided)
        block_on_deny: If True, check() raises AgentTrustError on denial (default: True)
        fail_open: If True, allow when Guardian is unreachable (default: False)
    """

    def __init__(
        self,
        client,
        agent_id: str,
        session_id: str = None,
        block_on_deny: bool = True,
        fail_open: bool = False,
    ):
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.block_on_deny = block_on_deny
        self.fail_open = fail_open
        self._telemetry = TelemetryReporter(
            telemetry_api=client.telemetry,
            agent_id=agent_id,
            session_id=self.session_id,
        )

    def check(self, tool_name: str, input_summary: str = "", action_effect: str = "") -> bool:
        """Pre-flight check before a tool call. Returns True if allowed.

        Raises AgentTrustError if denied and block_on_deny=True.
        When elevation is required, the error's details dict contains
        'elevation_required': True and 'approval_id': '<id>'.

        Args:
            tool_name: Name of the tool being called
            input_summary: Summary of inputs (truncated to 200 chars)
            action_effect: Effect hint (read, mutating, destructive, admin).
                If empty, the backend auto-classifies.
        """
        # Truncate for privacy
        if len(input_summary) > 200:
            input_summary = input_summary[:200]

        try:
            result = self.client.actions.check(
                agent_id=self.agent_id,
                action="tool_call",
                tool_name=tool_name,
                tool_input_summary=input_summary,
                session_id=self.session_id,
                action_effect=action_effect,
            )
            if not result.allowed:
                logger.warning("AgentTrust ID denied: tool=%s reason=%s", tool_name, result.reason)
                if self.block_on_deny:
                    details = {}
                    if result.elevation_required:
                        details["elevation_required"] = True
                        details["approval_id"] = result.approval_id
                    raise AgentTrustError(
                        f"Tool '{tool_name}' denied: {result.reason}",
                        code="ELEVATION_REQUIRED" if result.elevation_required else "ACTION_DENIED",
                        details=details,
                    )
                return False
            return True
        except AgentTrustError:
            raise
        except Exception as e:
            logger.error("AgentTrust ID action-check failed: %s", e)
            if not self.fail_open:
                raise AgentTrustError(f"Guardian unreachable: {e}", code="GUARDIAN_UNAVAILABLE")
            return True

    def report(self, tool_name: str, success: bool = True, duration_ms: int = 0, error_type: str = None):
        """Report a tool call result (fire-and-forget telemetry)."""
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

    def close(self):
        """Flush telemetry. Call when agent is done."""
        self._telemetry.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
