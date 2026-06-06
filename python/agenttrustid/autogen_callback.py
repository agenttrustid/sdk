"""AgentTrust SDK AutoGen Integration

Wraps AutoGen tool functions with AgentTrust ID Guardian security checks and telemetry.

Install: pip install agenttrustid[autogen]

Usage:
    from agenttrustid import AgentTrustClient
    from agenttrustid.autogen_callback import agenttrust_wrap_tool, AgentTrustAutoGenToolWrapper

    client = AgentTrustClient.from_env()

    # Decorator form
    @agenttrust_wrap_tool(client=client, agent_id="agent-123")
    def web_search(query: str) -> str:
        return search(query)

    # Class form
    wrapper = AgentTrustAutoGenToolWrapper(
        func=my_function,
        client=client,
        agent_id="agent-123",
    )
    result = wrapper("some input")

    # Register with an AutoGen agent
    from agenttrustid.autogen_callback import agenttrust_register_tool
    agenttrust_register_tool(agent, func=web_search, client=client, agent_id="agent-123")
"""

import functools
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from .exceptions import AgentTrustError
from .telemetry import TelemetryReporter

logger = logging.getLogger("agenttrustid.autogen")

try:
    from autogen import ConversableAgent as _ConversableAgent
except ImportError:
    try:
        from autogen_agentchat import ConversableAgent as _ConversableAgent
    except ImportError:
        # Provide a stub so the module can be imported without autogen
        class _ConversableAgent:  # type: ignore[no-redef]
            """Stub — install autogen-agentchat for real agent support."""
            pass


class AgentTrustAutoGenToolWrapper:
    """Wraps an AutoGen tool function with AgentTrust ID Guardian security.

    Before each call, checks with Guardian. After execution, reports
    telemetry (success/failure + duration). On denial, raises AgentTrustError
    (if block_on_deny) or returns a denial message string.

    Args:
        func: The tool function to wrap
        client: AgentTrustClient instance (must have api_key set)
        agent_id: Registered agent ID
        tool_name: Override tool name (defaults to func.__name__)
        session_id: Session ID for correlation (auto-generated if not provided)
        block_on_deny: If True, denied actions raise AgentTrustError (default: True)
        fail_open: If True, allow actions when Guardian is unreachable (default: False)
        max_input_chars: Max characters for input summaries (default: 200)

    Usage:
        wrapper = AgentTrustAutoGenToolWrapper(
            func=my_function,
            client=ati_client,
            agent_id="agent-123",
        )
        result = wrapper("some query")
    """

    def __init__(
        self,
        func: Callable,
        client,
        agent_id: str,
        tool_name: str = None,
        session_id: str = None,
        block_on_deny: bool = True,
        fail_open: bool = False,
        max_input_chars: int = 200,
    ):
        self._func = func
        self.client = client
        self.agent_id = agent_id
        self.tool_name = tool_name or getattr(func, "__name__", "unknown")
        self.session_id = session_id or str(uuid.uuid4())
        self.block_on_deny = block_on_deny
        self.fail_open = fail_open
        self.max_input_chars = max_input_chars

        # Preserve function metadata
        functools.update_wrapper(self, func)

        # Background telemetry reporter
        self._telemetry = TelemetryReporter(
            telemetry_api=client.telemetry,
            agent_id=agent_id,
            session_id=self.session_id,
        )

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the wrapped function with Guardian check and telemetry."""
        tool_name = self.tool_name

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

        # 2. Execute the original function
        start = time.monotonic()
        success = True
        error_type = None
        try:
            result = self._func(*args, **kwargs)
            return result
        except Exception as exc:
            success = False
            error_type = type(exc).__name__
            raise
        finally:
            # 3. Report telemetry
            duration_ms = int((time.monotonic() - start) * 1000)
            self._report(tool_name, success, duration_ms, error_type)

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


class AgentTrustAutoGenMiddleware:
    """Middleware for AutoGen message handling with AgentTrust ID Guardian security.

    Can be used as a hook in AutoGen's message processing pipeline
    to check and report on tool-related messages.

    Args:
        client: AgentTrustClient instance
        agent_id: Registered agent ID
        session_id: Session ID for correlation (auto-generated if not provided)
        block_on_deny: If True, denied actions raise AgentTrustError (default: True)
        fail_open: If True, allow when Guardian unreachable (default: False)

    Usage:
        middleware = AgentTrustAutoGenMiddleware(client=ati_client, agent_id="agent-123")

        # Use in message processing
        middleware.on_tool_call(tool_name="web_search", tool_input="query")
        # ... execute tool ...
        middleware.on_tool_result(tool_name="web_search", success=True, duration_ms=500)

        middleware.close()
    """

    def __init__(
        self,
        client,
        agent_id: str,
        session_id: str = None,
        block_on_deny: bool = True,
        fail_open: bool = False,
        max_input_chars: int = 200,
    ):
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.block_on_deny = block_on_deny
        self.fail_open = fail_open
        self.max_input_chars = max_input_chars

        self._telemetry = TelemetryReporter(
            telemetry_api=client.telemetry,
            agent_id=agent_id,
            session_id=self.session_id,
        )
        self._call_starts: Dict[str, float] = {}

    def on_tool_call(self, tool_name: str, tool_input: str = "") -> bool:
        """Check with Guardian before a tool call. Returns True if allowed.

        Raises AgentTrustError if denied (when block_on_deny=True) or if Guardian
        is unreachable (when fail_open=False).
        """
        # Truncate for privacy
        input_summary = tool_input[: self.max_input_chars] if tool_input else ""

        # Track start time
        call_id = f"{tool_name}:{uuid.uuid4().hex[:8]}"
        # Prevent unbounded memory growth
        if len(self._call_starts) > 1000:
            self._call_starts.clear()
        self._call_starts[call_id] = time.monotonic()

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
                        f"Tool '{tool_name}' denied by Guardian: {result.reason}",
                        code="ACTION_DENIED",
                        details={"tool_name": tool_name},
                    )
                return False

            # Record tool_start telemetry
            self._telemetry.add_event({
                "event_type": "tool_start",
                "tool_name": tool_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
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

    def on_tool_result(
        self,
        tool_name: str,
        success: bool = True,
        duration_ms: int = 0,
        error_type: str = None,
    ) -> None:
        """Report a tool call result (fire-and-forget telemetry)."""
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


def agenttrust_wrap_tool(
    client,
    agent_id: str,
    tool_name: str = None,
    session_id: str = None,
    block_on_deny: bool = True,
    fail_open: bool = False,
    max_input_chars: int = 200,
) -> Callable:
    """Decorator that wraps a tool function with AgentTrust ID Guardian security.

    Use this to protect individual tool functions registered with AutoGen.

    Args:
        client: AgentTrustClient instance
        agent_id: Registered agent ID
        tool_name: Override tool name (defaults to function name)
        session_id: Session ID for correlation (auto-generated if not provided)
        block_on_deny: If True, denied actions raise AgentTrustError (default: True)
        fail_open: If True, allow when Guardian unreachable (default: False)
        max_input_chars: Max chars for input summaries (default: 200)

    Usage:
        @agenttrust_wrap_tool(client=ati_client, agent_id="agent-123")
        def web_search(query: str) -> str:
            return search(query)
    """
    _session_id = session_id or str(uuid.uuid4())

    def decorator(func: Callable) -> Callable:
        _tool_name = tool_name or getattr(func, "__name__", "unknown")

        telemetry = TelemetryReporter(
            telemetry_api=client.telemetry,
            agent_id=agent_id,
            session_id=_session_id,
        )

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Build input summary (privacy: truncated)
            raw_input = " ".join(str(a) for a in args)
            if kwargs:
                raw_input += " " + " ".join(
                    f"{k}={v}" for k, v in kwargs.items()
                )
            input_summary = raw_input[:max_input_chars] if raw_input else ""

            # 1. Pre-flight Guardian check
            try:
                result = client.actions.check(
                    agent_id=agent_id,
                    action="tool_call",
                    tool_name=_tool_name,
                    tool_input_summary=input_summary,
                    session_id=_session_id,
                )
                if not result.allowed:
                    logger.warning(
                        "AgentTrust ID denied tool call: tool=%s reason=%s",
                        _tool_name,
                        result.reason,
                    )
                    if block_on_deny:
                        raise AgentTrustError(
                            f"Tool '{_tool_name}' denied by Guardian: {result.reason}",
                            code="ACTION_DENIED",
                            details={"tool_name": _tool_name},
                        )
                    return f"Tool '{_tool_name}' denied by AgentTrust ID Guardian"
            except AgentTrustError:
                raise
            except Exception as e:
                logger.error("AgentTrust ID action-check failed: %s", e)
                if not fail_open:
                    raise AgentTrustError(
                        f"Guardian unreachable and fail_open=False: {e}",
                        code="GUARDIAN_UNAVAILABLE",
                    )

            # 2. Execute the original function
            start = time.monotonic()
            success = True
            error_type = None
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                success = False
                error_type = type(exc).__name__
                raise
            finally:
                # 3. Report telemetry
                duration_ms = int((time.monotonic() - start) * 1000)
                try:
                    event = {
                        "event_type": "tool_end" if success else "tool_error",
                        "tool_name": _tool_name,
                        "duration_ms": duration_ms,
                        "success": success,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    if error_type:
                        event["error_type"] = error_type
                    telemetry.add_event(event)
                except Exception as te:
                    logger.warning("AgentTrust ID telemetry error: %s", te)

        # Attach close method to the wrapper for cleanup
        wrapper.close = telemetry.close  # type: ignore[attr-defined]
        wrapper._telemetry = telemetry  # type: ignore[attr-defined]
        return wrapper

    return decorator


def agenttrust_register_tool(
    agent,
    func: Callable,
    client,
    agent_id: str,
    tool_name: str = None,
    session_id: str = None,
    block_on_deny: bool = True,
    fail_open: bool = False,
    max_input_chars: int = 200,
    description: str = None,
) -> Callable:
    """Register a tool function with an AutoGen agent, wrapped with AgentTrust ID security.

    Wraps the function with Guardian checks and telemetry, then registers
    it with the AutoGen agent using agent.register_for_llm() and
    agent.register_for_execution() if those methods exist.

    Args:
        agent: AutoGen ConversableAgent instance
        func: Tool function to register
        client: AgentTrustClient instance
        agent_id: Registered agent ID
        tool_name: Override tool name (defaults to function name)
        session_id: Session ID for correlation
        block_on_deny: If True, denied actions raise AgentTrustError (default: True)
        fail_open: If True, allow when Guardian unreachable (default: False)
        max_input_chars: Max chars for input summaries (default: 200)
        description: Tool description for the LLM (defaults to func docstring)

    Returns:
        The wrapped function

    Usage:
        from agenttrustid.autogen_callback import agenttrust_register_tool

        def web_search(query: str) -> str:
            \"\"\"Search the web.\"\"\"
            return search(query)

        wrapped = agenttrust_register_tool(
            agent=assistant,
            func=web_search,
            client=ati_client,
            agent_id="agent-123",
        )
    """
    wrapped = AgentTrustAutoGenToolWrapper(
        func=func,
        client=client,
        agent_id=agent_id,
        tool_name=tool_name,
        session_id=session_id,
        block_on_deny=block_on_deny,
        fail_open=fail_open,
        max_input_chars=max_input_chars,
    )

    desc = description or getattr(func, "__doc__", None) or ""

    # Register with AutoGen agent if register methods exist
    if hasattr(agent, "register_for_llm"):
        try:
            agent.register_for_llm(description=desc)(wrapped)
        except Exception as e:
            logger.warning("Failed to register_for_llm: %s", e)

    if hasattr(agent, "register_for_execution"):
        try:
            agent.register_for_execution()(wrapped)
        except Exception as e:
            logger.warning("Failed to register_for_execution: %s", e)

    logger.info(
        "AgentTrust ID registered tool '%s' with agent",
        wrapped.tool_name,
    )
    return wrapped
