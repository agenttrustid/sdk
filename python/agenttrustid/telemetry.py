"""AgentTrust SDK Background Telemetry Reporter

Batches telemetry events and sends them to the audit service in the background.
Best-effort delivery — failures are logged, never crash the agent.
"""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("agenttrustid.telemetry")


class TelemetryReporter:
    """Batches events, sends every flush_interval_s seconds or batch_size events.

    Thread-safe. Uses threading.Timer (not asyncio) because LangChain callbacks are sync.

    Args:
        telemetry_api: TelemetryAPI instance from AgentTrustClient
        agent_id: Agent ID for all events
        session_id: Session ID for correlation
        batch_size: Max events before auto-flush (default: 10)
        flush_interval_s: Seconds between auto-flushes (default: 5.0)
    """

    def __init__(
        self,
        telemetry_api,
        agent_id: str,
        session_id: str,
        batch_size: int = 10,
        flush_interval_s: float = 5.0,
    ):
        self._api = telemetry_api
        self._agent_id = agent_id
        self._session_id = session_id
        self._batch_size = batch_size
        self._flush_interval = flush_interval_s

        self._buffer: List[Dict] = []
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._closed = False

        # Start the periodic flush timer
        self._schedule_flush()

    def add_event(self, event: Dict) -> None:
        """Add an event to the buffer. Thread-safe.

        If the buffer reaches batch_size, flush immediately.

        Args:
            event: Dict with event_type, tool_name, duration_ms, success, etc.
        """
        if self._closed:
            return

        # Ensure timestamp
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()

        with self._lock:
            self._buffer.append(event)
            # Prevent unbounded buffer growth
            if len(self._buffer) > 1000:
                self._buffer = self._buffer[-self._batch_size:]
            should_flush = len(self._buffer) >= self._batch_size

        if should_flush:
            self.flush()

    def flush(self) -> None:
        """Send all buffered events immediately. Thread-safe."""
        with self._lock:
            if not self._buffer:
                return
            events = self._buffer[:]
            self._buffer.clear()

        self._send_batch(events)

    def close(self) -> None:
        """Flush remaining events and stop the timer."""
        self._closed = True
        if self._timer:
            self._timer.cancel()
            self._timer = None
        self.flush()

    def _schedule_flush(self) -> None:
        """Schedule the next periodic flush."""
        if self._closed:
            return
        if self._timer is not None:
            self._timer.cancel()
        self._timer = threading.Timer(self._flush_interval, self._periodic_flush)
        self._timer.daemon = True
        self._timer.start()

    def _periodic_flush(self) -> None:
        """Called by timer — flush and reschedule."""
        if self._closed:
            return
        self.flush()
        self._schedule_flush()

    def _send_batch(self, events: List[Dict]) -> None:
        """Fire-and-forget HTTP send. Failures are logged, never raised."""
        try:
            self._api.report(
                agent_id=self._agent_id,
                session_id=self._session_id,
                events=events,
            )
        except Exception as e:
            logger.warning(
                "telemetry send failed (events=%d): %s", len(events), e
            )

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
