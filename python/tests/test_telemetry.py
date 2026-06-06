"""Tests for AgentTrust SDK Telemetry Reporter"""

import unittest
from unittest.mock import MagicMock, call
import threading
import time

from agenttrustid.telemetry import TelemetryReporter


def make_api(succeed=True):
    """Create a mock TelemetryAPI."""
    api = MagicMock()
    if succeed:
        api.report.return_value = {"accepted": True, "events_processed": 1}
    else:
        api.report.side_effect = ConnectionError("unreachable")
    return api


class TestTelemetryReporterInit(unittest.TestCase):
    """Test TelemetryReporter initialization."""

    def test_defaults(self):
        api = make_api()
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")

        self.assertEqual(reporter._agent_id, "a1")
        self.assertEqual(reporter._session_id, "s1")
        self.assertEqual(reporter._batch_size, 10)
        self.assertEqual(reporter._flush_interval, 5.0)
        self.assertFalse(reporter._closed)
        self.assertEqual(len(reporter._buffer), 0)

        reporter.close()

    def test_custom_batch_params(self):
        api = make_api()
        reporter = TelemetryReporter(
            api, agent_id="a1", session_id="s1",
            batch_size=5, flush_interval_s=1.0,
        )
        self.assertEqual(reporter._batch_size, 5)
        self.assertEqual(reporter._flush_interval, 1.0)
        reporter.close()


class TestAddEvent(unittest.TestCase):
    """Test adding events to the buffer."""

    def test_event_added_to_buffer(self):
        api = make_api()
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")

        reporter.add_event({"event_type": "tool_start", "tool_name": "search"})

        self.assertEqual(len(reporter._buffer), 1)
        self.assertEqual(reporter._buffer[0]["event_type"], "tool_start")
        reporter.close()

    def test_timestamp_added_if_missing(self):
        api = make_api()
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")

        reporter.add_event({"event_type": "tool_start"})

        self.assertIn("timestamp", reporter._buffer[0])
        reporter.close()

    def test_existing_timestamp_preserved(self):
        api = make_api()
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")

        reporter.add_event({"event_type": "tool_start", "timestamp": "2025-01-01T00:00:00Z"})

        self.assertEqual(reporter._buffer[0]["timestamp"], "2025-01-01T00:00:00Z")
        reporter.close()

    def test_events_ignored_after_close(self):
        api = make_api()
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")
        reporter.close()

        reporter.add_event({"event_type": "tool_start"})
        self.assertEqual(len(reporter._buffer), 0)


class TestBatchFlush(unittest.TestCase):
    """Test batch flushing behavior."""

    def test_auto_flush_at_batch_size(self):
        api = make_api()
        reporter = TelemetryReporter(
            api, agent_id="a1", session_id="s1", batch_size=3,
        )

        reporter.add_event({"event_type": "e1"})
        reporter.add_event({"event_type": "e2"})
        self.assertEqual(api.report.call_count, 0)

        reporter.add_event({"event_type": "e3"})
        # Should have flushed
        self.assertEqual(api.report.call_count, 1)
        self.assertEqual(len(reporter._buffer), 0)

        # Verify the batch sent
        sent_events = api.report.call_args.kwargs["events"]
        self.assertEqual(len(sent_events), 3)
        reporter.close()

    def test_manual_flush(self):
        api = make_api()
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")

        reporter.add_event({"event_type": "e1"})
        reporter.add_event({"event_type": "e2"})
        reporter.flush()

        self.assertEqual(api.report.call_count, 1)
        self.assertEqual(len(reporter._buffer), 0)
        reporter.close()

    def test_flush_empty_buffer_is_noop(self):
        api = make_api()
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")

        reporter.flush()
        self.assertEqual(api.report.call_count, 0)
        reporter.close()

    def test_close_flushes_remaining(self):
        api = make_api()
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")

        reporter.add_event({"event_type": "e1"})
        reporter.add_event({"event_type": "e2"})
        reporter.close()

        self.assertEqual(api.report.call_count, 1)
        sent_events = api.report.call_args.kwargs["events"]
        self.assertEqual(len(sent_events), 2)

    def test_sends_correct_agent_and_session(self):
        api = make_api()
        reporter = TelemetryReporter(api, agent_id="agent-x", session_id="sess-y")

        reporter.add_event({"event_type": "e1"})
        reporter.flush()

        api.report.assert_called_once_with(
            agent_id="agent-x",
            session_id="sess-y",
            events=unittest.mock.ANY,
        )
        reporter.close()


class TestTimerFlush(unittest.TestCase):
    """Test timer-based periodic flushing."""

    def test_timer_flushes_periodically(self):
        api = make_api()
        reporter = TelemetryReporter(
            api, agent_id="a1", session_id="s1",
            flush_interval_s=0.1,  # 100ms for fast test
        )

        reporter.add_event({"event_type": "e1"})

        # Wait for timer to fire
        time.sleep(0.3)

        self.assertGreaterEqual(api.report.call_count, 1)
        reporter.close()


class TestErrorResilience(unittest.TestCase):
    """Test that telemetry failures don't crash the agent."""

    def test_send_failure_does_not_raise(self):
        api = make_api(succeed=False)
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")

        reporter.add_event({"event_type": "e1"})
        # Should not raise even though API fails
        reporter.flush()

        self.assertEqual(api.report.call_count, 1)
        # Buffer should be cleared even on failure (fire-and-forget)
        self.assertEqual(len(reporter._buffer), 0)
        reporter.close()

    def test_close_with_failed_api_does_not_raise(self):
        api = make_api(succeed=False)
        reporter = TelemetryReporter(api, agent_id="a1", session_id="s1")

        reporter.add_event({"event_type": "e1"})
        # Should not raise
        reporter.close()


class TestThreadSafety(unittest.TestCase):
    """Test thread-safe buffer operations."""

    def test_concurrent_add_events(self):
        api = make_api()
        reporter = TelemetryReporter(
            api, agent_id="a1", session_id="s1",
            batch_size=1000,  # High limit so we don't auto-flush
        )

        def add_events(n):
            for i in range(n):
                reporter.add_event({"event_type": f"e-{threading.current_thread().name}-{i}"})

        threads = [threading.Thread(target=add_events, args=(50,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 200 events should be buffered (no lost events)
        reporter.flush()
        total_events = sum(len(c.kwargs["events"]) for c in api.report.call_args_list)
        self.assertEqual(total_events, 200)
        reporter.close()


class TestContextManager(unittest.TestCase):
    """Test context manager protocol."""

    def test_context_manager_closes(self):
        api = make_api()
        with TelemetryReporter(api, agent_id="a1", session_id="s1") as reporter:
            reporter.add_event({"event_type": "e1"})

        # After exiting, should be closed and flushed
        self.assertTrue(reporter._closed)
        self.assertEqual(api.report.call_count, 1)


if __name__ == "__main__":
    unittest.main()
