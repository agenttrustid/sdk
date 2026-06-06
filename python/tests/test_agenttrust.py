"""Tests for AgentTrust SDK AgentTrust 1.0 features (Sessions, Approvals, Elevation)"""

import unittest
from unittest.mock import patch, MagicMock
import json

import sys
sys.path.insert(0, '..')

from agenttrustid import AgentTrustClient, Session, ApprovalRequest, SessionsAPI, ApprovalsAPI
from agenttrustid.models import ActionCheckResult
from agenttrustid.guard import AgentTrustGuard
from agenttrustid.exceptions import AgentTrustError


class MockResponse:
    """Mock HTTP response"""

    def __init__(self, data, status=200):
        self.data = json.dumps(data).encode('utf-8')
        self.status = status

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class TestSessionModel(unittest.TestCase):
    """Test Session model"""

    def test_from_dict_full(self):
        data = {
            "session_id": "sess-001",
            "agent_id": "agent-123",
            "org_id": "org-456",
            "source": "mcp",
            "server_id": "srv-001",
            "mode": "read_only",
            "allowed_actions": ["files:read"],
            "scope_ceiling": ["files:read", "files:write"],
            "total_calls": 10,
            "read_calls": 8,
            "write_calls": 1,
            "denied_calls": 1,
            "created_at": "2026-03-01T10:00:00Z",
            "last_activity_at": "2026-03-01T10:05:00Z",
        }
        session = Session.from_dict(data)

        self.assertEqual(session.session_id, "sess-001")
        self.assertEqual(session.agent_id, "agent-123")
        self.assertEqual(session.org_id, "org-456")
        self.assertEqual(session.source, "mcp")
        self.assertEqual(session.server_id, "srv-001")
        self.assertEqual(session.mode, "read_only")
        self.assertEqual(session.allowed_actions, ["files:read"])
        self.assertEqual(session.scope_ceiling, ["files:read", "files:write"])
        self.assertEqual(session.total_calls, 10)
        self.assertEqual(session.read_calls, 8)
        self.assertEqual(session.write_calls, 1)
        self.assertEqual(session.denied_calls, 1)
        self.assertIsNotNone(session.created_at)
        self.assertIsNotNone(session.last_activity_at)

    def test_from_dict_minimal(self):
        data = {"session_id": "sess-002"}
        session = Session.from_dict(data)

        self.assertEqual(session.session_id, "sess-002")
        self.assertEqual(session.mode, "")
        self.assertEqual(session.allowed_actions, [])
        self.assertEqual(session.scope_ceiling, [])
        self.assertEqual(session.total_calls, 0)
        self.assertIsNone(session.created_at)


class TestApprovalRequestModel(unittest.TestCase):
    """Test ApprovalRequest model"""

    def test_from_dict_full(self):
        data = {
            "id": "apr-001",
            "session_id": "sess-001",
            "agent_id": "agent-123",
            "org_id": "org-456",
            "action_name": "delete_file",
            "action_effect": "destructive",
            "status": "pending",
            "created_at": "2026-03-01T10:00:00Z",
            "expires_at": "2026-03-01T10:15:00Z",
            "decided_by": "",
        }
        approval = ApprovalRequest.from_dict(data)

        self.assertEqual(approval.id, "apr-001")
        self.assertEqual(approval.session_id, "sess-001")
        self.assertEqual(approval.agent_id, "agent-123")
        self.assertEqual(approval.action_name, "delete_file")
        self.assertEqual(approval.action_effect, "destructive")
        self.assertEqual(approval.status, "pending")
        self.assertIsNotNone(approval.created_at)
        self.assertIsNotNone(approval.expires_at)

    def test_from_dict_minimal(self):
        data = {"id": "apr-002"}
        approval = ApprovalRequest.from_dict(data)

        self.assertEqual(approval.id, "apr-002")
        self.assertEqual(approval.status, "pending")
        self.assertIsNone(approval.created_at)


class TestActionCheckResultElevation(unittest.TestCase):
    """Test ActionCheckResult with elevation fields"""

    def test_elevation_required(self):
        data = {
            "allowed": False,
            "reason": "session is read_only",
            "elevation_required": True,
            "approval_id": "apr-001",
        }
        result = ActionCheckResult.from_dict(data)

        self.assertFalse(result.allowed)
        self.assertTrue(result.elevation_required)
        self.assertEqual(result.approval_id, "apr-001")
        self.assertEqual(result.reason, "session is read_only")

    def test_no_elevation(self):
        data = {"allowed": True, "reason": "ok"}
        result = ActionCheckResult.from_dict(data)

        self.assertTrue(result.allowed)
        self.assertFalse(result.elevation_required)
        self.assertIsNone(result.approval_id)


# ---------------------------------------------------------------------------
# SessionsAPI Tests
# ---------------------------------------------------------------------------

class TestSessionsAPI(unittest.TestCase):
    """Test SessionsAPI"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_init_session(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "session_id": "sess-001",
            "agent_id": "agent-123",
            "org_id": "org-456",
            "source": "mcp",
            "server_id": "srv-001",
            "mode": "read_only",
            "allowed_actions": ["files:read"],
            "scope_ceiling": ["files:read", "files:write"],
            "total_calls": 0,
            "read_calls": 0,
            "write_calls": 0,
            "denied_calls": 0,
            "created_at": "2026-03-01T10:00:00Z",
        })

        session = self.client.sessions.init_session(
            agent_id="agent-123",
            server_id="srv-001",
        )

        self.assertEqual(session.session_id, "sess-001")
        self.assertEqual(session.agent_id, "agent-123")
        self.assertEqual(session.mode, "read_only")
        self.assertEqual(session.server_id, "srv-001")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/mcp/sessions/init", request.full_url)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["agent_id"], "agent-123")
        self.assertEqual(body["server_id"], "srv-001")

    @patch('urllib.request.urlopen')
    def test_get_session(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "session_id": "sess-001",
            "agent_id": "agent-123",
            "org_id": "org-456",
            "source": "mcp",
            "mode": "elevated",
            "total_calls": 5,
            "read_calls": 3,
            "write_calls": 2,
            "denied_calls": 0,
        })

        session = self.client.sessions.get_session("sess-001")

        self.assertEqual(session.session_id, "sess-001")
        self.assertEqual(session.mode, "elevated")
        self.assertEqual(session.total_calls, 5)

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("/mcp/sessions/sess-001", request.full_url)

    @patch('urllib.request.urlopen')
    def test_init_api_session(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "session_id": "sess-api-001",
            "agent_id": "agent-123",
            "source": "api",
            "mode": "read_only",
            "scope_ceiling": ["files:read"],
        })

        session = self.client.sessions.init_api_session("eyJ.api-token")

        self.assertEqual(session.session_id, "sess-api-001")
        self.assertEqual(session.source, "api")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/api/v1/agenttrust/api-sessions/init", request.full_url)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["token"], "eyJ.api-token")

    def test_sessions_property_lazy_init(self):
        client = AgentTrustClient()
        self.assertIsInstance(client.sessions, SessionsAPI)
        self.assertIs(client.sessions, client.sessions)


# ---------------------------------------------------------------------------
# ApprovalsAPI Tests
# ---------------------------------------------------------------------------

class TestApprovalsAPI(unittest.TestCase):
    """Test ApprovalsAPI"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_approve(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({"status": "approved"})

        self.client.approvals.approve("apr-001", decided_by="admin@example.com")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/mcp/approvals/apr-001/approve", request.full_url)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["decided_by"], "admin@example.com")

    @patch('urllib.request.urlopen')
    def test_deny(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({"status": "denied"})

        self.client.approvals.deny("apr-001", decided_by="admin@example.com")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/mcp/approvals/apr-001/deny", request.full_url)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["decided_by"], "admin@example.com")

    @patch('urllib.request.urlopen')
    def test_get_approval(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "id": "apr-001",
            "session_id": "sess-001",
            "agent_id": "agent-123",
            "org_id": "org-456",
            "action_name": "delete_file",
            "action_effect": "destructive",
            "status": "approved",
            "decided_by": "admin@example.com",
            "created_at": "2026-03-01T10:00:00Z",
            "expires_at": "2026-03-01T10:15:00Z",
        })

        approval = self.client.approvals.get("apr-001")

        self.assertEqual(approval.id, "apr-001")
        self.assertEqual(approval.status, "approved")
        self.assertEqual(approval.decided_by, "admin@example.com")
        self.assertEqual(approval.action_effect, "destructive")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("/mcp/approvals/apr-001", request.full_url)

    def test_approvals_property_lazy_init(self):
        client = AgentTrustClient()
        self.assertIsInstance(client.approvals, ApprovalsAPI)
        self.assertIs(client.approvals, client.approvals)


# ---------------------------------------------------------------------------
# ActionsAPI with action_effect Tests
# ---------------------------------------------------------------------------

class TestActionsCheckActionEffect(unittest.TestCase):
    """Test ActionsAPI.check with action_effect parameter"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_check_with_action_effect(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "allowed": True,
            "check_id": "chk-1",
        })

        self.client.actions.check(
            agent_id="agent-123",
            tool_name="write_file",
            action_effect="mutating",
        )

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["action_effect"], "mutating")

    @patch('urllib.request.urlopen')
    def test_check_without_action_effect(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({"allowed": True})

        self.client.actions.check(
            agent_id="agent-123",
            tool_name="read_file",
        )

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertNotIn("action_effect", body)

    @patch('urllib.request.urlopen')
    def test_check_returns_elevation(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "allowed": False,
            "reason": "session is read_only",
            "elevation_required": True,
            "approval_id": "apr-001",
        })

        result = self.client.actions.check(
            agent_id="agent-123",
            tool_name="delete_file",
            session_id="sess-001",
        )

        self.assertFalse(result.allowed)
        self.assertTrue(result.elevation_required)
        self.assertEqual(result.approval_id, "apr-001")


# ---------------------------------------------------------------------------
# AgentTrustGuard Elevation Tests
# ---------------------------------------------------------------------------

class TestAgentTrustGuardElevation(unittest.TestCase):
    """Test AgentTrustGuard.check with elevation handling"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_guard_check_elevation_required(self, mock_urlopen):
        """Guard raises AgentTrustError with ELEVATION_REQUIRED code"""
        mock_urlopen.return_value = MockResponse({
            "allowed": False,
            "reason": "session is read_only",
            "elevation_required": True,
            "approval_id": "apr-001",
        })

        guard = AgentTrustGuard(self.client, agent_id="agent-123")

        with self.assertRaises(AgentTrustError) as ctx:
            guard.check("delete_file")

        self.assertEqual(ctx.exception.code, "ELEVATION_REQUIRED")
        self.assertTrue(ctx.exception.details.get("elevation_required"))
        self.assertEqual(ctx.exception.details.get("approval_id"), "apr-001")

    @patch('urllib.request.urlopen')
    def test_guard_check_with_action_effect(self, mock_urlopen):
        """Guard passes action_effect to actions.check"""
        mock_urlopen.return_value = MockResponse({"allowed": True})

        guard = AgentTrustGuard(self.client, agent_id="agent-123")
        guard.check("write_file", action_effect="mutating")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["action_effect"], "mutating")

    @patch('urllib.request.urlopen')
    def test_guard_check_denied_not_elevation(self, mock_urlopen):
        """Guard raises ACTION_DENIED when denied without elevation"""
        mock_urlopen.return_value = MockResponse({
            "allowed": False,
            "reason": "capability not registered",
        })

        guard = AgentTrustGuard(self.client, agent_id="agent-123")

        with self.assertRaises(AgentTrustError) as ctx:
            guard.check("forbidden_tool")

        self.assertEqual(ctx.exception.code, "ACTION_DENIED")

    @patch('urllib.request.urlopen')
    def test_guard_check_elevation_no_block(self, mock_urlopen):
        """Guard returns False when elevation required but block_on_deny=False"""
        mock_urlopen.return_value = MockResponse({
            "allowed": False,
            "reason": "needs elevation",
            "elevation_required": True,
            "approval_id": "apr-002",
        })

        guard = AgentTrustGuard(self.client, agent_id="agent-123", block_on_deny=False)
        result = guard.check("write_file")

        self.assertFalse(result)


# ---------------------------------------------------------------------------
# MCPAPI.call_tool with session_id Tests
# ---------------------------------------------------------------------------

class TestMCPCallToolSessionID(unittest.TestCase):
    """Test MCPAPI.call_tool with session_id parameter"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_call_tool_with_session_id(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "result": {"content": "ok"}
        })

        self.client.mcp.call_tool(
            server_id="srv-001",
            method="tools/call",
            params={"name": "read_file"},
            session_id="sess-001",
        )

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_header("X-session-id"), "sess-001")

    @patch('urllib.request.urlopen')
    def test_call_tool_session_header_cleanup(self, mock_urlopen):
        """X-Session-ID header is removed after call"""
        mock_urlopen.return_value = MockResponse({"result": {}})

        self.client.mcp.call_tool(
            server_id="srv-001",
            method="tools/call",
            session_id="sess-001",
        )

        # After the call, the header should be cleaned up
        self.assertNotIn("X-Session-ID", self.client.mcp._http.headers)

    @patch('urllib.request.urlopen')
    def test_call_tool_without_session_id(self, mock_urlopen):
        """No X-Session-ID header when session_id not provided"""
        mock_urlopen.return_value = MockResponse({"result": {}})

        self.client.mcp.call_tool(
            server_id="srv-001",
            method="tools/list",
        )

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertIsNone(request.get_header("X-session-id"))


if __name__ == "__main__":
    unittest.main()
