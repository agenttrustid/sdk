"""Tests for AgentTrust SDK protocol modules (A2A, Agent Cards, MCP, Delegations)"""

import unittest
from unittest.mock import patch, MagicMock
import json

import sys
sys.path.insert(0, '..')

from agenttrustid import AgentTrustClient
from agenttrustid.models import (
    AgentCard,
    A2ATask,
    A2AMessageTask,
    MCPServer,
    Delegation,
)
from agenttrustid.a2a import A2AAPI
from agenttrustid.agentcard import AgentCardsAPI
from agenttrustid.mcp_client import MCPAPI
from agenttrustid.delegation import DelegationsAPI
from agenttrustid.federation import FederationAPI
from agenttrustid.streaming import StreamingAPI


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


def make_v1_card(name="my-agent", version="1.0.0", url="http://localhost:8080/a2a/agents/agent-123",
                 trust_score=0.87):
    """Build an A2A v1.0 sample Agent Card dict."""
    return {
        "name": name,
        "description": "A test agent",
        "version": version,
        "supportedInterfaces": [
            {
                "url": url,
                "protocolBinding": "jsonrpc",
                "protocolVersion": "1.0",
                "tenant": "org-123",
            }
        ],
        "provider": {"organization": "ATI", "url": "https://agenttrust.id"},
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
            "extensions": [
                {
                    "uri": "https://agenttrust.id/ext/trust/v1",
                    "description": "AgentTrust trust score",
                    "required": False,
                    "params": {"ati_trust_score": trust_score},
                }
            ],
        },
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "securityRequirements": [{"bearer": []}],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {
                "id": "summarize",
                "name": "Summarize",
                "description": "Summarize text",
                "tags": ["nlp", "summary"],
                "examples": ["Summarize this report"],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain"],
            }
        ],
        "signatures": [
            {"protected": "eyJ...", "signature": "abc...", "header": {"kid": "k1"}}
        ],
        "documentationUrl": "https://agenttrust.id/docs",
        "iconUrl": "https://agenttrust.id/icon.png",
    }


# ---------------------------------------------------------------------------
# Agent Cards API tests
# ---------------------------------------------------------------------------

class TestAgentCardsAPI(unittest.TestCase):
    """Test AgentCardsAPI"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_generate_card(self, mock_urlopen):
        """Test generating a v1.0 agent card"""
        mock_urlopen.return_value = MockResponse(make_v1_card())

        card = self.client.agent_cards.generate("agent-123")

        self.assertEqual(card.name, "my-agent")
        self.assertEqual(card.version, "1.0.0")
        self.assertEqual(card.provider, {"organization": "ATI", "url": "https://agenttrust.id"})
        self.assertTrue(card.capabilities.get("streaming"))
        self.assertEqual(len(card.skills), 1)
        self.assertEqual(card.skills[0]["tags"], ["nlp", "summary"])
        # v1.0 derived accessors
        self.assertEqual(card.primary_url, "http://localhost:8080/a2a/agents/agent-123")
        self.assertAlmostEqual(card.trust_score, 0.87)

        # Verify correct HTTP method and path
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/api/v1/agents/agent-123/card", request.full_url)

    @patch('urllib.request.urlopen')
    def test_get_card(self, mock_urlopen):
        """Test getting a v1.0 agent card"""
        mock_urlopen.return_value = MockResponse(make_v1_card())

        card = self.client.agent_cards.get("agent-123")

        self.assertEqual(card.name, "my-agent")
        self.assertEqual(card.primary_url, "http://localhost:8080/a2a/agents/agent-123")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("/api/v1/agents/agent-123/card", request.full_url)

    @patch('urllib.request.urlopen')
    def test_publish_card(self, mock_urlopen):
        """Test publishing a v1.0 agent card"""
        mock_urlopen.return_value = MockResponse(make_v1_card())

        card = self.client.agent_cards.publish("agent-123")

        self.assertEqual(card.name, "my-agent")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "PUT")
        self.assertIn("/api/v1/agents/agent-123/card/publish", request.full_url)

    @patch('urllib.request.urlopen')
    def test_get_public_card(self, mock_urlopen):
        """Test getting a public v1.0 agent card via well-known path"""
        mock_urlopen.return_value = MockResponse(
            make_v1_card(name="public-agent", version="2.0.0",
                         url="http://example.com/a2a/agents/agent-123")
        )

        card = self.client.agent_cards.get_public("agent-123")

        self.assertEqual(card.name, "public-agent")
        self.assertEqual(card.version, "2.0.0")
        self.assertEqual(card.primary_url, "http://example.com/a2a/agents/agent-123")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("/a2a/agents/agent-123/agent.json", request.full_url)


# ---------------------------------------------------------------------------
# A2A API tests
# ---------------------------------------------------------------------------

class TestA2AAPI(unittest.TestCase):
    """Test A2AAPI"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_send_task(self, mock_urlopen):
        """Test sending an A2A task"""
        mock_urlopen.return_value = MockResponse({
            "result": {
                "id": "task-001",
                "source_agent_id": "agent-123",
                "target_agent_id": "agent-456",
                "status": "pending",
                "message": "Summarize this report",
                "artifacts": [],
                "metadata": {"priority": "high"},
                "created_at": "2026-02-28T10:00:00Z",
                "updated_at": "2026-02-28T10:00:00Z",
            }
        })

        task = self.client.a2a.send_task(
            source_agent_id="agent-123",
            target_agent_id="agent-456",
            message="Summarize this report",
            metadata={"priority": "high"},
        )

        self.assertEqual(task.id, "task-001")
        self.assertEqual(task.source_agent_id, "agent-123")
        self.assertEqual(task.target_agent_id, "agent-456")
        self.assertEqual(task.status, "pending")
        self.assertEqual(task.message, "Summarize this report")
        self.assertEqual(task.metadata, {"priority": "high"})

        # Verify JSON-RPC payload
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/a2a", request.full_url)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["jsonrpc"], "2.0")
        self.assertEqual(body["method"], "tasks/send")
        self.assertEqual(body["params"]["source_agent_id"], "agent-123")
        self.assertEqual(body["params"]["target_agent_id"], "agent-456")
        self.assertEqual(body["params"]["message"], "Summarize this report")

    @patch('urllib.request.urlopen')
    def test_send_task_without_metadata(self, mock_urlopen):
        """Test sending a task without optional metadata"""
        mock_urlopen.return_value = MockResponse({
            "result": {
                "id": "task-002",
                "source_agent_id": "agent-123",
                "target_agent_id": "agent-456",
                "status": "pending",
                "message": "Simple task",
            }
        })

        task = self.client.a2a.send_task(
            source_agent_id="agent-123",
            target_agent_id="agent-456",
            message="Simple task",
        )

        self.assertEqual(task.id, "task-002")

        # Verify no metadata in payload
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertNotIn("metadata", body["params"])

    @patch('urllib.request.urlopen')
    def test_get_task(self, mock_urlopen):
        """Test getting an A2A task"""
        mock_urlopen.return_value = MockResponse({
            "result": {
                "id": "task-001",
                "source_agent_id": "agent-123",
                "target_agent_id": "agent-456",
                "status": "completed",
                "message": "Summarize this report",
                "artifacts": [{"type": "text", "content": "Summary here"}],
                "created_at": "2026-02-28T10:00:00Z",
                "updated_at": "2026-02-28T10:05:00Z",
            }
        })

        task = self.client.a2a.get_task("task-001")

        self.assertEqual(task.id, "task-001")
        self.assertEqual(task.status, "completed")
        self.assertEqual(len(task.artifacts), 1)

        # Verify JSON-RPC method
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["method"], "tasks/get")
        self.assertEqual(body["params"]["task_id"], "task-001")

    @patch('urllib.request.urlopen')
    def test_cancel_task(self, mock_urlopen):
        """Test cancelling an A2A task"""
        mock_urlopen.return_value = MockResponse({
            "result": {
                "id": "task-001",
                "source_agent_id": "agent-123",
                "target_agent_id": "agent-456",
                "status": "cancelled",
                "message": "Summarize this report",
            }
        })

        task = self.client.a2a.cancel_task("task-001")

        self.assertEqual(task.id, "task-001")
        self.assertEqual(task.status, "cancelled")

        # Verify JSON-RPC method
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["method"], "tasks/cancel")

    @patch('urllib.request.urlopen')
    def test_jsonrpc_unwraps_result(self, mock_urlopen):
        """Test that JSON-RPC result is properly unwrapped"""
        mock_urlopen.return_value = MockResponse({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "id": "task-003",
                "status": "pending",
                "message": "test",
            }
        })

        task = self.client.a2a.get_task("task-003")
        self.assertEqual(task.id, "task-003")

    @patch('urllib.request.urlopen')
    def test_send_message(self, mock_urlopen):
        """Test sending an A2A v1.0 message via message/send"""
        mock_urlopen.return_value = MockResponse({
            "result": {
                "id": "task-msg-001",
                "contextId": "ctx-001",
                "status": {
                    "state": "completed",
                    "timestamp": "2026-02-28T10:00:00Z",
                },
                "history": [
                    {"role": "user", "parts": [{"kind": "text", "text": "Hello"}]}
                ],
                "artifacts": [{"artifactId": "art-1", "parts": []}],
            }
        })

        task = self.client.a2a.send_message(
            agent_id="agent-456",
            text="Hello",
            message_id="msg-123",
        )

        self.assertIsInstance(task, A2AMessageTask)
        self.assertEqual(task.id, "task-msg-001")
        self.assertEqual(task.context_id, "ctx-001")
        self.assertEqual(task.state, "completed")
        self.assertEqual(task.status_timestamp, "2026-02-28T10:00:00Z")
        self.assertEqual(len(task.history), 1)
        self.assertEqual(len(task.artifacts), 1)

        # Verify JSON-RPC payload for message/send
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        # message/send targets the per-agent endpoint so the server resolves
        # the actor from the path, not a params field.
        self.assertTrue(request.full_url.endswith("/a2a/agents/agent-456"))
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["jsonrpc"], "2.0")
        self.assertEqual(body["method"], "message/send")
        self.assertNotIn("agent_id", body["params"])
        message = body["params"]["message"]
        self.assertEqual(message["role"], "user")
        self.assertEqual(message["parts"], [{"kind": "text", "text": "Hello"}])
        self.assertEqual(message["messageId"], "msg-123")
        self.assertNotIn("taskId", message)

    @patch('urllib.request.urlopen')
    def test_send_message_generates_id_and_task_id(self, mock_urlopen):
        """Test message/send auto-generates messageId and forwards taskId"""
        mock_urlopen.return_value = MockResponse({
            "result": {"id": "task-msg-002", "status": {"state": "working"}}
        })

        task = self.client.a2a.send_message(
            agent_id="agent-456",
            text="Continue",
            task_id="task-existing",
        )

        self.assertEqual(task.id, "task-msg-002")
        self.assertEqual(task.state, "working")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        message = body["params"]["message"]
        # A messageId is generated when not supplied
        self.assertTrue(message["messageId"])
        self.assertEqual(message["taskId"], "task-existing")


# ---------------------------------------------------------------------------
# MCP API tests
# ---------------------------------------------------------------------------

class TestMCPAPI(unittest.TestCase):
    """Test MCPAPI"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_register_server(self, mock_urlopen):
        """Test registering an MCP server"""
        mock_urlopen.return_value = MockResponse({
            "id": "srv-001",
            "name": "filesystem",
            "url": "http://localhost:9000",
            "capabilities": ["files:read", "files:write"],
            "org_id": "org-123",
            "created_at": "2026-02-28T10:00:00Z",
        })

        server = self.client.mcp.register_server(
            name="filesystem",
            url="http://localhost:9000",
            capabilities=["files:read", "files:write"],
        )

        self.assertEqual(server.id, "srv-001")
        self.assertEqual(server.name, "filesystem")
        self.assertEqual(server.url, "http://localhost:9000")
        self.assertEqual(server.capabilities, ["files:read", "files:write"])
        self.assertEqual(server.org_id, "org-123")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/mcp/servers", request.full_url)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["name"], "filesystem")
        self.assertEqual(body["url"], "http://localhost:9000")
        self.assertEqual(body["capabilities"], ["files:read", "files:write"])

    @patch('urllib.request.urlopen')
    def test_register_server_no_capabilities(self, mock_urlopen):
        """Test registering a server without capabilities"""
        mock_urlopen.return_value = MockResponse({
            "id": "srv-002",
            "name": "basic-server",
            "url": "http://localhost:9001",
        })

        server = self.client.mcp.register_server(
            name="basic-server",
            url="http://localhost:9001",
        )

        self.assertEqual(server.id, "srv-002")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertNotIn("capabilities", body)

    @patch('urllib.request.urlopen')
    def test_list_servers(self, mock_urlopen):
        """Test listing MCP servers"""
        mock_urlopen.return_value = MockResponse({
            "servers": [
                {"id": "srv-001", "name": "filesystem", "url": "http://localhost:9000", "capabilities": ["files:read"]},
                {"id": "srv-002", "name": "database", "url": "http://localhost:9001", "capabilities": ["db:query"]},
            ]
        })

        servers = self.client.mcp.list_servers()

        self.assertEqual(len(servers), 2)
        self.assertEqual(servers[0].id, "srv-001")
        self.assertEqual(servers[0].name, "filesystem")
        self.assertEqual(servers[1].id, "srv-002")
        self.assertEqual(servers[1].name, "database")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("/mcp/servers", request.full_url)

    @patch('urllib.request.urlopen')
    def test_list_servers_empty(self, mock_urlopen):
        """Test listing servers when none exist"""
        mock_urlopen.return_value = MockResponse({"servers": []})

        servers = self.client.mcp.list_servers()
        self.assertEqual(servers, [])

    @patch('urllib.request.urlopen')
    def test_remove_server(self, mock_urlopen):
        """Test removing an MCP server"""
        mock_urlopen.return_value = MockResponse({})

        self.client.mcp.remove_server("srv-001")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "DELETE")
        self.assertIn("/mcp/servers/srv-001", request.full_url)

    @patch('urllib.request.urlopen')
    def test_call_tool(self, mock_urlopen):
        """Test calling a tool through the MCP proxy"""
        mock_urlopen.return_value = MockResponse({
            "result": {
                "content": [{"type": "text", "text": "File contents here"}],
            }
        })

        result = self.client.mcp.call_tool(
            server_id="srv-001",
            agent_id="agent-001",
            method="tools/call",
            params={"name": "read_file", "arguments": {"path": "/tmp/data.txt"}},
        )

        self.assertIn("content", result)
        self.assertEqual(result["content"][0]["text"], "File contents here")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/mcp/srv-001", request.full_url)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["jsonrpc"], "2.0")
        self.assertEqual(body["method"], "tools/call")
        self.assertEqual(body["params"]["name"], "read_file")

    @patch('urllib.request.urlopen')
    def test_call_tool_no_params(self, mock_urlopen):
        """Test calling a tool without params"""
        mock_urlopen.return_value = MockResponse({
            "result": {"tools": []}
        })

        result = self.client.mcp.call_tool(
            server_id="srv-001",
            agent_id="agent-001",
            method="tools/list",
        )

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertNotIn("params", body)


# ---------------------------------------------------------------------------
# Delegations API tests
# ---------------------------------------------------------------------------

class TestDelegationsAPI(unittest.TestCase):
    """Test DelegationsAPI"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_create_delegation(self, mock_urlopen):
        """Test creating a delegation"""
        mock_urlopen.return_value = MockResponse({
            "id": "del-001",
            "from_agent_id": "agent-123",
            "to_agent_id": "agent-456",
            "scope": ["files:read"],
            "restrictions": {"paths": ["/tmp/*"]},
            "delegation_chain": ["del-001"],
            "expires_at": "2026-02-28T11:00:00Z",
            "created_at": "2026-02-28T10:00:00Z",
        })

        delegation = self.client.delegations.create(
            from_agent_id="agent-123",
            to_agent_id="agent-456",
            scope=["files:read"],
            ttl_seconds=3600,
            restrictions={"paths": ["/tmp/*"]},
        )

        self.assertEqual(delegation.id, "del-001")
        self.assertEqual(delegation.from_agent_id, "agent-123")
        self.assertEqual(delegation.to_agent_id, "agent-456")
        self.assertEqual(delegation.scope, ["files:read"])
        self.assertEqual(delegation.restrictions, {"paths": ["/tmp/*"]})
        self.assertIsNotNone(delegation.expires_at)
        self.assertIsNotNone(delegation.created_at)

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/api/v1/delegations", request.full_url)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["from_agent_id"], "agent-123")
        self.assertEqual(body["to_agent_id"], "agent-456")
        self.assertEqual(body["scope"], ["files:read"])
        self.assertEqual(body["ttl_seconds"], 3600)
        self.assertEqual(body["restrictions"], {"paths": ["/tmp/*"]})

    @patch('urllib.request.urlopen')
    def test_create_delegation_minimal(self, mock_urlopen):
        """Test creating a delegation with minimal args"""
        mock_urlopen.return_value = MockResponse({
            "id": "del-002",
            "from_agent_id": "agent-123",
            "to_agent_id": "agent-456",
            "scope": ["web:fetch"],
        })

        delegation = self.client.delegations.create(
            from_agent_id="agent-123",
            to_agent_id="agent-456",
            scope=["web:fetch"],
        )

        self.assertEqual(delegation.id, "del-002")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["ttl_seconds"], 3600)  # default
        self.assertNotIn("restrictions", body)
        self.assertNotIn("parent_delegation_id", body)

    @patch('urllib.request.urlopen')
    def test_create_delegation_with_parent(self, mock_urlopen):
        """Test creating a chained delegation"""
        mock_urlopen.return_value = MockResponse({
            "id": "del-003",
            "from_agent_id": "agent-456",
            "to_agent_id": "agent-789",
            "scope": ["files:read"],
            "delegation_chain": ["del-001", "del-003"],
        })

        delegation = self.client.delegations.create(
            from_agent_id="agent-456",
            to_agent_id="agent-789",
            scope=["files:read"],
            parent_delegation_id="del-001",
        )

        self.assertEqual(delegation.id, "del-003")
        self.assertEqual(delegation.delegation_chain, ["del-001", "del-003"])

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["parent_delegation_id"], "del-001")

    @patch('urllib.request.urlopen')
    def test_list_delegations(self, mock_urlopen):
        """Test listing delegations"""
        mock_urlopen.return_value = MockResponse({
            "delegations": [
                {"id": "del-001", "from_agent_id": "a1", "to_agent_id": "a2", "scope": ["files:read"]},
                {"id": "del-002", "from_agent_id": "a2", "to_agent_id": "a3", "scope": ["web:fetch"]},
            ]
        })

        delegations = self.client.delegations.list()

        self.assertEqual(len(delegations), 2)
        self.assertEqual(delegations[0].id, "del-001")
        self.assertEqual(delegations[1].id, "del-002")
        self.assertEqual(delegations[0].scope, ["files:read"])
        self.assertEqual(delegations[1].scope, ["web:fetch"])

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("/api/v1/delegations", request.full_url)

    @patch('urllib.request.urlopen')
    def test_list_delegations_empty(self, mock_urlopen):
        """Test listing delegations when none exist"""
        mock_urlopen.return_value = MockResponse({"delegations": []})

        delegations = self.client.delegations.list()
        self.assertEqual(delegations, [])

    @patch('urllib.request.urlopen')
    def test_revoke_delegation(self, mock_urlopen):
        """Test revoking a delegation"""
        mock_urlopen.return_value = MockResponse({})

        self.client.delegations.revoke("del-001")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "DELETE")
        self.assertIn("/api/v1/delegations/del-001", request.full_url)

    @patch('urllib.request.urlopen')
    def test_init_delegated_session(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "session_id": "sess-del-001",
            "agent_id": "agent-456",
            "delegation_id": "del-001",
            "source": "a2a",
            "mode": "read_only",
            "scope_ceiling": ["files:read"],
        })

        session = self.client.delegations.init_session("del-001")

        self.assertEqual(session.session_id, "sess-del-001")
        self.assertEqual(session.delegation_id, "del-001")
        self.assertEqual(session.source, "a2a")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/api/v1/delegations/del-001/session", request.full_url)


class TestFederationAPI(unittest.TestCase):
    """Test FederationAPI"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_register_and_list_providers(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "provider": {
                "id": "prov-001",
                "org_id": "org-001",
                "issuer": "https://issuer.example.com",
                "name": "Example Issuer",
                "jwks_uri": "https://issuer.example.com/jwks",
                "trust_level": "high",
                "status": "active",
            }
        })

        provider = self.client.federation.register_provider(
            issuer="https://issuer.example.com",
            name="Example Issuer",
            trust_level="high",
        )
        self.assertEqual(provider.id, "prov-001")
        self.assertEqual(provider.trust_level, "high")

        mock_urlopen.return_value = MockResponse({
            "providers": [
                {
                    "id": "prov-001",
                    "org_id": "org-001",
                    "issuer": "https://issuer.example.com",
                    "name": "Example Issuer",
                    "jwks_uri": "https://issuer.example.com/jwks",
                    "trust_level": "high",
                    "status": "active",
                }
            ]
        })
        providers = self.client.federation.list_providers()
        self.assertEqual(len(providers), 1)
        self.assertEqual(providers[0].issuer, "https://issuer.example.com")

    @patch('urllib.request.urlopen')
    def test_verify_token_and_init_session(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "valid": True,
            "agent_id": "agent-remote-1",
            "issuer": "https://issuer.example.com",
            "expires_at": "2026-03-01T10:15:00Z",
        })

        result = self.client.federation.verify_token("eyJ.federated-token")
        self.assertTrue(result.valid)
        self.assertEqual(result.agent_id, "agent-remote-1")

        mock_urlopen.return_value = MockResponse({
            "session_id": "sess-fed-001",
            "agent_id": "agent-remote-1",
            "provider_id": "prov-001",
            "issuer": "https://issuer.example.com",
            "trust_level": "high",
            "source": "federation",
            "mode": "read_only",
            "scope_ceiling": ["federation:invoke"],
        })
        session = self.client.federation.init_session("eyJ.federated-token")
        self.assertEqual(session.session_id, "sess-fed-001")
        self.assertEqual(session.provider_id, "prov-001")
        self.assertEqual(session.trust_level, "high")


class TestStreamingAPI(unittest.TestCase):
    """Test StreamingAPI"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_crud_and_logs(self, mock_urlopen):
        mock_urlopen.return_value = MockResponse({
            "id": "dest-001",
            "name": "Splunk Prod",
            "destination_type": "splunk_hec",
            "endpoint_url": "https://splunk.example.com",
            "is_active": True,
            "batch_size": 100,
            "flush_interval_seconds": 30,
        })
        destination = self.client.streaming.create(
            name="Splunk Prod",
            destination_type="splunk_hec",
            endpoint_url="https://splunk.example.com",
        )
        self.assertEqual(destination.id, "dest-001")

        mock_urlopen.return_value = MockResponse({
            "destinations": [
                {
                    "id": "dest-001",
                    "name": "Splunk Prod",
                    "destination_type": "splunk_hec",
                    "endpoint_url": "https://splunk.example.com",
                    "is_active": True,
                    "batch_size": 100,
                    "flush_interval_seconds": 30,
                }
            ]
        })
        self.assertEqual(len(self.client.streaming.list()), 1)

        mock_urlopen.return_value = MockResponse({
            "logs": [
                {
                    "id": "log-001",
                    "destination_id": "dest-001",
                    "batch_size": 50,
                    "status": "success",
                    "delivered_at": "2026-03-01T10:00:00Z",
                }
            ]
        })
        logs = self.client.streaming.delivery_log("dest-001")
        self.assertEqual(logs[0].destination_id, "dest-001")


# ---------------------------------------------------------------------------
# Model tests for new dataclasses
# ---------------------------------------------------------------------------

class TestAgentCardModel(unittest.TestCase):
    """Test AgentCard model (A2A v1.0)"""

    def test_from_dict_full(self):
        """Test creating AgentCard from a full v1.0 dict"""
        card = AgentCard.from_dict(make_v1_card())

        self.assertEqual(card.name, "my-agent")
        self.assertEqual(card.description, "A test agent")
        self.assertEqual(card.version, "1.0.0")
        self.assertEqual(len(card.supported_interfaces), 1)
        self.assertEqual(card.supported_interfaces[0]["protocolBinding"], "jsonrpc")
        self.assertEqual(card.provider["organization"], "ATI")
        self.assertTrue(card.capabilities["streaming"])
        self.assertEqual(card.security_schemes["bearer"]["scheme"], "bearer")
        self.assertEqual(card.security_requirements, [{"bearer": []}])
        self.assertEqual(card.default_input_modes, ["text/plain"])
        self.assertEqual(card.default_output_modes, ["text/plain"])
        self.assertEqual(card.skills[0]["tags"], ["nlp", "summary"])
        self.assertEqual(len(card.signatures), 1)
        self.assertEqual(card.documentation_url, "https://agenttrust.id/docs")
        self.assertEqual(card.icon_url, "https://agenttrust.id/icon.png")
        # Derived accessors
        self.assertEqual(card.primary_url, "http://localhost:8080/a2a/agents/agent-123")
        self.assertAlmostEqual(card.trust_score, 0.87)

    def test_from_dict_minimal(self):
        """Test creating AgentCard from a minimal dict (older cached card)"""
        data = {"name": "minimal-agent"}
        card = AgentCard.from_dict(data)

        self.assertEqual(card.name, "minimal-agent")
        self.assertEqual(card.supported_interfaces, [])
        self.assertEqual(card.capabilities, {})
        self.assertEqual(card.skills, [])
        self.assertIsNone(card.signatures)
        self.assertIsNone(card.provider)
        self.assertIsNone(card.security_schemes)
        # No interfaces and no legacy url -> empty primary_url; no extension -> 0.0
        self.assertEqual(card.primary_url, "")
        self.assertEqual(card.trust_score, 0.0)

    def test_parsing_tolerates_missing_fields(self):
        """Parsing must not raise when url/supportedInterfaces/signatures absent"""
        # Completely empty dict
        card = AgentCard.from_dict({})
        self.assertEqual(card.name, "")
        self.assertEqual(card.primary_url, "")
        self.assertEqual(card.trust_score, 0.0)

    def test_primary_url_falls_back_to_legacy_url(self):
        """A pre-v1.0 card with a top-level url still resolves primary_url"""
        card = AgentCard.from_dict({
            "name": "legacy-agent",
            "url": "http://legacy.example.com/agent.json",
        })
        self.assertEqual(card.primary_url, "http://legacy.example.com/agent.json")

    def test_trust_score_default_when_extension_missing(self):
        """trust_score is 0.0 when the trust extension is absent"""
        card = AgentCard.from_dict({
            "name": "no-trust",
            "capabilities": {"streaming": False, "extensions": [
                {"uri": "https://other.example/ext", "params": {"x": 1}}
            ]},
        })
        self.assertEqual(card.trust_score, 0.0)


class TestA2ATaskModel(unittest.TestCase):
    """Test A2ATask model"""

    def test_from_dict_full(self):
        """Test creating A2ATask from dict with all fields"""
        data = {
            "id": "task-001",
            "source_agent_id": "agent-123",
            "target_agent_id": "agent-456",
            "status": "completed",
            "message": "Summarize this",
            "artifacts": [{"type": "text", "content": "Done"}],
            "metadata": {"priority": "high"},
            "created_at": "2026-02-28T10:00:00Z",
            "updated_at": "2026-02-28T10:05:00Z",
        }
        task = A2ATask.from_dict(data)

        self.assertEqual(task.id, "task-001")
        self.assertEqual(task.source_agent_id, "agent-123")
        self.assertEqual(task.target_agent_id, "agent-456")
        self.assertEqual(task.status, "completed")
        self.assertEqual(task.message, "Summarize this")
        self.assertEqual(len(task.artifacts), 1)
        self.assertEqual(task.metadata["priority"], "high")
        self.assertIsNotNone(task.created_at)
        self.assertIsNotNone(task.updated_at)

    def test_from_dict_minimal(self):
        """Test creating A2ATask from minimal dict"""
        data = {"id": "task-002"}
        task = A2ATask.from_dict(data)

        self.assertEqual(task.id, "task-002")
        self.assertEqual(task.status, "pending")
        self.assertEqual(task.message, "")
        self.assertEqual(task.artifacts, [])
        self.assertIsNone(task.created_at)


class TestMCPServerModel(unittest.TestCase):
    """Test MCPServer model"""

    def test_from_dict_full(self):
        """Test creating MCPServer from dict with all fields"""
        data = {
            "id": "srv-001",
            "name": "filesystem",
            "url": "http://localhost:9000",
            "capabilities": ["files:read", "files:write"],
            "org_id": "org-123",
            "created_at": "2026-02-28T10:00:00Z",
        }
        server = MCPServer.from_dict(data)

        self.assertEqual(server.id, "srv-001")
        self.assertEqual(server.name, "filesystem")
        self.assertEqual(server.url, "http://localhost:9000")
        self.assertEqual(server.capabilities, ["files:read", "files:write"])
        self.assertEqual(server.org_id, "org-123")
        self.assertIsNotNone(server.created_at)

    def test_from_dict_minimal(self):
        """Test creating MCPServer from minimal dict"""
        data = {"id": "srv-002"}
        server = MCPServer.from_dict(data)

        self.assertEqual(server.id, "srv-002")
        self.assertEqual(server.name, "")
        self.assertEqual(server.capabilities, [])
        self.assertIsNone(server.created_at)


class TestDelegationModel(unittest.TestCase):
    """Test Delegation model"""

    def test_from_dict_full(self):
        """Test creating Delegation from dict with all fields"""
        data = {
            "id": "del-001",
            "from_agent_id": "agent-123",
            "to_agent_id": "agent-456",
            "scope": ["files:read"],
            "restrictions": {"paths": ["/tmp/*"]},
            "delegation_chain": ["del-001"],
            "expires_at": "2026-02-28T11:00:00Z",
            "revoked_at": None,
            "created_at": "2026-02-28T10:00:00Z",
        }
        delegation = Delegation.from_dict(data)

        self.assertEqual(delegation.id, "del-001")
        self.assertEqual(delegation.from_agent_id, "agent-123")
        self.assertEqual(delegation.to_agent_id, "agent-456")
        self.assertEqual(delegation.scope, ["files:read"])
        self.assertEqual(delegation.restrictions, {"paths": ["/tmp/*"]})
        self.assertEqual(delegation.delegation_chain, ["del-001"])
        self.assertIsNotNone(delegation.expires_at)
        self.assertIsNone(delegation.revoked_at)
        self.assertIsNotNone(delegation.created_at)

    def test_from_dict_minimal(self):
        """Test creating Delegation from minimal dict"""
        data = {"id": "del-002"}
        delegation = Delegation.from_dict(data)

        self.assertEqual(delegation.id, "del-002")
        self.assertEqual(delegation.scope, [])
        self.assertEqual(delegation.restrictions, {})
        self.assertEqual(delegation.delegation_chain, [])
        self.assertIsNone(delegation.expires_at)
        self.assertIsNone(delegation.revoked_at)

    def test_from_dict_with_revoked(self):
        """Test creating Delegation that has been revoked"""
        data = {
            "id": "del-003",
            "from_agent_id": "agent-123",
            "to_agent_id": "agent-456",
            "scope": ["files:read"],
            "revoked_at": "2026-02-28T10:30:00Z",
            "created_at": "2026-02-28T10:00:00Z",
        }
        delegation = Delegation.from_dict(data)

        self.assertIsNotNone(delegation.revoked_at)
        self.assertIsNotNone(delegation.created_at)


# ---------------------------------------------------------------------------
# Client integration: verify lazy property initialization
# ---------------------------------------------------------------------------

class TestClientProtocolProperties(unittest.TestCase):
    """Test that AgentTrustClient correctly exposes protocol API properties"""

    def test_a2a_property(self):
        """Test a2a property is lazily initialized"""
        client = AgentTrustClient()
        self.assertIsInstance(client.a2a, A2AAPI)
        # Same instance on second access
        self.assertIs(client.a2a, client.a2a)

    def test_agent_cards_property(self):
        """Test agent_cards property is lazily initialized"""
        client = AgentTrustClient()
        self.assertIsInstance(client.agent_cards, AgentCardsAPI)
        self.assertIs(client.agent_cards, client.agent_cards)

    def test_mcp_property(self):
        """Test mcp property is lazily initialized"""
        client = AgentTrustClient()
        self.assertIsInstance(client.mcp, MCPAPI)
        self.assertIs(client.mcp, client.mcp)

    def test_delegations_property(self):
        """Test delegations property is lazily initialized"""
        client = AgentTrustClient()
        self.assertIsInstance(client.delegations, DelegationsAPI)
        self.assertIs(client.delegations, client.delegations)

    def test_federation_property(self):
        client = AgentTrustClient()
        self.assertIsInstance(client.federation, FederationAPI)
        self.assertIs(client.federation, client.federation)

    def test_streaming_property(self):
        client = AgentTrustClient()
        self.assertIsInstance(client.streaming, StreamingAPI)
        self.assertIs(client.streaming, client.streaming)


if __name__ == "__main__":
    unittest.main()
