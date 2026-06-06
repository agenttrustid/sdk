"""Tests for AgentTrust SDK client with mocked HTTP"""

import unittest
from unittest.mock import patch, MagicMock
import json

import sys
sys.path.insert(0, '..')

from agenttrustid import AgentTrustClient
from agenttrustid.exceptions import (
    AuthenticationError,
    AuthorizationError,
    NetworkError,
    ValidationError,
)


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


class TestAgentTrustClient(unittest.TestCase):
    """Test AgentTrustClient initialization"""

    def test_init_defaults(self):
        """Test default initialization"""
        client = AgentTrustClient()
        self.assertIsNotNone(client.agents)
        self.assertIsNotNone(client.tokens)

    def test_init_custom_urls(self):
        """Test custom URL initialization"""
        client = AgentTrustClient(
            base_url="https://ati.example.com:8081",
            auth_url="https://ati.example.com:8082",
        )
        self.assertEqual(client._http.base_url, "https://ati.example.com:8081")

    def test_from_env(self):
        """Test initialization from environment"""
        with patch.dict('os.environ', {
            'AGENTTRUST_BASE_URL': 'http://test:8081',
            'AGENTTRUST_AUTH_URL': 'http://test:8082',
        }):
            client = AgentTrustClient.from_env()
            self.assertEqual(client._http.base_url, "http://test:8081")


class TestAgentsAPI(unittest.TestCase):
    """Test agents API"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8081")

    @patch('urllib.request.urlopen')
    def test_create_agent(self, mock_urlopen):
        """Test agent creation"""
        mock_response = MockResponse({
            "id": "agent-123",
            "name": "test-agent",
            "org_id": "org-456",
            "framework": "langchain",
            "public_key": "pk_xxx",
            "private_key": "-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----",
            "status": "active",
            "capabilities": ["files:read"],
        })
        mock_urlopen.return_value = mock_response

        agent = self.client.agents.create(
            name="test-agent",
            framework="langchain",
            capabilities=["files:read"],
        )

        self.assertEqual(agent.id, "agent-123")
        self.assertEqual(agent.name, "test-agent")
        self.assertIsNotNone(agent.private_key)

        request = mock_urlopen.call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/api/v1/agents", request.full_url)

    @patch('urllib.request.urlopen')
    def test_get_agent(self, mock_urlopen):
        """Test getting an agent"""
        mock_response = MockResponse({
            "id": "agent-123",
            "name": "test-agent",
            "org_id": "org-456",
            "framework": "custom",
            "public_key": "pk_xxx",
            "status": "active",
        })
        mock_urlopen.return_value = mock_response

        agent = self.client.agents.get("agent-123")

        self.assertEqual(agent.id, "agent-123")
        self.assertEqual(agent.name, "test-agent")

        request = mock_urlopen.call_args[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("/api/v1/agents/agent-123", request.full_url)

    @patch('urllib.request.urlopen')
    def test_list_agents(self, mock_urlopen):
        """Test listing agents"""
        mock_response = MockResponse({
            "agents": [
                {"id": "agent-1", "name": "agent-one", "org_id": "org", "framework": "custom", "public_key": "pk1"},
                {"id": "agent-2", "name": "agent-two", "org_id": "org", "framework": "custom", "public_key": "pk2"},
            ]
        })
        mock_urlopen.return_value = mock_response

        agents = self.client.agents.list()

        self.assertEqual(len(agents), 2)
        self.assertEqual(agents[0].name, "agent-one")
        self.assertEqual(agents[1].name, "agent-two")

        request = mock_urlopen.call_args[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("/api/v1/agents", request.full_url)


class TestTokensAPI(unittest.TestCase):
    """Test tokens API"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8081")

    @patch('urllib.request.urlopen')
    def test_issue_token(self, mock_urlopen):
        """Test token issuance"""
        mock_response = MockResponse({
            "token": "at_xK3z9abcdef123",
            "agent_id": "agent-123",
            "scope": ["files:read", "files:write"],
            "audience": ["mcp://filesystem"],
            "issued_at": "2024-01-01T00:00:00Z",
            "expires_at": "2024-01-01T00:05:00Z",
            "token_id": "tok-456",
        })
        mock_urlopen.return_value = mock_response

        token = self.client.tokens.issue(
            agent_id="agent-123",
            scopes=["files:read", "files:write"],
            target="mcp://filesystem",
        )

        self.assertEqual(token.agent_id, "agent-123")
        self.assertEqual(token.scopes, ["files:read", "files:write"])
        self.assertTrue(token.token.startswith("at_"))

        request = mock_urlopen.call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/api/v1/agent-tokens/issue", request.full_url)

    @patch('urllib.request.urlopen')
    def test_introspect_token_active(self, mock_urlopen):
        """Test token introspection - active"""
        mock_response = MockResponse({
            "active": True,
            "agent_id": "agent-123",
            "org_id": "org-1",
            "scopes": ["files:read"],
            "reasoning": "Token valid, scopes sufficient",
        })
        mock_urlopen.return_value = mock_response

        result = self.client.tokens.introspect(
            token="at_xxx",
            target="mcp://filesystem",
        )

        self.assertTrue(result.active)
        self.assertEqual(result.agent_id, "agent-123")
        self.assertEqual(result.org_id, "org-1")

        request = mock_urlopen.call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/api/v1/agent-tokens/introspect", request.full_url)

    @patch('urllib.request.urlopen')
    def test_introspect_token_inactive(self, mock_urlopen):
        """Test token introspection - inactive"""
        mock_response = MockResponse({
            "active": False,
            "reasoning": "Token revoked",
        })
        mock_urlopen.return_value = mock_response

        result = self.client.tokens.introspect(token="at_xxx")

        self.assertFalse(result.active)
        self.assertEqual(result.reasoning, "Token revoked")

        request = mock_urlopen.call_args[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("/api/v1/agent-tokens/introspect", request.full_url)

    def test_token_caching(self):
        """Test that tokens are cached"""
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MockResponse({
                "token": "at_cached_xxx",
                "agent_id": "agent-123",
                "scope": ["files:read"],
                "audience": ["mcp://filesystem"],
                "issued_at": "2024-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:05:00Z",  # Far future
            })
            mock_urlopen.return_value = mock_response

            # First call
            token1 = self.client.tokens.issue(
                agent_id="agent-123",
                scopes=["files:read"],
                target="mcp://filesystem",
            )

            # Second call should use cache (urlopen called only once)
            token2 = self.client.tokens.issue(
                agent_id="agent-123",
                scopes=["files:read"],
                target="mcp://filesystem",
            )

            self.assertEqual(token1.token, token2.token)
            self.assertEqual(mock_urlopen.call_count, 1)

    def test_cache_bypass(self):
        """Test cache can be bypassed"""
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MockResponse({
                "token": "at_new_xxx",
                "agent_id": "agent-123",
                "scope": ["files:read"],
                "audience": [],
                "issued_at": "2024-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:05:00Z",
            })
            mock_urlopen.return_value = mock_response

            # First call
            self.client.tokens.issue(
                agent_id="agent-123",
                scopes=["files:read"],
                use_cache=False,
            )

            # Second call with cache bypass
            self.client.tokens.issue(
                agent_id="agent-123",
                scopes=["files:read"],
                use_cache=False,
            )

            # Both should hit the API
            self.assertEqual(mock_urlopen.call_count, 2)


class TestErrorHandling(unittest.TestCase):
    """Test error handling"""

    def setUp(self):
        self.client = AgentTrustClient(base_url="http://localhost:8081")

    @patch('urllib.request.urlopen')
    def test_authentication_error(self, mock_urlopen):
        """Test 401 raises AuthenticationError"""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"message": "Invalid credentials"}'),
        )

        with self.assertRaises(AuthenticationError) as ctx:
            self.client.agents.get("agent-123")

        self.assertIn("Invalid credentials", str(ctx.exception))

    @patch('urllib.request.urlopen')
    def test_authorization_error(self, mock_urlopen):
        """Test 403 raises AuthorizationError"""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"message": "Insufficient permissions"}'),
        )

        with self.assertRaises(AuthorizationError) as ctx:
            self.client.tokens.issue(agent_id="x", scopes=["admin"])

        self.assertIn("Insufficient permissions", str(ctx.exception))

    @patch('urllib.request.urlopen')
    def test_validation_error(self, mock_urlopen):
        """Test 400 raises ValidationError"""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"message": "Invalid agent name"}'),
        )

        with self.assertRaises(ValidationError):
            self.client.agents.create(name="")

    @patch('urllib.request.urlopen')
    def test_network_error(self, mock_urlopen):
        """Test network errors raise NetworkError"""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        with self.assertRaises(NetworkError):
            self.client.health()


if __name__ == "__main__":
    unittest.main()
