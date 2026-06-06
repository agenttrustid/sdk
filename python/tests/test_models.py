"""Tests for AgentTrust SDK models"""

import unittest
from datetime import datetime, timedelta, timezone

import sys
sys.path.insert(0, '..')

from agenttrustid.models import Agent, Token, IntrospectionResult, AgentStatus


class TestAgent(unittest.TestCase):
    """Test Agent model"""

    def test_from_dict_basic(self):
        """Test creating Agent from dict"""
        data = {
            "id": "agent-123",
            "name": "test-agent",
            "org_id": "org-456",
            "framework": "langchain",
            "public_key": "pk_xxx",
            "status": "active",
            "capabilities": ["files:read"],
            "metadata": {"env": "test"},
        }
        agent = Agent.from_dict(data)

        self.assertEqual(agent.id, "agent-123")
        self.assertEqual(agent.name, "test-agent")
        self.assertEqual(agent.framework, "langchain")
        self.assertEqual(agent.status, AgentStatus.ACTIVE)
        self.assertEqual(agent.capabilities, ["files:read"])

    def test_from_dict_nested_response(self):
        """Test parsing the {"agent": {...}} wrapper format"""
        data = {
            "agent": {
                "id": "agent-123",
                "name": "test-agent",
                "org_id": "org-456",
                "framework": "custom",
                "public_key": "pk_xxx",
                "status": "active",
            }
        }
        agent = Agent.from_dict(data)

        self.assertEqual(agent.id, "agent-123")
        self.assertEqual(agent.name, "test-agent")

    def test_from_dict_with_private_key(self):
        """Test Agent with private key (creation response)"""
        data = {
            "id": "agent-123",
            "name": "new-agent",
            "org_id": "org-456",
            "framework": "crewai",
            "public_key": "pk_xxx",
            "private_key": "-----BEGIN PRIVATE KEY-----",
        }
        agent = Agent.from_dict(data)

        self.assertEqual(agent.private_key, "-----BEGIN PRIVATE KEY-----")


class TestToken(unittest.TestCase):
    """Test Token model"""

    def test_from_dict(self):
        """Test creating Token from dict"""
        data = {
            "token": "at_xK3z9abcdef",
            "agent_id": "agent-123",
            "scope": ["files:read", "files:write"],
            "audience": ["mcp://filesystem"],
            "issued_at": "2024-01-01T00:00:00Z",
            "expires_at": "2024-01-01T00:05:00Z",
            "token_id": "tok-456",
        }
        token = Token.from_dict(data)

        self.assertEqual(token.token, "at_xK3z9abcdef")
        self.assertTrue(token.token.startswith("at_"))
        self.assertEqual(token.agent_id, "agent-123")
        self.assertEqual(token.scopes, ["files:read", "files:write"])
        self.assertEqual(token.token_id, "tok-456")

    def test_is_expired(self):
        """Test token expiration check"""
        # Expired token
        expired_token = Token(
            token="at_expired",
            agent_id="agent-123",
            scopes=["test"],
            audience=[],
            issued_at=datetime.now(timezone.utc) - timedelta(hours=1),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=30),
        )
        self.assertTrue(expired_token.is_expired)

        # Valid token
        valid_token = Token(
            token="at_valid",
            agent_id="agent-123",
            scopes=["test"],
            audience=[],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        self.assertFalse(valid_token.is_expired)

    def test_ttl_seconds(self):
        """Test TTL calculation"""
        token = Token(
            token="at_ttl",
            agent_id="agent-123",
            scopes=["test"],
            audience=[],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=300),
        )
        # Should be close to 300 (within a few seconds)
        self.assertGreater(token.ttl_seconds, 295)
        self.assertLessEqual(token.ttl_seconds, 300)


class TestIntrospectionResult(unittest.TestCase):
    """Test IntrospectionResult model"""

    def test_from_dict_active(self):
        """Test active result"""
        data = {
            "active": True,
            "agent_id": "agent-123",
            "org_id": "org-456",
            "scopes": ["files:read"],
            "reasoning": "Token valid, scopes sufficient",
        }
        result = IntrospectionResult.from_dict(data)

        self.assertTrue(result.active)
        self.assertEqual(result.agent_id, "agent-123")
        self.assertEqual(result.org_id, "org-456")

    def test_from_dict_inactive(self):
        """Test inactive result"""
        data = {
            "active": False,
            "reasoning": "Token revoked",
        }
        result = IntrospectionResult.from_dict(data)

        self.assertFalse(result.active)
        self.assertEqual(result.reasoning, "Token revoked")


if __name__ == "__main__":
    unittest.main()
