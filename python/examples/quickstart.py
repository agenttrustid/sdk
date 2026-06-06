#!/usr/bin/env python3
"""
AgentTrust ID SDK Quick Start Example

This example demonstrates:
1. Creating an agent
2. Issuing an opaque agent token
3. Introspecting (server-side validating) the token
4. Handling errors

Prerequisites:
    - AgentTrust ID services running (docker-compose up)
    - pip install -e sdk/python

Run:
    python sdk/python/examples/quickstart.py
"""

from pathlib import Path
import sys

# Add SDK to path for development
sys.path.insert(0, str(Path(__file__).parent.parent))

from agenttrustid import (
    AgentTrustClient,
    AuthenticationError,
    AuthorizationError,
    NetworkError,
)


def main():
    print("=" * 60)
    print("AgentTrust ID SDK Quick Start")
    print("=" * 60)

    # 1. Connect to AgentTrust ID
    print("\n1. Connecting to AgentTrust ID...")
    try:
        client = AgentTrustClient(base_url="http://localhost:8080")
        health = client.health()
        print(f"   Connected! Service status: {health.get('status', 'unknown')}")
    except NetworkError as e:
        print(f"   ERROR: Could not connect to AgentTrust ID services")
        print(f"   Make sure AgentTrust ID is running: docker-compose up")
        print(f"   Details: {e.message}")
        return 1

    # 2. Create an agent
    print("\n2. Creating agent...")
    try:
        agent = client.agents.create(
            name="quickstart-agent",
            framework="custom",
            capabilities=["files:read", "files:write", "web:fetch"],
            metadata={"environment": "development", "version": "1.0"}
        )
        print(f"   Agent ID: {agent.id}")
        print(f"   Name: {agent.name}")
        print(f"   Framework: {agent.framework}")
        print(f"   Status: {agent.status.value}")

    except AuthenticationError as e:
        print(f"   ERROR: Authentication failed - {e.message}")
        return 1

    # 3. Issue a token
    print("\n3. Issuing token...")
    try:
        token = client.tokens.issue(
            agent_id=agent.id,
            scopes=["files:read", "files:write"],
            ttl_seconds=300  # 5 minutes
        )
        print(f"   Token issued!")
        print(f"   Scopes: {token.scopes}")
        print(f"   Expires in: {token.ttl_seconds} seconds")
        # Tokens are opaque random strings (e.g. "at_xK3z9..."), not JWTs.
        # Show a prefix only — never log full tokens in production.
        print(f"   Token prefix: {token.token[:12]}...")

    except AuthorizationError as e:
        print(f"   ERROR: Not authorized - {e.message}")
        return 1

    # 4. Introspect the token (server-side validation)
    print("\n4. Introspecting token...")
    result = client.tokens.introspect(
        token=token.token,
        target="mcp://filesystem",
        required_scopes=["files:read"]
    )
    print(f"   Active: {result.active}")
    print(f"   Agent ID: {result.agent_id}")
    print(f"   Scopes: {result.scopes}")
    if result.reasoning:
        print(f"   Reasoning: {result.reasoning}")

    # 5. Demonstrate token caching
    print("\n5. Token caching...")
    token2 = client.tokens.issue(
        agent_id=agent.id,
        scopes=["files:read", "files:write"],
    )
    if token2.token == token.token:
        print("   Cached token returned (same opaque token)")
    else:
        print("   New token issued")

    # 6. List agents
    print("\n6. Listing agents...")
    agents = client.agents.list()
    print(f"   Found {len(agents)} agent(s)")
    for a in agents[:5]:  # Show first 5
        print(f"   - {a.name} ({a.id})")

    print("\n" + "=" * 60)
    print("Quick start complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("  - Integrate tokens into your AI agent's tool calls")
    print("  - Use client.tokens.introspect() in your MCP servers")
    print("  - Check docs/architecture.md for system details")

    return 0


if __name__ == "__main__":
    sys.exit(main())
