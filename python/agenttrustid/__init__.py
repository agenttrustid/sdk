"""
AgentTrust SDK - Authentication, authorization, and runtime security for AI agents.

Quick Start:
    from agenttrustid import AgentTrustClient

    # Initialize with gateway URL and API key
    client = AgentTrustClient(base_url="http://localhost:8080", api_key="sk_live_xxx")

    # Create an agent
    agent = client.agents.create(name="my-agent", framework="langchain")

    # LangChain integration (pip install agenttrustid[langchain])
    from agenttrustid.callback import AgentTrustCallbackHandler
    handler = AgentTrustCallbackHandler(client, agent_id=agent.id)
    agent_executor.invoke({"input": "..."}, config={"callbacks": [handler]})

    # CrewAI integration
    from agenttrustid.crewai_callback import AgentTrustCrewAIToolWrapper, agenttrust_protect_crew

    # AutoGen integration
    from agenttrustid.autogen_callback import AgentTrustAutoGenToolWrapper, agenttrust_wrap_tool

"""

from .client import AgentTrustClient
from .models import (
    Agent,
    Token,
    IntrospectionResult,
    VerificationResult,
    ActionCheckResult,
    AgentCard,
    A2ATask,
    A2AMessageTask,
    MCPServer,
    Delegation,
    Session,
    ApprovalRequest,
    FederationProvider,
    FederationIntrospectionResult,
    VerifyFederatedTokenResult,
    SIEMDestination,
    SIEMDeliveryRecord,
)
from .a2a import A2AAPI
from .agentcard import AgentCardsAPI
from .mcp_client import MCPAPI
from .delegation import DelegationsAPI
from .federation import FederationAPI
from .streaming import StreamingAPI
from .client import SessionsAPI, ApprovalsAPI
from .guard import AgentTrustGuard
from .exceptions import (
    AgentTrustError,
    AuthenticationError,
    AuthorizationError,
    TokenExpiredError,
    AgentRevokedError,
    NetworkError,
    ValidationError,
)

__version__ = "0.3.0"
__all__ = [
    "AgentTrustClient",
    "AgentTrustGuard",
    "Agent",
    "Token",
    "IntrospectionResult",
    "VerificationResult",
    "ActionCheckResult",
    "AgentCard",
    "A2ATask",
    "A2AMessageTask",
    "MCPServer",
    "Delegation",
    "Session",
    "ApprovalRequest",
    "FederationProvider",
    "FederationIntrospectionResult",
    "VerifyFederatedTokenResult",
    "SIEMDestination",
    "SIEMDeliveryRecord",
    "A2AAPI",
    "AgentCardsAPI",
    "MCPAPI",
    "DelegationsAPI",
    "FederationAPI",
    "StreamingAPI",
    "SessionsAPI",
    "ApprovalsAPI",
    "AgentTrustError",
    "AuthenticationError",
    "AuthorizationError",
    "TokenExpiredError",
    "AgentRevokedError",
    "NetworkError",
    "ValidationError",
]
