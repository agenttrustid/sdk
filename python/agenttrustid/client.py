"""AgentTrust SDK Main Client"""

import base64
import json
import ssl
import time
import warnings
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from pathlib import Path
import urllib.request
import urllib.error

from .models import (
    Agent, Token, IntrospectionResult, Organization, ActionCheckResult, Session, ApprovalRequest,
    WIMSETokenResponse, VerifyWIMSETokenResponse, ChallengeResponse,
)
from .keys import KeyStore
from .exceptions import (
    AgentTrustError,
    AuthenticationError,
    AuthorizationError,
    TokenExpiredError,
    AgentRevokedError,
    NetworkError,
    ValidationError,
)
from .a2a import A2AAPI
from .agentcard import AgentCardsAPI
from .mcp_client import MCPAPI
from .delegation import DelegationsAPI
from .federation import FederationAPI
from .streaming import StreamingAPI


class HTTPClient:
    """Simple HTTP client (no external dependencies)"""

    def __init__(self, base_url: str, timeout: int = 30, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json"}
        if verify_tls:
            self._ssl_context = ssl.create_default_context()
        else:
            warnings.warn(
                "TLS certificate verification is disabled. "
                "This is insecure and should only be used for local development.",
                stacklevel=2,
            )
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    def set_auth(self, token: str):
        """Set authorization header"""
        self.headers["Authorization"] = f"Bearer {token}"

    def set_api_key(self, api_key: str):
        """Set org API key header"""
        self.headers["X-API-Key"] = api_key

    def request(self, method: str, path: str, data: dict = None) -> dict:
        """Make HTTP request"""
        url = f"{self.base_url}{path}"

        body = None
        if data:
            body = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=self.headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as response:
                response_data = response.read().decode("utf-8")
                if response_data:
                    return json.loads(response_data)
                return {}
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8") if e.fp else ""
            try:
                error_data = json.loads(error_body) if error_body else {}
            except json.JSONDecodeError:
                error_data = {"message": error_body}

            if e.code == 401:
                raise AuthenticationError(
                    error_data.get("message", error_data.get("error", "Authentication failed")),
                    code="AUTH_FAILED",
                )
            elif e.code == 403:
                raise AuthorizationError(
                    error_data.get("message", error_data.get("error", "Authorization denied")),
                    code="AUTH_DENIED",
                )
            elif e.code == 404:
                raise AgentTrustError(
                    error_data.get("message", error_data.get("error", "Resource not found")),
                    code="NOT_FOUND",
                )
            elif e.code == 400:
                raise ValidationError(
                    error_data.get("message", error_data.get("error", "Validation failed")),
                    code="VALIDATION_ERROR",
                    details=error_data,
                )
            else:
                raise AgentTrustError(
                    error_data.get("message", error_data.get("error", f"HTTP {e.code} error")),
                    code=f"HTTP_{e.code}",
                )
        except urllib.error.URLError as e:
            raise NetworkError(f"Network error: {e.reason}", code="NETWORK_ERROR")

    def get(self, path: str) -> dict:
        return self.request("GET", path)

    def post(self, path: str, data: dict = None) -> dict:
        return self.request("POST", path, data)

    def put(self, path: str, data: dict = None) -> dict:
        return self.request("PUT", path, data)

    def delete(self, path: str) -> dict:
        return self.request("DELETE", path)


class AgentsAPI:
    """Agent management API"""

    def __init__(self, http: HTTPClient):
        self._http = http

    def create(
        self,
        name: str,
        framework: str = "custom",
        org_id: str = None,
        capabilities: List[str] = None,
        metadata: Dict = None,
        public_key: str = None,
    ) -> Agent:
        """
        Register a new agent.

        By default the SDK generates an Ed25519 identity keypair locally and
        registers only the public key; the returned ``Agent.private_key`` holds the
        private key, which never leaves this process — store it in a KeyStore.
        Pass ``public_key`` (PKIX PEM) to bring your own. The platform does not
        issue certificates; use ``client.tokens.issue(...)`` afterwards to mint
        opaque ``at_`` tokens.

        Args:
            name: Unique agent name within organization
            framework: AI framework (openai, anthropic, langchain, crewai, autogen, custom)
            org_id: Organization ID (uses default if not specified)
            capabilities: List of capabilities the agent can request
            metadata: Additional metadata
            public_key: Optional caller-supplied Ed25519 public key (PKIX PEM); when
                omitted the SDK generates the keypair and keeps the private key local

        Returns:
            Agent record.

        Example:
            agent = client.agents.create(
                name="my-assistant",
                framework="langchain",
                capabilities=["files:read", "web:fetch"]
            )
        """
        from .keys import generate_agent_key

        # Generate an identity keypair client-side when the caller didn't supply a
        # public key, so the private key never leaves this process. Only the public
        # key is registered with the platform.
        generated_private_key_pem = None
        pub = public_key
        if not pub:
            keypair = generate_agent_key()
            pub = keypair.public_key_pem
            generated_private_key_pem = keypair.private_key_pem

        data = {
            "name": name,
            "framework": framework,
            "capabilities": capabilities or [],
            "metadata": metadata or {},
            "public_key": pub,
        }
        if org_id:
            data["org_id"] = org_id

        result = self._http.post("/api/v1/agents", data)
        agent = Agent.from_dict(result)
        # When we generated the keypair locally, the private key stays here and is
        # never round-tripped through the platform.
        if generated_private_key_pem is not None:
            agent.private_key = generated_private_key_pem
        return agent

    def get(self, agent_id: str) -> Agent:
        """Get agent by ID"""
        result = self._http.get(f"/api/v1/agents/{agent_id}")
        return Agent.from_dict(result)

    def list(self, org_id: str = None) -> List[Agent]:
        """List all agents"""
        path = "/api/v1/agents"
        if org_id:
            path += f"?org_id={org_id}"
        result = self._http.get(path)
        agents_data = result.get("agents", result) if isinstance(result, dict) else result
        if isinstance(agents_data, list):
            return [Agent.from_dict(a) for a in agents_data]
        return []

    def revoke(self, agent_id: str, reason: str = "manual_revocation") -> bool:
        """
        Revoke an agent and all its tokens.

        This is immediate and cannot be undone.
        """
        self._http.post(f"/api/v1/agents/{agent_id}/revoke", {"reason": reason})
        return True


class TokensAPI:
    """Token management API"""

    def __init__(self, http: HTTPClient, auth_http: HTTPClient = None):
        self._http = http
        self._auth_http = auth_http if auth_http else http
        self._cache: Dict[str, Token] = {}

    def issue(
        self,
        agent_id: str,
        scopes: List[str],
        target: str = None,
        ttl_seconds: int = 300,  # 5 minutes default
        session_id: str = None,
        use_cache: bool = True,
    ) -> Token:
        """
        Issue a new opaque agent token (prefix ``at_``).

        Tokens are random opaque strings — not JWTs. They have no signature
        and cannot be validated client-side. To check a token, call
        ``introspect(token)``.

        Args:
            agent_id: Agent requesting the token
            scopes: Permissions needed (e.g., ["files:read", "web:fetch"])
            target: Target resource for local cache separation only
            ttl_seconds: Token lifetime (max 300s recommended)
            session_id: Optional AgentTrust session to bind the token to
            use_cache: Return cached token if still valid

        Returns:
            Token with the opaque string in ``token.token``.

        Example:
            token = client.tokens.issue(
                agent_id=agent.id,
                scopes=["files:read"],
                target="mcp://filesystem"
            )
            # Use in requests
            headers = {"Authorization": f"Bearer {token.token}"}
        """
        # Check cache
        cache_key = f"{agent_id}:{':'.join(sorted(scopes))}:{target}:{session_id or ''}"
        if use_cache and cache_key in self._cache:
            cached = self._cache[cache_key]
            if cached.ttl_seconds > 30:  # At least 30s remaining
                return cached

        data = {
            "agent_id": agent_id,
            "scopes": scopes,
            "ttl": ttl_seconds,
        }
        if session_id:
            data["session_id"] = session_id

        result = self._auth_http.post("/api/v1/agent-tokens/issue", data)
        token = Token.from_dict(result)

        # Cache token
        if use_cache:
            self._cache[cache_key] = token

        return token

    def introspect(
        self,
        token: str,
        target: str = None,
        required_scopes: List[str] = None,
    ) -> IntrospectionResult:
        """
        Introspect an opaque agent token.

        Sends the token to ``POST /api/v1/agent-tokens/introspect`` for
        server-side validation. The server checks:

        - Token exists and is not revoked
        - Token has not expired
        - Scopes sufficient for target

        Args:
            token: Opaque agent token (e.g. ``at_xK3z9...``).
            target: Resource being accessed (optional).
            required_scopes: Scopes that must be present (optional).

        Returns:
            IntrospectionResult with ``active`` flag and metadata.
        """
        data = {
            "token": token,
            "target": target,
            "required_scopes": required_scopes or [],
        }
        result = self._auth_http.post("/api/v1/agent-tokens/introspect", data)
        return IntrospectionResult.from_dict(result)

    # Deprecated alias retained for backwards compatibility. Calls introspect.
    def verify(
        self,
        token: str,
        target: str = None,
        required_scopes: List[str] = None,
    ) -> IntrospectionResult:
        return self.introspect(token, target=target, required_scopes=required_scopes)

    def revoke(self, token: str, reason: str = "manual_revocation") -> bool:
        """Revoke a specific token immediately."""
        self._auth_http.post("/api/v1/agent-tokens/revoke", {
            "token": token,
            "reason": reason,
        })
        # Clear from cache
        self._cache = {k: v for k, v in self._cache.items() if v.token != token}
        return True

    def clear_cache(self):
        """Clear token cache"""
        self._cache.clear()


class ActionsAPI:
    """Pre-flight action authorization checks"""

    def __init__(self, http: HTTPClient):
        self._http = http

    def check(
        self,
        agent_id: str,
        action: str = "tool_call",
        tool_name: str = "",
        tool_input_summary: str = "",
        session_id: str = "",
        action_effect: str = "",
    ) -> ActionCheckResult:
        """
        Check if an action is authorized before executing it.

        This is a lightweight Fast Guard check (<15ms).
        Use this before every tool call for real-time protection.

        Args:
            agent_id: The agent requesting the action
            action: Type of action (default: "tool_call")
            tool_name: Name of the tool being called
            tool_input_summary: Truncated summary of inputs (max 200 chars, for privacy)
            session_id: Current session ID for correlation
            action_effect: Effect classification hint (read, mutating, destructive, admin).
                If empty, the backend auto-classifies based on action name.

        Returns:
            ActionCheckResult with allowed/denied decision.
            If elevation is required, elevation_required=True and approval_id is set.
        """
        # Truncate for privacy
        if len(tool_input_summary) > 200:
            tool_input_summary = tool_input_summary[:200]

        data = {
            "agent_id": agent_id,
            "session_id": session_id,
            "action_name": tool_name or action,
            "action_source": "api",
            "action_input_summary": tool_input_summary,
        }
        if action_effect:
            data["action_effect"] = action_effect

        result = self._http.post("/api/v1/agenttrust/check", data)
        return ActionCheckResult.from_dict(result)


class TelemetryAPI:
    """Telemetry reporting for agent behavior tracking"""

    def __init__(self, http: HTTPClient):
        self._http = http

    def report(
        self,
        agent_id: str,
        session_id: str,
        events: List[Dict],
    ) -> dict:
        """
        Report a batch of telemetry events.

        Args:
            agent_id: The agent that generated the events
            session_id: Session ID for correlation
            events: List of event dicts with keys:
                - event_type: "tool_start", "tool_end", "tool_error", etc.
                - tool_name: Name of the tool
                - duration_ms: How long the tool call took
                - success: Whether it succeeded
                - error_type: Error class name if failed
                - timestamp: ISO timestamp

        Returns:
            dict with accepted=True and events_processed count
        """
        return self._http.post("/api/v1/telemetry/report", {
            "agent_id": agent_id,
            "session_id": session_id,
            "events": events,
        })


class SessionsAPI:
    """AgentTrust session management API"""

    def __init__(self, http: HTTPClient):
        self._http = http

    def init_session(self, agent_id: str, server_id: str) -> Session:
        """Initialize a new AgentTrust session for an MCP connection.

        Args:
            agent_id: The agent opening the session
            server_id: The MCP server being connected to

        Returns:
            Session with session_id, mode, and scope_ceiling
        """
        result = self._http.post("/mcp/sessions/init", {
            "agent_id": agent_id,
            "server_id": server_id,
        })
        return Session.from_dict(result)

    def get_session(self, session_id: str) -> Session:
        """Get the current state of a session.

        Args:
            session_id: Session ID returned from init_session

        Returns:
            Session with full state including call metrics
        """
        result = self._http.get(f"/mcp/sessions/{session_id}")
        return Session.from_dict(result)

    def init_api_session(self, token: str) -> Session:
        """Initialize an AgentTrust session from an AgentTrust ID API token."""
        result = self._http.post("/api/v1/agenttrust/api-sessions/init", {
            "token": token,
        })
        return Session.from_dict(result)


class ApprovalsAPI:
    """AgentTrust elevation approval management API"""

    def __init__(self, http: HTTPClient):
        self._http = http

    def approve(self, approval_id: str, decided_by: str = "sdk_user") -> dict:
        """Approve a pending elevation request.

        Args:
            approval_id: The approval ID from ActionCheckResult.approval_id
            decided_by: Identifier of who approved (e.g., user email)

        Returns:
            dict with status="approved"
        """
        return self._http.post(f"/mcp/approvals/{approval_id}/approve", {
            "decided_by": decided_by,
        })

    def deny(self, approval_id: str, decided_by: str = "sdk_user") -> dict:
        """Deny a pending elevation request.

        Args:
            approval_id: The approval ID from ActionCheckResult.approval_id
            decided_by: Identifier of who denied

        Returns:
            dict with status="denied"
        """
        return self._http.post(f"/mcp/approvals/{approval_id}/deny", {
            "decided_by": decided_by,
        })

    def get(self, approval_id: str) -> ApprovalRequest:
        """Get the status of an approval request.

        Args:
            approval_id: The approval ID

        Returns:
            ApprovalRequest with current status
        """
        result = self._http.get(f"/mcp/approvals/{approval_id}")
        return ApprovalRequest.from_dict(result)


def _pop_message(nonce: str, agent_id: str, audience: str, ts: int) -> bytes:
    """Build the canonical proof-of-possession message.

    Must stay byte-identical to the server's ``crypto.PoPMessage``:
    ``pop-v1:<nonce>:<agentID>:<audience>:<ts>`` where ``audience`` is the
    comma-joined request audience (in request order) and ``ts`` is the signing
    time in unix seconds.
    """
    return f"pop-v1:{nonce}:{agent_id}:{audience}:{ts}".encode("utf-8")


class WIMSEAPI:
    """WIMSE workload identity token operations.

    Issues and verifies SPIFFE-style workload identity tokens (JWTs) for agents,
    and supports proof-of-possession: an agent proves it holds its registered
    private key by signing a server challenge, binding the issued token to that
    key via the RFC 7800 ``cnf.jkt`` claim.
    """

    def __init__(self, http: HTTPClient):
        self._http = http

    def issue_token(
        self,
        agent_id: str,
        service_name: Optional[str] = None,
        environment: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        audience: Optional[List[str]] = None,
        proof: Optional[dict] = None,
    ) -> WIMSETokenResponse:
        """Issue a WIMSE workload identity token (``POST /api/v1/wimse/token``)."""
        data: Dict = {"agent_id": agent_id}
        if service_name is not None:
            data["service_name"] = service_name
        if environment is not None:
            data["environment"] = environment
        if ttl_seconds is not None:
            data["ttl_seconds"] = ttl_seconds
        if audience:
            data["audience"] = audience
        if proof is not None:
            data["proof"] = proof
        return WIMSETokenResponse.from_dict(self._http.post("/api/v1/wimse/token", data))

    def verify_token(
        self, token: str, trust_domain_filter: Optional[str] = None
    ) -> VerifyWIMSETokenResponse:
        """Verify a WIMSE workload identity token (``POST /api/v1/wimse/verify``)."""
        data: Dict = {"token": token}
        if trust_domain_filter:
            data["trust_domain_filter"] = trust_domain_filter
        return VerifyWIMSETokenResponse.from_dict(self._http.post("/api/v1/wimse/verify", data))

    def challenge(self, agent_id: str) -> ChallengeResponse:
        """Request a single-use proof-of-possession challenge nonce for an agent."""
        return ChallengeResponse.from_dict(
            self._http.post(f"/api/v1/agents/{agent_id}/challenge")
        )

    def issue_token_with_proof(
        self,
        agent_id: str,
        key_store: KeyStore,
        service_name: Optional[str] = None,
        environment: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        audience: Optional[List[str]] = None,
    ) -> WIMSETokenResponse:
        """Issue a WIMSE token using proof-of-possession.

        Fetches a challenge for the agent, signs the canonical challenge message
        with the agent's key from ``key_store``, and issues with the proof
        attached so the resulting token is bound to the agent key (``cnf.jkt``).
        Required when the org enables proof-of-possession.
        """
        challenge = self.challenge(agent_id)
        ts = int(time.time())
        aud_str = ",".join(audience) if audience else ""
        signature = key_store.sign(agent_id, _pop_message(challenge.nonce, agent_id, aud_str, ts))
        proof = {
            "nonce": challenge.nonce,
            "ts": ts,
            "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        }
        return self.issue_token(
            agent_id,
            service_name=service_name,
            environment=environment,
            ttl_seconds=ttl_seconds,
            audience=audience,
            proof=proof,
        )


class AgentTrustClient:
    """
    AgentTrust Client - Main entry point for AgentTrust.

    Example:
        # Basic usage (via gateway)
        client = AgentTrustClient(base_url="http://localhost:8080")

        # Create an agent
        agent = client.agents.create(name="my-agent", framework="langchain")

        # Save credentials
        Path("agent.key").write_text(agent.private_key)

        # Get tokens for tool access
        token = client.tokens.issue(
            agent_id=agent.id,
            scopes=["files:read"],
            target="mcp://filesystem"
        )

        # Validate tokens (for tool providers) by introspecting them
        result = client.tokens.introspect(token.token)
        if result.active:
            # Allow the operation
            pass
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        auth_url: str = None,
        audit_url: str = None,
        api_key: str = None,
        timeout: int = 30,
        verify_tls: bool = True,
    ):
        """
        Initialize AgentTrust client.

        Args:
            base_url: Gateway URL (default: http://localhost:8080). When using
                the gateway, all API traffic is routed through a single endpoint.
                For direct service access, use http://localhost:8081 (identity).
            auth_url: Auth service URL (optional, derived from base_url)
            audit_url: Audit service URL (optional, derived from base_url)
            api_key: Organization API key (sk_live_xxx)
            timeout: Request timeout in seconds
        """
        self.http = HTTPClient(base_url, timeout, verify_tls=verify_tls)
        self._http = self.http  # backward compat

        # Derive auth URL from base URL if not provided
        if not auth_url:
            if ":8081" in base_url:
                auth_url = base_url.replace(":8081", ":8082")
            else:
                auth_url = base_url

        # Derive audit URL from base URL if not provided
        if not audit_url:
            if ":8081" in base_url:
                audit_url = base_url.replace(":8081", ":8084")
            else:
                audit_url = base_url

        # Set API key on all HTTP clients
        if api_key:
            self._http.set_api_key(api_key)

        self._auth_http = HTTPClient(auth_url, timeout, verify_tls=verify_tls)
        self._audit_http = HTTPClient(audit_url, timeout, verify_tls=verify_tls)

        if api_key:
            self._auth_http.set_api_key(api_key)
            self._audit_http.set_api_key(api_key)

        self.agents = AgentsAPI(self._http)
        self.tokens = TokensAPI(self._http, self._auth_http)
        self.actions = ActionsAPI(self._auth_http)
        self.telemetry = TelemetryAPI(self._audit_http)
        self.wimse = WIMSEAPI(self._http)

        # Lazy-initialized protocol API instances
        self._a2a = None
        self._agent_cards = None
        self._mcp = None
        self._delegations = None
        self._federation = None
        self._streaming = None
        self._sessions = None
        self._approvals = None

    @property
    def a2a(self) -> A2AAPI:
        """A2A (Agent-to-Agent) task management API."""
        if self._a2a is None:
            self._a2a = A2AAPI(self._http)
        return self._a2a

    @property
    def agent_cards(self) -> AgentCardsAPI:
        """Agent Card management API."""
        if self._agent_cards is None:
            self._agent_cards = AgentCardsAPI(self._http)
        return self._agent_cards

    @property
    def mcp(self) -> MCPAPI:
        """MCP proxy client API."""
        if self._mcp is None:
            self._mcp = MCPAPI(self._http)
        return self._mcp

    @property
    def delegations(self) -> DelegationsAPI:
        """Delegation management API."""
        if self._delegations is None:
            self._delegations = DelegationsAPI(self._http)
        return self._delegations

    @property
    def federation(self) -> FederationAPI:
        """Federation provider and session bridge API."""
        if self._federation is None:
            self._federation = FederationAPI(self._http)
        return self._federation

    @property
    def streaming(self) -> StreamingAPI:
        """SIEM streaming destination management API."""
        if self._streaming is None:
            self._streaming = StreamingAPI(self._http)
        return self._streaming

    @property
    def sessions(self) -> SessionsAPI:
        """AgentTrust session management API."""
        if self._sessions is None:
            self._sessions = SessionsAPI(self._http)
        return self._sessions

    @property
    def approvals(self) -> ApprovalsAPI:
        """AgentTrust elevation approval API."""
        if self._approvals is None:
            self._approvals = ApprovalsAPI(self._http)
        return self._approvals

    def set_api_key(self, api_key: str):
        """Set org API key on all internal HTTP clients (identity, auth, audit)."""
        self._http.set_api_key(api_key)
        self._auth_http.set_api_key(api_key)
        self._audit_http.set_api_key(api_key)

    def health(self) -> Dict:
        """Check service health"""
        return self._http.get("/health")

    @classmethod
    def from_env(cls) -> "AgentTrustClient":
        """
        Create client from environment variables.

        Preferred environment variables:
            AGENTTRUST_URL: Gateway URL (or AGENTTRUST_BASE_URL, default: http://localhost:8080)
            AGENTTRUST_AUTH_URL: Auth service URL (optional, derived from base)
            AGENTTRUST_AUDIT_URL: Audit service URL (optional, derived from base)
            AGENTTRUST_API_KEY: Organization API key (sk_live_xxx)
        """
        import os

        base_url = (
            os.getenv("AGENTTRUST_URL")
            or os.getenv("AGENTTRUST_BASE_URL")
            or "http://localhost:8080"
        )

        return cls(
            base_url=base_url,
            auth_url=os.getenv("AGENTTRUST_AUTH_URL"),
            audit_url=os.getenv("AGENTTRUST_AUDIT_URL"),
            api_key=os.getenv("AGENTTRUST_API_KEY"),
        )

    @classmethod
    def from_config(cls, config_path: str) -> "AgentTrustClient":
        """
        Create client from config file.

        Config file (JSON):
            {
                "base_url": "http://localhost:8081",
                "auth_url": "http://localhost:8082",
                "api_key": "optional-api-key"
            }
        """
        with open(config_path) as f:
            config = json.load(f)

        return cls(
            base_url=config.get("base_url", "http://localhost:8081"),
            auth_url=config.get("auth_url"),
            api_key=config.get("api_key"),
        )
