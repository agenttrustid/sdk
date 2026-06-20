"""AgentTrust SDK Data Models"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional
from enum import Enum


class AgentStatus(Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class Framework(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    CUSTOM = "custom"


@dataclass
class Agent:
    """Registered AI agent"""
    id: str
    name: str
    org_id: str
    framework: str
    public_key: str
    status: AgentStatus = AgentStatus.ACTIVE
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    created_at: datetime = None
    private_key: str = None  # Only set during creation

    @classmethod
    def from_dict(cls, data: dict) -> "Agent":
        # Handle nested response: {"agent": {...}}
        if "agent" in data and isinstance(data["agent"], dict):
            data = data["agent"]
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            org_id=data.get("org_id", ""),
            framework=data.get("framework", "custom"),
            public_key=data.get("public_key", ""),
            status=AgentStatus(data.get("status", "active")),
            capabilities=data.get("capabilities", []),
            metadata=data.get("metadata", {}),
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")) if data.get("created_at") else None,
            private_key=data.get("private_key"),
        )


@dataclass
class Token:
    """Opaque agent token (prefixed `at_`).

    Tokens are random strings, not JWTs. They have no signature or claims and
    cannot be verified client-side. To validate a token, call
    `client.tokens.introspect(token)` which sends it to
    `POST /api/v1/agent-tokens/introspect`.
    """
    token: str  # Opaque token string, e.g. "at_xK3z9..."
    agent_id: str
    scopes: List[str]
    audience: List[str]
    issued_at: datetime
    expires_at: datetime
    token_id: str = None

    @property
    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        expires = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=timezone.utc)
        return now > expires

    @property
    def ttl_seconds(self) -> int:
        """Seconds until token expires"""
        now = datetime.now(timezone.utc)
        expires = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=timezone.utc)
        delta = expires - now
        return max(0, int(delta.total_seconds()))

    @classmethod
    def from_dict(cls, data: dict) -> "Token":
        return cls(
            token=data.get("token", data.get("agent_token", "")),
            agent_id=data.get("agent_id", ""),
            scopes=data.get("scopes", data.get("scope", [])),
            audience=data.get("audience", []),
            issued_at=datetime.fromisoformat(data["issued_at"].replace("Z", "+00:00")) if data.get("issued_at") else datetime.now(timezone.utc),
            expires_at=datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")) if data.get("expires_at") else None,
            token_id=data.get("token_id", data.get("id")),
        )


@dataclass
class IntrospectionResult:
    """Result of an opaque-token introspection (server-side validation)."""
    active: bool
    agent_id: str = None
    org_id: str = None
    scopes: List[str] = field(default_factory=list)
    expires_at: datetime = None
    reasoning: str = None

    @classmethod
    def from_dict(cls, data: dict) -> "IntrospectionResult":
        return cls(
            active=data.get("active", False),
            agent_id=data.get("agent_id"),
            org_id=data.get("org_id"),
            scopes=data.get("scopes", []),
            expires_at=datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")) if data.get("expires_at") else None,
            reasoning=data.get("reasoning"),
        )


@dataclass
class ActionCheckResult:
    """Result of a pre-flight action authorization check"""
    allowed: bool
    check_id: str = None
    confidence: float = None
    guard_tier: str = None
    latency_ms: int = None
    reason: str = None
    elevation_required: bool = False
    approval_id: str = None

    @classmethod
    def from_dict(cls, data: dict) -> "ActionCheckResult":
        return cls(
            allowed=data.get("allowed", False),
            check_id=data.get("check_id"),
            confidence=data.get("confidence"),
            guard_tier=data.get("guard_tier"),
            latency_ms=data.get("latency_ms"),
            reason=data.get("reason"),
            elevation_required=data.get("elevation_required", False),
            approval_id=data.get("approval_id"),
        )


@dataclass
class Session:
    """AgentTrust session state"""
    session_id: str
    agent_id: str = ""
    org_id: str = ""
    source: str = ""
    server_id: str = ""
    delegation_id: str = ""
    provider_id: str = ""
    issuer: str = ""
    trust_level: str = ""
    mode: str = ""
    allowed_actions: List[str] = field(default_factory=list)
    scope_ceiling: List[str] = field(default_factory=list)
    total_calls: int = 0
    read_calls: int = 0
    write_calls: int = 0
    denied_calls: int = 0
    created_at: datetime = None
    last_activity_at: datetime = None

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        return cls(
            session_id=data.get("session_id", ""),
            agent_id=data.get("agent_id", ""),
            org_id=data.get("org_id", ""),
            source=data.get("source", ""),
            server_id=data.get("server_id", ""),
            delegation_id=data.get("delegation_id", ""),
            provider_id=data.get("provider_id", ""),
            issuer=data.get("issuer", ""),
            trust_level=data.get("trust_level", ""),
            mode=data.get("mode", ""),
            allowed_actions=data.get("allowed_actions") or [],
            scope_ceiling=data.get("scope_ceiling") or [],
            total_calls=data.get("total_calls", 0),
            read_calls=data.get("read_calls", 0),
            write_calls=data.get("write_calls", 0),
            denied_calls=data.get("denied_calls", 0),
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")) if data.get("created_at") else None,
            last_activity_at=datetime.fromisoformat(data["last_activity_at"].replace("Z", "+00:00")) if data.get("last_activity_at") else None,
        )


@dataclass
class ApprovalRequest:
    """Pending elevation approval request"""
    id: str
    session_id: str = ""
    agent_id: str = ""
    org_id: str = ""
    action_name: str = ""
    action_effect: str = ""
    status: str = "pending"
    created_at: datetime = None
    expires_at: datetime = None
    decided_by: str = None

    @classmethod
    def from_dict(cls, data: dict) -> "ApprovalRequest":
        return cls(
            id=data.get("id", ""),
            session_id=data.get("session_id", ""),
            agent_id=data.get("agent_id", ""),
            org_id=data.get("org_id", ""),
            action_name=data.get("action_name", ""),
            action_effect=data.get("action_effect", ""),
            status=data.get("status", "pending"),
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")) if data.get("created_at") else None,
            expires_at=datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")) if data.get("expires_at") else None,
            decided_by=data.get("decided_by"),
        )


@dataclass
class FederationProvider:
    """Trusted external OIDC federation provider.

    The platform consumes external OIDC ID tokens. The `jwks_uri` here points
    at the *external* issuer's JWKS — AgentTrust does not serve its own JWKS.
    """
    id: str
    org_id: str = ""
    issuer: str = ""
    name: str = ""
    jwks_uri: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    trust_level: str = ""
    status: str = ""
    created_at: datetime = None
    updated_at: datetime = None

    @classmethod
    def from_dict(cls, data: dict) -> "FederationProvider":
        provider = data.get("provider", data)
        return cls(
            id=provider.get("id", ""),
            org_id=provider.get("org_id", ""),
            issuer=provider.get("issuer", ""),
            name=provider.get("name", ""),
            jwks_uri=provider.get("jwks_uri", ""),
            authorization_endpoint=provider.get("authorization_endpoint", ""),
            token_endpoint=provider.get("token_endpoint", ""),
            trust_level=provider.get("trust_level", ""),
            status=provider.get("status", ""),
            created_at=datetime.fromisoformat(provider["created_at"].replace("Z", "+00:00")) if provider.get("created_at") else None,
            updated_at=datetime.fromisoformat(provider["updated_at"].replace("Z", "+00:00")) if provider.get("updated_at") else None,
        )


@dataclass
class FederationIntrospectionResult:
    """Result of introspecting a federated external OIDC ID token.

    Federation tokens use the `fed_` prefix when they are AgentTrust
    federation session tokens. External OIDC ID tokens are introspected by
    the platform server-side; the SDK never validates signatures locally.
    """
    active: bool
    agent_id: str = ""
    issuer: str = ""
    expires_at: datetime = None
    error: str = ""

    @property
    def valid(self) -> bool:
        """Back-compat alias for ``active``."""
        return self.active

    @classmethod
    def from_dict(cls, data: dict) -> "FederationIntrospectionResult":
        # Server may use either "active" or legacy "valid".
        active = data.get("active", data.get("valid", False))
        return cls(
            active=active,
            agent_id=data.get("agent_id", ""),
            issuer=data.get("issuer", ""),
            expires_at=datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")) if data.get("expires_at") else None,
            error=data.get("error", ""),
        )


@dataclass
class SIEMDestination:
    """SIEM streaming destination"""
    id: str
    org_id: str = ""
    name: str = ""
    destination_type: str = ""
    endpoint_url: str = ""
    auth_token: str = ""
    is_active: bool = False
    batch_size: int = 0
    flush_interval_seconds: int = 0
    filter_event_types: List[str] = field(default_factory=list)
    created_at: datetime = None
    updated_at: datetime = None

    @classmethod
    def from_dict(cls, data: dict) -> "SIEMDestination":
        return cls(
            id=data.get("id", ""),
            org_id=data.get("org_id", ""),
            name=data.get("name", ""),
            destination_type=data.get("destination_type", ""),
            endpoint_url=data.get("endpoint_url", ""),
            auth_token=data.get("auth_token", ""),
            is_active=data.get("is_active", False),
            batch_size=data.get("batch_size", 0),
            flush_interval_seconds=data.get("flush_interval_seconds", 0),
            filter_event_types=data.get("filter_event_types", []) or [],
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00")) if data.get("updated_at") else None,
        )


@dataclass
class SIEMDeliveryRecord:
    """SIEM delivery attempt record"""
    id: str
    destination_id: str = ""
    batch_size: int = 0
    status: str = ""
    status_code: int = 0
    error_message: str = ""
    delivered_at: datetime = None

    @classmethod
    def from_dict(cls, data: dict) -> "SIEMDeliveryRecord":
        return cls(
            id=data.get("id", ""),
            destination_id=data.get("destination_id", ""),
            batch_size=data.get("batch_size", 0),
            status=data.get("status", ""),
            status_code=data.get("status_code", 0),
            error_message=data.get("error_message", ""),
            delivered_at=datetime.fromisoformat(data["delivered_at"].replace("Z", "+00:00")) if data.get("delivered_at") else None,
        )


@dataclass
class Organization:
    """Customer organization"""
    id: str
    name: str
    tier: str  # free, pro, enterprise
    settings: Dict = field(default_factory=dict)
    created_at: datetime = None

    @classmethod
    def from_dict(cls, data: dict) -> "Organization":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            tier=data.get("tier", "free"),
            settings=data.get("settings", {}),
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")) if data.get("created_at") else None,
        )


# URI of the AgentTrust trust extension carried inside the A2A v1.0 Agent Card
# capabilities.extensions list. Its params hold the ATI trust score.
ATI_TRUST_EXTENSION_URI = "https://agenttrust.id/ext/trust/v1"


@dataclass
class AgentCard:
    """Agent Card following the A2A protocol v1.0 spec.

    The SDK *parses* this structure from the server. Every field is optional so
    that older cached cards (which may lack ``supportedInterfaces``,
    ``signatures``, or even ``capabilities``) still deserialize without raising.

    The v1.0 schema dropped the top-level ``url`` and ``security_policy`` fields.
    Use the :attr:`primary_url` property (which falls back to a legacy ``url``
    key) and :attr:`trust_score` to read the ATI trust extension.
    """
    name: str
    description: str = ""
    version: str = ""
    supported_interfaces: List[Dict] = field(default_factory=list)
    provider: Optional[Dict] = None
    capabilities: Dict = field(default_factory=dict)
    security_schemes: Optional[Dict] = None
    security_requirements: Optional[List[Dict]] = None
    default_input_modes: List[str] = field(default_factory=list)
    default_output_modes: List[str] = field(default_factory=list)
    skills: List[Dict] = field(default_factory=list)
    signatures: Optional[List[Dict]] = None
    documentation_url: str = ""
    icon_url: str = ""
    # Preserve any legacy top-level ``url`` so primary_url can fall back to it.
    legacy_url: str = ""

    @property
    def primary_url(self) -> str:
        """The agent's primary A2A endpoint URL.

        Reads ``supportedInterfaces[0].url`` (v1.0). Falls back to a legacy
        top-level ``url`` key if the card predates v1.0. Returns ``""`` when
        neither is present.
        """
        if self.supported_interfaces:
            first = self.supported_interfaces[0]
            if isinstance(first, dict) and first.get("url"):
                return first["url"]
        return self.legacy_url or ""

    @property
    def trust_score(self) -> float:
        """ATI trust score from the trust extension.

        Reads ``capabilities.extensions[]`` for the entry whose ``uri`` equals
        ``ATI_TRUST_EXTENSION_URI`` and returns its ``params.ati_trust_score``
        as a float. Returns ``0.0`` if the extension or score is absent.
        """
        extensions = []
        if isinstance(self.capabilities, dict):
            extensions = self.capabilities.get("extensions") or []
        for ext in extensions:
            if not isinstance(ext, dict):
                continue
            if ext.get("uri") == ATI_TRUST_EXTENSION_URI:
                params = ext.get("params") or {}
                try:
                    return float(params.get("ati_trust_score", 0.0))
                except (TypeError, ValueError):
                    return 0.0
        return 0.0

    @classmethod
    def from_dict(cls, data: dict) -> "AgentCard":
        data = data or {}
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            version=data.get("version", ""),
            supported_interfaces=data.get("supportedInterfaces") or [],
            provider=data.get("provider"),
            capabilities=data.get("capabilities") or {},
            security_schemes=data.get("securitySchemes"),
            security_requirements=data.get("securityRequirements"),
            default_input_modes=data.get("defaultInputModes") or [],
            default_output_modes=data.get("defaultOutputModes") or [],
            skills=data.get("skills") or [],
            signatures=data.get("signatures"),
            documentation_url=data.get("documentationUrl", ""),
            icon_url=data.get("iconUrl", ""),
            legacy_url=data.get("url", ""),
        )


@dataclass
class A2ATask:
    """A2A (Agent-to-Agent) task"""
    id: str
    source_agent_id: str = ""
    target_agent_id: str = ""
    status: str = "pending"
    message: str = ""
    artifacts: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    created_at: datetime = None
    updated_at: datetime = None

    @classmethod
    def from_dict(cls, data: dict) -> "A2ATask":
        return cls(
            id=data.get("id", ""),
            source_agent_id=data.get("source_agent_id", ""),
            target_agent_id=data.get("target_agent_id", ""),
            status=data.get("status", "pending"),
            message=data.get("message", ""),
            artifacts=data.get("artifacts", []),
            metadata=data.get("metadata", {}),
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00")) if data.get("updated_at") else None,
        )


@dataclass
class A2AMessageTask:
    """A2A v1.0 Task returned by the ``message/send`` method.

    Mirrors the A2A v1.0 Task object: ``{id, contextId, status: {state,
    timestamp}, history?, artifacts?}``. Every field tolerates absence so
    partial server responses do not raise.
    """
    id: str = ""
    context_id: str = ""
    state: str = ""
    status_timestamp: str = ""
    status: Dict = field(default_factory=dict)
    history: List[Dict] = field(default_factory=list)
    artifacts: List[Dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "A2AMessageTask":
        data = data or {}
        status = data.get("status") or {}
        if not isinstance(status, dict):
            status = {}
        return cls(
            id=data.get("id", ""),
            context_id=data.get("contextId", ""),
            state=status.get("state", ""),
            status_timestamp=status.get("timestamp", ""),
            status=status,
            history=data.get("history") or [],
            artifacts=data.get("artifacts") or [],
        )


@dataclass
class MCPServer:
    """Registered MCP server"""
    id: str
    name: str = ""
    url: str = ""
    capabilities: List[str] = field(default_factory=list)
    org_id: str = ""
    created_at: datetime = None

    @classmethod
    def from_dict(cls, data: dict) -> "MCPServer":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            url=data.get("url", ""),
            capabilities=data.get("capabilities", []),
            org_id=data.get("org_id", ""),
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")) if data.get("created_at") else None,
        )


@dataclass
class Delegation:
    """Agent-to-agent capability delegation"""
    id: str
    from_agent_id: str = ""
    to_agent_id: str = ""
    scope: List[str] = field(default_factory=list)
    restrictions: Dict = field(default_factory=dict)
    delegation_chain: List[str] = field(default_factory=list)
    expires_at: datetime = None
    revoked_at: datetime = None
    created_at: datetime = None

    @classmethod
    def from_dict(cls, data: dict) -> "Delegation":
        return cls(
            id=data.get("id", ""),
            from_agent_id=data.get("from_agent_id", ""),
            to_agent_id=data.get("to_agent_id", ""),
            scope=data.get("scope", []),
            restrictions=data.get("restrictions", {}),
            delegation_chain=data.get("delegation_chain", []),
            expires_at=datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")) if data.get("expires_at") else None,
            revoked_at=datetime.fromisoformat(data["revoked_at"].replace("Z", "+00:00")) if data.get("revoked_at") else None,
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")) if data.get("created_at") else None,
        )


@dataclass
class WIMSETokenResponse:
    """Result of issuing a WIMSE workload identity token."""
    token: str = ""
    workload_id: str = ""
    trust_domain: str = ""
    expires_at: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "WIMSETokenResponse":
        return cls(
            token=data.get("token", ""),
            workload_id=data.get("workload_id", ""),
            trust_domain=data.get("trust_domain", ""),
            expires_at=data.get("expires_at", ""),
        )


@dataclass
class VerifyWIMSETokenResponse:
    """Result of verifying a WIMSE workload identity token."""
    valid: bool = False
    agent_id: Optional[str] = None
    workload_id: Optional[str] = None
    trust_domain: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    reason: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "VerifyWIMSETokenResponse":
        return cls(
            valid=data.get("valid", False),
            agent_id=data.get("agent_id"),
            workload_id=data.get("workload_id"),
            trust_domain=data.get("trust_domain"),
            capabilities=data.get("capabilities", []) or [],
            reason=data.get("reason"),
        )


@dataclass
class ChallengeResponse:
    """Server reply to a proof-of-possession challenge."""
    nonce: str = ""
    expires_at: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "ChallengeResponse":
        return cls(nonce=data.get("nonce", ""), expires_at=data.get("expires_at", ""))


# Backwards-compat aliases. The platform no longer issues certificates and
# tokens are no longer JWTs, but external code may import these names.
VerificationResult = IntrospectionResult
VerifyFederatedTokenResult = FederationIntrospectionResult
