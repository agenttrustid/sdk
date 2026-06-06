"""AgentTrust SDK Federation Management

Federation lets the platform consume ID tokens from external OIDC providers.
Validation always happens server-side (the platform calls the provider's
JWKS) — this SDK never parses or verifies external OIDC tokens locally.

The platform itself does NOT serve a JWKS endpoint and does NOT issue OIDC
ID tokens.
"""

from typing import List, Optional

from .models import FederationProvider, Session, FederationIntrospectionResult


class FederationAPI:
    """OIDC federation provider registration, introspection, and session bridging."""

    def __init__(self, http_client):
        self._http = http_client

    def register_provider(
        self,
        issuer: str,
        name: str,
        trust_level: Optional[str] = None,
    ) -> FederationProvider:
        data = {
            "issuer": issuer,
            "name": name,
        }
        if trust_level is not None:
            data["trust_level"] = trust_level

        result = self._http.post("/api/v1/federation/providers", data)
        return FederationProvider.from_dict(result)

    def list_providers(self) -> List[FederationProvider]:
        result = self._http.get("/api/v1/federation/providers")
        providers = result.get("providers", result) if isinstance(result, dict) else result
        if isinstance(providers, list):
            return [FederationProvider.from_dict(provider) for provider in providers]
        return []

    def delete_provider(self, provider_id: str) -> None:
        self._http.delete(f"/api/v1/federation/providers/{provider_id}")

    def introspect_token(
        self, token: str, issuer_hint: Optional[str] = None
    ) -> FederationIntrospectionResult:
        """Introspect a federated OIDC ID token.

        The platform validates the token against the registered provider's JWKS
        server-side. ``token`` may be either an external OIDC ID token (the
        normal federation case) or a federation session token with the
        ``fed_`` prefix.
        """
        data = {"token": token}
        if issuer_hint:
            data["issuer_hint"] = issuer_hint
        result = self._http.post("/api/v1/federation/tokens/introspect", data)
        return FederationIntrospectionResult.from_dict(result)

    # Deprecated alias for back-compat.
    def verify_token(
        self, token: str, issuer_hint: Optional[str] = None
    ) -> FederationIntrospectionResult:
        return self.introspect_token(token, issuer_hint=issuer_hint)

    def init_session(self, token: str, issuer_hint: Optional[str] = None) -> Session:
        data = {"token": token}
        if issuer_hint:
            data["issuer_hint"] = issuer_hint
        result = self._http.post("/api/v1/federation/sessions/init", data)
        return Session.from_dict(result)
