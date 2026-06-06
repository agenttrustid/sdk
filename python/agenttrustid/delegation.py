"""AgentTrust SDK Delegation Management"""

from typing import Dict, List, Optional

from .models import Delegation, Session


class DelegationsAPI:
    """Delegation management API.

    Delegations allow one agent to grant a subset of its capabilities
    to another agent, with scoping, time limits, and optional restrictions.

    Example:
        # Create a delegation
        delegation = client.delegations.create(
            from_agent_id="agent-123",
            to_agent_id="agent-456",
            scope=["files:read"],
            ttl_seconds=3600,
            restrictions={"paths": ["/tmp/*"]},
        )

        # List active delegations
        delegations = client.delegations.list()

        # Revoke a delegation
        client.delegations.revoke(delegation.id)
    """

    def __init__(self, http_client):
        self._http = http_client

    def create(
        self,
        from_agent_id: str,
        to_agent_id: str,
        scope: List[str],
        ttl_seconds: int = 3600,
        restrictions: Optional[Dict] = None,
        parent_delegation_id: Optional[str] = None,
    ) -> Delegation:
        """
        Create a delegation from one agent to another.

        Args:
            from_agent_id: ID of the agent granting capabilities
            to_agent_id: ID of the agent receiving capabilities
            scope: List of capability scopes being delegated
            ttl_seconds: Time-to-live in seconds (default: 3600 = 1 hour)
            restrictions: Optional restrictions on the delegated capabilities
            parent_delegation_id: Optional parent delegation for chained delegations

        Returns:
            Delegation with the created delegation details
        """
        data = {
            "from_agent_id": from_agent_id,
            "to_agent_id": to_agent_id,
            "scope": scope,
            "ttl_seconds": ttl_seconds,
        }
        if restrictions is not None:
            data["restrictions"] = restrictions
        if parent_delegation_id is not None:
            data["parent_delegation_id"] = parent_delegation_id

        result = self._http.post("/api/v1/delegations", data)
        # API wraps response: {"delegation": {...}}
        if isinstance(result, dict) and "delegation" in result:
            return Delegation.from_dict(result["delegation"])
        return Delegation.from_dict(result)

    def list(self) -> List[Delegation]:
        """
        List all delegations for the organization.

        Returns:
            List of Delegation instances
        """
        result = self._http.get("/api/v1/delegations")
        delegations_data = result.get("delegations", result) if isinstance(result, dict) else result
        if isinstance(delegations_data, list):
            return [Delegation.from_dict(d) for d in delegations_data]
        return []

    def revoke(self, delegation_id: str) -> None:
        """
        Revoke a delegation immediately.

        Args:
            delegation_id: ID of the delegation to revoke
        """
        self._http.delete(f"/api/v1/delegations/{delegation_id}")

    def init_session(self, delegation_id: str) -> Session:
        """
        Initialize an AgentTrust session from an active delegation.

        Args:
            delegation_id: ID of the delegation to bridge into a local session

        Returns:
            Session created from the delegation context
        """
        result = self._http.post(f"/api/v1/delegations/{delegation_id}/session")
        return Session.from_dict(result)
