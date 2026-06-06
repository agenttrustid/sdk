"""AgentTrust SDK Agent Card Management"""

from typing import Optional

from .models import AgentCard


class AgentCardsAPI:
    """Agent Card management API.

    Agent Cards provide standardized metadata about an agent's identity,
    capabilities, supported interfaces, and skills following the A2A
    protocol v1.0. Cards are parsed into :class:`AgentCard`; use
    ``card.primary_url`` and ``card.trust_score`` to read the endpoint and
    ATI trust extension.

    Example:
        # Generate and publish a card
        card = client.agent_cards.generate(agent_id="agent-123")
        client.agent_cards.publish(agent_id="agent-123")

        # Retrieve the public card (no auth required)
        public_card = client.agent_cards.get_public(agent_id="agent-123")
    """

    def __init__(self, http_client):
        self._http = http_client

    def generate(self, agent_id: str) -> AgentCard:
        """
        Generate an Agent Card for the given agent.

        Creates or regenerates the agent's card with current metadata,
        capabilities, and security policy information.

        Args:
            agent_id: ID of the agent to generate a card for

        Returns:
            AgentCard with the generated card data
        """
        result = self._http.post(f"/api/v1/agents/{agent_id}/card")
        return AgentCard.from_dict(result)

    def get(self, agent_id: str) -> AgentCard:
        """
        Get the Agent Card for the given agent.

        Args:
            agent_id: ID of the agent

        Returns:
            AgentCard with current card data
        """
        result = self._http.get(f"/api/v1/agents/{agent_id}/card")
        return AgentCard.from_dict(result)

    def publish(self, agent_id: str) -> AgentCard:
        """
        Publish the agent's card, making it publicly discoverable.

        Once published, the card is available at the well-known URL
        and can be discovered by other agents via A2A protocol.

        Args:
            agent_id: ID of the agent

        Returns:
            AgentCard with updated publish status
        """
        result = self._http.put(f"/api/v1/agents/{agent_id}/card/publish")
        return AgentCard.from_dict(result)

    def get_public(self, agent_id: str) -> AgentCard:
        """
        Get the publicly published Agent Card (no authentication required).

        This uses the well-known A2A discovery path.

        Args:
            agent_id: ID of the agent

        Returns:
            AgentCard with public card data
        """
        result = self._http.get(f"/a2a/agents/{agent_id}/agent.json")
        return AgentCard.from_dict(result)
