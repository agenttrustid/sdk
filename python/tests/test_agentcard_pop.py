"""AgentCard proof-of-possession binding: extracting the agent's registered key
(ati_agent_key) from a fetched card's trust extension."""
import base64

from cryptography.hazmat.primitives import serialization

from agenttrustid import generate_agent_key
from agenttrustid.models import AgentCard

TRUST_URI = "https://agenttrust.id/ext/trust/v1"


def _x_from_pem(public_key_pem: str) -> str:
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _card(params: dict) -> AgentCard:
    return AgentCard.from_dict(
        {"name": "a", "capabilities": {"extensions": [{"uri": TRUST_URI, "params": params}]}}
    )


def test_agent_public_key_pem_roundtrip():
    kp = generate_agent_key()
    card = _card({"ati_agent_key": {"kty": "OKP", "crv": "Ed25519", "x": _x_from_pem(kp.public_key_pem)}})
    pem = card.agent_public_key_pem
    assert pem is not None
    assert pem.strip() == kp.public_key_pem.strip()


def test_agent_public_key_pem_absent_returns_none():
    assert _card({"ati_trust_score": 0.5}).agent_public_key_pem is None
    assert AgentCard.from_dict({"name": "a"}).agent_public_key_pem is None


def test_agent_public_key_pem_malformed_returns_none():
    assert _card({"ati_agent_key": {"kty": "OKP", "crv": "Ed25519", "x": "not base64!!"}}).agent_public_key_pem is None
    assert _card({"ati_agent_key": {"kty": "RSA"}}).agent_public_key_pem is None
