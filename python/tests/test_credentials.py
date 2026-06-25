"""Coverage for AgentCredentials: PoP token issuance, caching/refresh, and the
WIMSE-bearer + DPoP headers attached to runtime checks."""
import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agenttrustid import (
    AgentCredentials,
    AgentTrustClient,
    InMemoryKeyStore,
    generate_agent_key,
)

CHECK_PATH = "/api/v1/agenttrust/check"


class _Resp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify_dpop(proof: str):
    h, p, s = proof.split(".")
    header = json.loads(_b64url_decode(h))
    payload = json.loads(_b64url_decode(p))
    pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(header["jwk"]["x"]))
    try:
        pub.verify(_b64url_decode(s), f"{h}.{p}".encode("ascii"))
        ok = True
    except InvalidSignature:
        ok = False
    return ok, payload


def _router(token_expires_at: str, cap: dict):
    def handler(req, *args, **kwargs):
        url = req.full_url
        if url.endswith("/challenge"):
            body = {
                "nonce": "nonce-123",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            }
            return _Resp(json.dumps(body).encode())
        if url.endswith("/api/v1/wimse/token"):
            cap["token_calls"] += 1
            return _Resp(json.dumps({"token": "wimse-tok", "expires_at": token_expires_at}).encode())
        if url.endswith(CHECK_PATH):
            cap["check_calls"] += 1
            cap["auth"] = req.get_header("Authorization")
            cap["dpop"] = req.get_header("Dpop")  # urllib canonicalizes "DPoP" -> "Dpop"
            return _Resp(json.dumps({"allowed": True, "guard_tier": "fast"}).encode())
        return _Resp(b"{}")

    return handler


def _iso(seconds_from_now: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)).isoformat()


def _new_creds():
    kp = generate_agent_key()
    ks = InMemoryKeyStore()
    ks.store("agent-1", kp.private_key_pem)
    client = AgentTrustClient(base_url="http://localhost:8080")
    ac = AgentCredentials(client, ks, "agent-1", kp.public_key_pem)
    return client, ac


def test_issues_caches_and_mints_headers():
    cap = {"token_calls": 0, "check_calls": 0}
    client, ac = _new_creds()
    with patch("urllib.request.urlopen", side_effect=_router(_iso(3600), cap)):
        assert ac.token() == "wimse-tok"
        ac.token()  # cached (~1h) — must not re-issue
        assert cap["token_calls"] == 1

        headers = ac.runtime_headers("POST", CHECK_PATH)
        assert headers["Authorization"] == "Bearer wimse-tok"
        ok, payload = _verify_dpop(headers["DPoP"])
        assert ok
        assert payload["htu"] == "http://localhost:8080" + CHECK_PATH


def test_refreshes_when_near_expiry():
    cap = {"token_calls": 0, "check_calls": 0}
    _, ac = _new_creds()
    # Expires in 10s — inside the 60s refresh skew — so each token() re-issues.
    with patch("urllib.request.urlopen", side_effect=_router(_iso(10), cap)):
        ac.token()
        ac.token()
        assert cap["token_calls"] == 2


def test_check_attaches_bearer_and_dpop():
    cap = {"token_calls": 0, "check_calls": 0}
    client, ac = _new_creds()
    client.use_agent_credentials(ac)
    with patch("urllib.request.urlopen", side_effect=_router(_iso(3600), cap)):
        result = client.actions.check(agent_id="agent-1", tool_name="read_file")
        assert result.allowed is True
        assert cap["check_calls"] == 1
        assert cap["auth"] == "Bearer wimse-tok"
        assert cap["dpop"]
        ok, _ = _verify_dpop(cap["dpop"])
        assert ok


def test_invalidate_forces_reissue():
    cap = {"token_calls": 0, "check_calls": 0}
    _, ac = _new_creds()
    with patch("urllib.request.urlopen", side_effect=_router(_iso(3600), cap)):
        ac.token()
        ac.invalidate()
        ac.token()
        assert cap["token_calls"] == 2
