import base64
import hashlib
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agenttrustid import (
    InMemoryKeyStore,
    generate_agent_key,
    mint_dpop_proof,
    mint_dpop_proof_with_key_store,
)

CHECK_URL = "https://api.agenttrust.id/api/v1/agenttrust/check"


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _parse(proof: str):
    h, p, s = proof.split(".")
    return (
        json.loads(_b64url_decode(h)),
        json.loads(_b64url_decode(p)),
        f"{h}.{p}".encode("ascii"),
        _b64url_decode(s),
    )


def _verify(proof: str) -> bool:
    header, _, signing_input, sig = _parse(proof)
    raw = _b64url_decode(header["jwk"]["x"])
    pub = Ed25519PublicKey.from_public_bytes(raw)
    try:
        pub.verify(sig, signing_input)
        return True
    except InvalidSignature:
        return False


def test_mint_dpop_proof_claims_and_signature():
    kp = generate_agent_key()
    proof = mint_dpop_proof(kp.private_key_pem, "POST", CHECK_URL, "access-tok")
    header, payload, _, _ = _parse(proof)

    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "EdDSA"
    assert header["jwk"]["kty"] == "OKP"
    assert header["jwk"]["crv"] == "Ed25519"
    assert header["jwk"]["x"]

    assert payload["htm"] == "POST"
    assert payload["htu"] == CHECK_URL
    assert isinstance(payload["iat"], int)
    assert payload["jti"]
    expected_ath = base64.urlsafe_b64encode(hashlib.sha256(b"access-tok").digest()).rstrip(b"=").decode("ascii")
    assert payload["ath"] == expected_ath

    assert _verify(proof) is True


def test_mint_dpop_proof_omits_ath_without_token():
    kp = generate_agent_key()
    _, payload, _, _ = _parse(mint_dpop_proof(kp.private_key_pem, "GET", "https://x/y"))
    assert "ath" not in payload


def test_mint_dpop_proof_unique_jti():
    kp = generate_agent_key()
    _, a, _, _ = _parse(mint_dpop_proof(kp.private_key_pem, "POST", CHECK_URL, "tok"))
    _, b, _, _ = _parse(mint_dpop_proof(kp.private_key_pem, "POST", CHECK_URL, "tok"))
    assert a["jti"] != b["jti"]


def test_mint_dpop_proof_with_key_store_verifies():
    kp = generate_agent_key()
    ks = InMemoryKeyStore()
    ks.store("agent-1", kp.private_key_pem)
    proof = mint_dpop_proof_with_key_store(ks, "agent-1", kp.public_key_pem, "POST", CHECK_URL, "tok")
    assert _verify(proof) is True


def test_mint_dpop_proof_rejects_non_ed25519():
    with pytest.raises(Exception):
        mint_dpop_proof("-----BEGIN PRIVATE KEY-----\nbogus\n-----END PRIVATE KEY-----", "POST", CHECK_URL)
