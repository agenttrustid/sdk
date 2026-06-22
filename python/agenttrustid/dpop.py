"""RFC 9449 DPoP proof minting.

Produces the exact JOSE shape the platform verifies, signed with the agent's
Ed25519 key (using the same ``cryptography`` primitives as the SDK's existing
proof-of-possession signing)::

    header:  {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": ...}}
    payload: {"htm", "htu", "iat", "jti", "ath"?}

The platform verifies the signature against the embedded JWK and checks the
key's thumbprint against the access token's RFC 7800 ``cnf.jkt``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Callable, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .keys import KeyStore, _load_private_key, sign_with_private_key_pem


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json(obj: Dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def _jwk_from_public_key(pub: Ed25519PublicKey) -> Dict[str, str]:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


def _load_public_key(public_key_pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return key


def _build_proof(
    jwk: Dict[str, str],
    sign: Callable[[bytes], bytes],
    method: str,
    url: str,
    access_token: str,
) -> str:
    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk}
    payload: Dict = {
        "htm": method,
        "htu": url,
        "iat": int(time.time()),
        "jti": os.urandom(16).hex(),
    }
    if access_token:
        payload["ath"] = _b64url(hashlib.sha256(access_token.encode("utf-8")).digest())
    signing_input = _b64url(_json(header)) + "." + _b64url(_json(payload))
    sig = sign(signing_input.encode("ascii"))
    return signing_input + "." + _b64url(sig)


def mint_dpop_proof(private_key_pem: str, method: str, url: str, access_token: str = "") -> str:
    """Mint a DPoP proof signed with the agent's Ed25519 private key (PKCS#8 PEM)."""
    jwk = _jwk_from_public_key(_load_private_key(private_key_pem).public_key())
    return _build_proof(
        jwk,
        lambda d: sign_with_private_key_pem(private_key_pem, d),
        method,
        url,
        access_token,
    )


def mint_dpop_proof_with_key_store(
    key_store: KeyStore,
    agent_id: str,
    public_key_pem: str,
    method: str,
    url: str,
    access_token: str = "",
) -> str:
    """Mint a DPoP proof signing through a KeyStore, so the private key stays
    non-exportable; only the public key (PKIX PEM) is handled in the clear."""
    jwk = _jwk_from_public_key(_load_public_key(public_key_pem))
    return _build_proof(
        jwk,
        lambda d: key_store.sign(agent_id, d),
        method,
        url,
        access_token,
    )
