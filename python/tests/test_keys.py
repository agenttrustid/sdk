"""Tests for client-side agent identity keys (Phase 0).

The platform parses public keys as PKIX SubjectPublicKeyInfo ("PUBLIC KEY") and
private keys as PKCS#8 ("PRIVATE KEY"); these tests assert the SDK emits exactly
that so registration interoperates.
"""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agenttrustid.keys import (
    generate_agent_key,
    sign_with_private_key_pem,
    InMemoryKeyStore,
    KeychainKeyStore,
)


def test_generate_agent_key_server_compatible_pem():
    kp = generate_agent_key()
    assert kp.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert kp.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
    pub = serialization.load_pem_public_key(kp.public_key_pem.encode())
    assert isinstance(pub, Ed25519PublicKey)


def test_sign_verifies_against_public_key():
    kp = generate_agent_key()
    msg = b"proof-of-possession challenge"
    sig = sign_with_private_key_pem(kp.private_key_pem, msg)
    pub = serialization.load_pem_public_key(kp.public_key_pem.encode())
    pub.verify(sig, msg)  # raises InvalidSignature on failure


def test_in_memory_key_store_roundtrip():
    kp = generate_agent_key()
    ks = InMemoryKeyStore()
    ks.store("agt-1", kp.private_key_pem)

    sig = ks.sign("agt-1", b"hello")
    pub = serialization.load_pem_public_key(kp.public_key_pem.encode())
    pub.verify(sig, b"hello")

    ks.delete("agt-1")
    with pytest.raises(KeyError):
        ks.sign("agt-1", b"hello")


def test_in_memory_key_store_rejects_invalid_key():
    ks = InMemoryKeyStore()
    with pytest.raises(Exception):
        ks.store("agt", "not-a-pem")


def test_sign_with_invalid_private_key_raises():
    with pytest.raises(Exception):
        sign_with_private_key_pem("not-a-key", b"data")


def test_rejects_valid_but_non_ed25519_key():
    # A valid PKCS#8 RSA key parses fine but must be rejected as not Ed25519.
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    with pytest.raises(ValueError):
        sign_with_private_key_pem(rsa_pem, b"data")


def test_keychain_key_store_roundtrip(monkeypatch):
    # Exercise the native keychain backend without a real OS keychain by patching
    # the keyring library with an in-memory dict.
    import keyring

    fake = {}
    monkeypatch.setattr(keyring, "set_password", lambda s, u, p: fake.__setitem__((s, u), p))
    monkeypatch.setattr(keyring, "get_password", lambda s, u: fake.get((s, u)))
    monkeypatch.setattr(keyring, "delete_password", lambda s, u: fake.pop((s, u), None))

    kp = generate_agent_key()
    ks = KeychainKeyStore()
    ks.store("agt-1", kp.private_key_pem)
    assert ("agenttrust-id", "agt-1") in fake

    sig = ks.sign("agt-1", b"hello")
    pub = serialization.load_pem_public_key(kp.public_key_pem.encode())
    pub.verify(sig, b"hello")

    ks.delete("agt-1")
    with pytest.raises(KeyError):
        ks.sign("agt-1", b"hello")
