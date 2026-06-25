"""Client-side agent identity keys.

Agents generate their own Ed25519 keypair and register only the public key with
the platform; the private key never leaves the agent. PEM encoding matches the
platform parser: PKIX SubjectPublicKeyInfo ("PUBLIC KEY") for the public half and
PKCS#8 ("PRIVATE KEY") for the private half.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_KEYCHAIN_SERVICE = "agenttrust-id"


@dataclass
class AgentKeyPair:
    """A PEM-encoded Ed25519 identity keypair. Only ``public_key_pem`` is sent to
    the platform; ``private_key_pem`` stays on the agent."""

    public_key_pem: str
    private_key_pem: str


def generate_agent_key() -> "AgentKeyPair":
    """Generate a new Ed25519 identity keypair for an agent."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return AgentKeyPair(public_key_pem=public_pem, private_key_pem=private_pem)


def _load_private_key(private_key_pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key is not Ed25519")
    return key


def sign_with_private_key_pem(private_key_pem: str, data: bytes) -> bytes:
    """Sign ``data`` with a PKCS#8 PEM-encoded Ed25519 private key.

    Used by KeyStore backends and the proof-of-possession / DPoP flows.
    """
    return _load_private_key(private_key_pem).sign(data)


class KeyStore(ABC):
    """Persists an agent's private key and signs with it. Native backends can keep
    the key non-exportable: callers sign through the store, not with raw material."""

    @abstractmethod
    def store(self, agent_id: str, private_key_pem: str) -> None:
        ...

    @abstractmethod
    def sign(self, agent_id: str, data: bytes) -> bytes:
        ...

    @abstractmethod
    def delete(self, agent_id: str) -> None:
        ...


class InMemoryKeyStore(KeyStore):
    """Keeps private keys in process memory. For tests and ephemeral agents; use
    :class:`KeychainKeyStore` for persistence."""

    def __init__(self) -> None:
        self._keys = {}

    def store(self, agent_id: str, private_key_pem: str) -> None:
        _load_private_key(private_key_pem)  # validate before storing
        self._keys[agent_id] = private_key_pem

    def sign(self, agent_id: str, data: bytes) -> bytes:
        pem = self._keys.get(agent_id)
        if pem is None:
            raise KeyError(f"no key stored for agent {agent_id!r}")
        return sign_with_private_key_pem(pem, data)

    def delete(self, agent_id: str) -> None:
        self._keys.pop(agent_id, None)


class KeychainKeyStore(KeyStore):
    """Stores private keys in the OS secret store via the ``keyring`` library:
    macOS Keychain, Windows Credential Manager, or the Linux Secret Service."""

    def __init__(self, service: str = _KEYCHAIN_SERVICE) -> None:
        self._service = service

    def store(self, agent_id: str, private_key_pem: str) -> None:
        import keyring

        _load_private_key(private_key_pem)  # validate before storing
        keyring.set_password(self._service, agent_id, private_key_pem)

    def sign(self, agent_id: str, data: bytes) -> bytes:
        import keyring

        pem = keyring.get_password(self._service, agent_id)
        if pem is None:
            raise KeyError(f"no key stored for agent {agent_id!r}")
        return sign_with_private_key_pem(pem, data)

    def delete(self, agent_id: str) -> None:
        import keyring

        keyring.delete_password(self._service, agent_id)
