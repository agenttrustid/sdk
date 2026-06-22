"""Auto-managed agent runtime credentials.

:class:`AgentCredentials` issues a WIMSE token via the proof-of-possession flow,
caches it, refreshes it before expiry, and produces per-request
``Authorization: Bearer`` + ``DPoP`` headers. The private key never leaves the
KeyStore — both the PoP signature (at issuance) and the DPoP proof (per request)
are signed through it.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .dpop import mint_dpop_proof_with_key_store
from .keys import KeyStore

# How long before a WIMSE token's expiry the manager proactively re-issues, so a
# request never goes out with an about-to-expire token.
_CREDENTIAL_REFRESH_SKEW_SECONDS = 60.0


class AgentCredentials:
    """Manages an agent's runtime authentication. Thread-safe.

    Build it from a client, then route runtime checks through it::

        ac = AgentCredentials(client, key_store, agent_id, public_key_pem)
        client.use_agent_credentials(ac)
        client.actions.check(agent_id=agent_id, tool_name="read_file")
    """

    def __init__(
        self,
        client,
        key_store: KeyStore,
        agent_id: str,
        public_key_pem: str,
        audience: Optional[List[str]] = None,
        ttl_seconds: Optional[int] = None,
    ):
        self._wimse = client.wimse
        self._base_url = client.http.base_url
        self._ks = key_store
        self._agent_id = agent_id
        self._public_key_pem = public_key_pem
        self._audience = audience
        self._ttl_seconds = ttl_seconds

        self._lock = threading.Lock()
        self._token = ""
        self._expires_at = 0.0  # epoch seconds

    def token(self) -> str:
        """Return a currently-valid WIMSE token, issuing or refreshing one via the
        proof-of-possession flow when the cache is empty or near expiry."""
        with self._lock:
            if self._token and (self._expires_at - time.time()) > _CREDENTIAL_REFRESH_SKEW_SECONDS:
                return self._token

            resp = self._wimse.issue_token_with_proof(
                agent_id=self._agent_id,
                key_store=self._ks,
                audience=self._audience,
                ttl_seconds=self._ttl_seconds,
            )
            self._token = resp.token
            self._expires_at = _parse_token_expiry(resp.expires_at)
            return self._token

    def runtime_headers(self, method: str, path: str) -> Dict[str, str]:
        """Return the headers to attach to a runtime request: a Bearer WIMSE token
        plus a fresh DPoP proof bound to the request (htu = base URL + path) and
        the token (ath)."""
        token = self.token()
        proof = mint_dpop_proof_with_key_store(
            self._ks,
            self._agent_id,
            self._public_key_pem,
            method,
            self._base_url + path,
            token,
        )
        return {"Authorization": f"Bearer {token}", "DPoP": proof}

    def invalidate(self) -> None:
        """Clear the cached token, forcing a fresh issuance on the next call."""
        with self._lock:
            self._token = ""
            self._expires_at = 0.0


def _parse_token_expiry(s: str) -> float:
    """Parse an RFC 3339 expiry to epoch seconds; on failure fall back to a
    conservative short window so the manager re-issues soon."""
    if s:
        try:
            normalized = s.replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).timestamp()
        except ValueError:
            pass
    return time.time() + 300.0
