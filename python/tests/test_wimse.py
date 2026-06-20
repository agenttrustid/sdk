"""Tests for the WIMSE API, including the proof-of-possession flow.

These assert the SDK performs challenge -> sign -> issue and that the proof it
sends is a valid Ed25519 signature over the canonical message the server
verifies (``pop-v1:<nonce>:<agentID>:<audience>:<ts>``).
"""
import base64
import unittest
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization

from agenttrustid.client import WIMSEAPI
from agenttrustid.keys import generate_agent_key, InMemoryKeyStore


class TestWIMSEAPI(unittest.TestCase):
    def test_issue_token_builds_request(self):
        http = MagicMock()
        http.post.return_value = {
            "token": "eyJ.t",
            "workload_id": "spiffe://ati/agent/a1",
            "trust_domain": "agenttrust.id",
            "expires_at": "2026-12-31T00:00:00Z",
        }
        resp = WIMSEAPI(http).issue_token("a1", service_name="payments", ttl_seconds=600)
        path, data = http.post.call_args[0]
        self.assertEqual(path, "/api/v1/wimse/token")
        self.assertEqual(data["agent_id"], "a1")
        self.assertEqual(data["service_name"], "payments")
        self.assertEqual(resp.token, "eyJ.t")
        self.assertEqual(resp.workload_id, "spiffe://ati/agent/a1")

    def test_verify_token(self):
        http = MagicMock()
        http.post.return_value = {"valid": True, "agent_id": "a1", "capabilities": ["x", "y"]}
        resp = WIMSEAPI(http).verify_token("eyJ.t")
        self.assertTrue(resp.valid)
        self.assertEqual(resp.agent_id, "a1")
        self.assertEqual(len(resp.capabilities), 2)

    def test_issue_token_with_proof_signs_canonical_message(self):
        kp = generate_agent_key()
        ks = InMemoryKeyStore()
        ks.store("a1", kp.private_key_pem)

        nonce = "server-nonce-xyz"
        audience = ["https://api.example.com"]
        captured = {}

        def post(path, data=None):
            if path.endswith("/challenge"):
                return {"nonce": nonce, "expires_at": "2026-12-31T00:00:00Z"}
            if path == "/api/v1/wimse/token":
                captured["body"] = data
                return {"token": "eyJ.bound", "trust_domain": "agenttrust.id"}
            raise AssertionError(f"unexpected path {path}")

        http = MagicMock()
        http.post.side_effect = post

        resp = WIMSEAPI(http).issue_token_with_proof("a1", ks, audience=audience)
        self.assertEqual(resp.token, "eyJ.bound")

        proof = captured["body"]["proof"]
        self.assertEqual(proof["nonce"], nonce)

        # Reconstruct the canonical message and verify the signature with the
        # agent's public key — exactly what the server's VerifyPoP checks.
        ts = proof["ts"]
        message = f"pop-v1:{nonce}:a1:{','.join(audience)}:{ts}".encode("utf-8")
        sig_b64 = proof["signature"] + "=" * (-len(proof["signature"]) % 4)
        sig = base64.urlsafe_b64decode(sig_b64)
        pub = serialization.load_pem_public_key(kp.public_key_pem.encode())
        pub.verify(sig, message)  # raises InvalidSignature on mismatch

    def test_challenge(self):
        http = MagicMock()
        http.post.return_value = {"nonce": "n1", "expires_at": "2026-12-31T00:00:00Z"}
        resp = WIMSEAPI(http).challenge("a1")
        http.post.assert_called_once_with("/api/v1/agents/a1/challenge")
        self.assertEqual(resp.nonce, "n1")


if __name__ == "__main__":
    unittest.main()
