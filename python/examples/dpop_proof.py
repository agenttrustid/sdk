#!/usr/bin/env python3
"""Narrated, end-to-end proof that AgentTrust ID's runtime authorization is
sender-constrained: agent identity is proven by a key-bound WIMSE token plus a
per-request DPoP proof, not asserted in the request body. Runs against a REAL
gateway (no mocks) and demonstrates four properties, printing ✓/✗ for each.
Exits non-zero if any proof fails.

Token order under test:

    org API key ─▶ register agent (identity key) ─▶ PoP challenge ─▶
    WIMSE token (cnf.jkt) ─▶ per-request DPoP proof ─▶ /agenttrust/check

Setup (local stack):

    export AGENTTRUST_URL=http://localhost:8080     # gateway
    export AGENTTRUST_API_KEY=sk_live_...           # an ORG ADMIN key
    # The gateway/auth-service MUST run with BASE_URL=http://localhost:8080 so the
    # DPoP `htu` the server rebuilds matches the URL the SDK signs. If they differ,
    # even the legitimate check fails with a DPoP URL error.
    cd sdk/python && pip install -e . && python examples/dpop_proof.py

The demo enables `require_sender_constrained_tokens` on the org for the run and
restores the prior setting at the end.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

from agenttrustid import (
    AgentCredentials,
    AgentTrustClient,
    InMemoryKeyStore,
    generate_agent_key,
    mint_dpop_proof,
    mint_dpop_proof_with_key_store,
)

BASE_URL = os.getenv("AGENTTRUST_URL", "http://localhost:8080")
ADMIN_KEY = os.getenv("AGENTTRUST_API_KEY", "")
CHECK_PATH = "/api/v1/agenttrust/check"

_failures = 0


def banner(s):
    print(f"\n══ {s} ══")


def section(s):
    print(f"\n── {s} ──")


def ok(msg):
    print(f"  ✓ {msg}")


def bad(msg):
    global _failures
    _failures += 1
    print(f"  ✗ {msg}")


def fatal(msg):
    print(f"\nFATAL: {msg}")
    sys.exit(2)


def raw_check(bearer, dpop, body_agent_id):
    """Simulate a non-SDK caller (attacker/replay): hand-build the request."""
    body = json.dumps(
        {"agent_id": body_agent_id, "action_name": "read_file", "action_source": "api"}
    ).encode()
    headers = {"Content-Type": "application/json", "X-API-Key": ADMIN_KEY}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if dpop:
        headers["DPoP"] = dpop
    req = urllib.request.Request(BASE_URL + CHECK_PATH, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def expect_rejected(label, status):
    if status in (401, 403):
        ok(f"{label} ⇒ rejected (HTTP {status})")
    else:
        bad(f"{label} ⇒ NOT rejected (HTTP {status})")


def _security_url():
    return BASE_URL + "/api/v1/orgs/security-settings"


def get_security_settings():
    req = urllib.request.Request(_security_url(), headers={"X-API-Key": ADMIN_KEY})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read() or b"{}")


def set_security_settings(pop, sct):
    body = json.dumps(
        {"require_proof_of_possession": pop, "require_sender_constrained_tokens": sct}
    ).encode()
    req = urllib.request.Request(
        _security_url(),
        data=body,
        headers={"Content-Type": "application/json", "X-API-Key": ADMIN_KEY},
        method="PUT",
    )
    with urllib.request.urlopen(req) as resp:
        if resp.status < 200 or resp.status >= 300:
            fatal(f"update security settings: HTTP {resp.status}")


def create_agent(client, name):
    agent = client.agents.create(name=f"{name}-{time.strftime('%H%M%S')}", framework="custom")
    if not agent.private_key:
        fatal(f"agent {name} returned no private key")
    return agent


def main():
    global _failures
    if not ADMIN_KEY:
        fatal("set AGENTTRUST_API_KEY to an org admin key (sk_live_...)")

    banner("AgentTrust ID — sender-constrained runtime auth proof")
    print(f"  gateway: {BASE_URL}")
    print(
        "\n  Token order under test:\n"
        "    1. org API key          who is the ORGANISATION (X-API-Key, control plane)\n"
        "    2. agent identity key   who is the AGENT (client-held Ed25519; only the public half is registered)\n"
        "    3. PoP challenge        single-use nonce proving the agent holds its key\n"
        "    4. WIMSE token          short-lived JWT bound to the agent key via cnf.jkt\n"
        "    5. DPoP proof           per-request signature proving key possession on THIS call"
    )

    prior = get_security_settings()
    set_security_settings(True, True)
    try:
        client = AgentTrustClient(base_url=BASE_URL, api_key=ADMIN_KEY)

        section("Provision: register agents (steps 1–4 of the token order)")
        agent_a = create_agent(client, "dpop-proof-A")
        agent_b = create_agent(client, "dpop-proof-B")
        print(f"  agent A {agent_a.id} — public key registered, private key kept locally")
        print(f"  agent B {agent_b.id} — a second agent in the same org (for the spoof test)")

        ks = InMemoryKeyStore()
        ks.store(agent_a.id, agent_a.private_key)
        creds = AgentCredentials(client, ks, agent_a.id, agent_a.public_key)
        client.use_agent_credentials(creds)

        token_a = creds.token()  # challenge → sign → issue, cached
        print(f"  step 4: WIMSE token issued for A (cnf.jkt-bound): {token_a[:18]}…")

        # PROOF 1
        section("PROOF 1 — legitimate agent: WIMSE bearer + DPoP ⇒ accepted")
        try:
            client.actions.check(agent_id=agent_a.id, tool_name="read_file")
            ok("check authenticated and evaluated (step 5 DPoP proof verified against cnf.jkt)")
        except Exception as e:  # noqa: BLE001 - demo surfaces any failure
            bad(f"legitimate check rejected: {e}")
            print(f"  hint: if this is a DPoP URL error, run the gateway with BASE_URL={BASE_URL}")

        # PROOF 2
        section("PROOF 2 — stolen token without the key ⇒ rejected")
        expect_rejected("2a: replayed bearer, no DPoP proof", raw_check(token_a, "", agent_a.id))
        attacker = generate_agent_key()
        forged = mint_dpop_proof(attacker.private_key_pem, "POST", BASE_URL + CHECK_PATH, token_a)
        expect_rejected(
            "2b: bearer + DPoP signed by a different key (cnf.jkt mismatch)",
            raw_check(token_a, forged, agent_a.id),
        )

        # PROOF 3
        section("PROOF 3 — body says agent B, token proves agent A ⇒ rejected")
        try:
            client.actions.check(agent_id=agent_b.id, tool_name="read_file")
            bad("body agent_id spoof was ACCEPTED (identity trusted from body)")
        except Exception as e:  # noqa: BLE001
            ok(f"body agent_id=B with A's proof rejected — identity comes from the token: {e}")

        # PROOF 4
        section("PROOF 4 — DPoP proof replay ⇒ rejected")
        proof = mint_dpop_proof_with_key_store(
            ks, agent_a.id, agent_a.public_key, "POST", BASE_URL + CHECK_PATH, token_a
        )
        st1 = raw_check(token_a, proof, agent_a.id)
        st2 = raw_check(token_a, proof, agent_a.id)  # same jti again
        if 200 <= st1 < 300 and st2 in (401, 403):
            ok(f"first use accepted (HTTP {st1}), identical proof replayed ⇒ rejected (HTTP {st2})")
        else:
            bad(f"replay not prevented: first={st1} second={st2} (want 2xx then 401/403)")
    finally:
        set_security_settings(
            prior.get("require_proof_of_possession", False),
            prior.get("require_sender_constrained_tokens", False),
        )

    banner("Result")
    if _failures == 0:
        print("  ✓ all proofs passed — runtime auth is sender-constrained and token-derived")
        sys.exit(0)
    print(f"  ✗ {_failures} proof(s) failed")
    sys.exit(1)


if __name__ == "__main__":
    main()
