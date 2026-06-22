# AgentTrust ID — Proof Demo

A two-part, code-backed demonstration that AgentTrust ID does what it claims:
**agent identity on the runtime path is cryptographically proven, not asserted.**
A stolen credential is inert without the agent's key, and the platform trusts
the *proven* identity over anything the caller puts in the request body.

The demo has two pieces, and both follow the same storyline — the **logical
order of the tokens** an agent accumulates from "who is the org" down to "prove
you hold your key on this exact call":

1. **SDK proof** — runnable, narrated scripts in Go, Python, and TypeScript that
   hit a real gateway and print ✓/✗ for each property.
2. **Dashboard walkthrough** — the same flow shown in the UI: flip the
   enforcement toggles, see the agents, and watch the allowed call and the
   rejected attacks land in the audit trail.

---

## The token order (what each token proves)

| # | Token / credential | Answers | Created by | What makes it trustworthy |
|---|--------------------|---------|------------|----------------------------|
| 1 | **Org API key** (`sk_live_…`) | *Which organisation?* | issued to the org; sent as `X-API-Key` | secret bearer; control-plane / tenancy only |
| 2 | **Agent identity key** (Ed25519) | *Which agent?* | generated **client-side**; only the public half is registered | the private key never leaves the agent |
| 3 | **PoP challenge nonce** | *Does the agent hold its key right now?* | `POST /api/v1/agents/{id}/challenge` | single-use, short-lived; the agent signs it |
| 4 | **WIMSE token** (JWT, `cnf.jkt`) | *The agent's runtime credential* | `POST /api/v1/wimse/token` with a PoP proof | bound to the agent key via the RFC 7800 `cnf.jkt` thumbprint |
| 5 | **DPoP proof** (per request, RFC 9449) | *Does the caller hold the key on THIS call?* | minted fresh per request | signs `htm/htu/iat/jti/ath`; checked against the token's `cnf.jkt`; single-use `jti` |
| 6 | **Opaque capability token** (`at_…`) | *Scoped access to a resource* | `client.tokens.issue(...)` | server-side introspection; not a JWT, not client-verifiable |

Steps 1–5 are exactly what the SDK's auto-managed `AgentCredentials` runs for
you, and exactly what the proof scripts exercise. Step 6 is the downstream
capability layer (shown in the dashboard, not required for the four proofs).

---

## Prerequisites (local stack)

```bash
# 1. Infra + services (see core/Makefile)
make infra-up
# 2. IMPORTANT: run the gateway/auth-service with BASE_URL set to the SAME origin
#    the SDK calls, so the DPoP `htu` the server rebuilds matches what the SDK signs.
export BASE_URL=http://localhost:8080
make run-gateway        # (and the auth-service / other services your stack needs)

# 3. Point the demo at the gateway with an ORG ADMIN key
export AGENTTRUST_URL=http://localhost:8080
export AGENTTRUST_API_KEY=sk_live_...      # admin key for the demo org
```

> **The one gotcha:** if the gateway's `BASE_URL` ≠ `AGENTTRUST_URL`, even the
> legitimate check fails with a DPoP URL mismatch. The scripts print a hint if
> they detect this.

**Enable enforcement first (one click).** In the dashboard, turn on **Settings →
Security → "Require sender-constrained tokens (DPoP)"** for the demo org. That
setting is admin/session-gated, so the scripts can't flip it with an API key —
instead they **detect** whether it's on and abort with instructions if it isn't.
Do this on the demo org, not one with live agents.

---

## Piece 1 — SDK proof

Each script walks the token order, then proves four properties:

| Proof | Scenario | Expected |
|-------|----------|----------|
| **1** | Legitimate agent presents WIMSE bearer **+** a fresh DPoP proof | **accepted** (authenticated, evaluated) |
| **2a** | Attacker replays the stolen WIMSE token with **no** DPoP proof | **rejected** (401) |
| **2b** | Attacker forges a DPoP proof with a **different** key | **rejected** — `cnf.jkt` mismatch (401) |
| **3** | Caller authenticates as agent **A** but puts `agent_id: B` in the body | **rejected** — identity comes from the token, not the body (403) |
| **4** | A captured, valid DPoP proof is **replayed** (same `jti`) | first use accepted, replay **rejected** (401) |

Run whichever language fits your audience:

```bash
# Go
cd sdk/go && go run ./examples/dpop_proof

# Python
cd sdk/python && pip install -e . && python examples/dpop_proof.py

# TypeScript
cd sdk/typescript && npm run build && npm i -D tsx && npx tsx examples/dpop-proof.ts
```

All three print the same narrated output and exit non-zero if any proof fails:

```
══ AgentTrust ID — sender-constrained runtime auth proof ══
  gateway: http://localhost:8080
  Token order under test:
    1. org API key  …  2. agent identity key  …  5. DPoP proof

── PROOF 1 — legitimate agent: WIMSE bearer + DPoP ⇒ accepted ──
  ✓ check authenticated and evaluated (step 5 DPoP proof verified against cnf.jkt)
── PROOF 2 — stolen token without the key ⇒ rejected ──
  ✓ 2a: replayed bearer, no DPoP proof ⇒ rejected (HTTP 401)
  ✓ 2b: bearer + DPoP signed by a different key (cnf.jkt mismatch) ⇒ rejected (HTTP 401)
── PROOF 3 — body says agent B, token proves agent A ⇒ rejected ──
  ✓ body agent_id=B with A's proof rejected — identity comes from the token
── PROOF 4 — DPoP proof replay ⇒ rejected ──
  ✓ first use accepted (HTTP 200), identical proof replayed ⇒ rejected (HTTP 401)
══ Result ══
  ✓ all proofs passed — runtime auth is sender-constrained and token-derived
```

The legitimate calls go through the SDK (`AgentCredentials` attaches the bearer
+ DPoP automatically); the attacker/replay calls are hand-built HTTP requests —
because a real attacker wouldn't use our SDK.

---

## Piece 2 — Dashboard walkthrough

Run this alongside the SDK script for a visual audience. All pages are in the
dashboard app.

1. **Settings → Security.** Show the two enforcement toggles:
   *"Require proof-of-possession"* and *"Require sender-constrained tokens
   (DPoP)."* Both default **off** — so turning enforcement on is opt-in and
   non-breaking for existing traffic. Turn them **on** for the demo org.
2. **Agents.** Show the two demo agents the script registered. Each has a
   **public key on file** — the platform stored only the public half; the
   private key stayed on the agent.
3. **Run the SDK proof script** (Piece 1). It registers the agents, makes the
   legitimate call, and fires the three attacks.
4. **Audit** ("Security events, denials, and guard decisions"). Show:
   - the **allowed** check from the legitimate agent, and
   - the **denials** from the stolen-token, spoofed-identity, and replay
     attempts.
5. **Accountability.** Show the signed audit chain — the decisions are recorded
   tamper-evidently, not just returned.
6. **The money shot (optional):** toggle *Require sender-constrained tokens*
   **off**, re-run just the stolen-token step, and show the bearer is now
   accepted; toggle it back **on** and show the same request rejected. That is
   the before/after of sender-constrained auth in one click.

---

## Claims ↔ evidence

| What we say | What proves it |
|-------------|----------------|
| "Per-agent cryptographic identity, not a shared key." | Proof 1 + the token order: every call carries the agent's key-bound WIMSE token + DPoP. |
| "A stolen token is useless without the agent's key." | Proof 2a / 2b — bearer alone, and even a forged DPoP, are rejected. |
| "We trust the proven identity, not the caller's claim." | Proof 3 — a spoofed `agent_id` in the body is overridden/rejected. |
| "Proofs can't be replayed." | Proof 4 — a reused `jti` is rejected. |
| "Enforcement is opt-in and safe to roll out." | Dashboard toggles default off; the before/after in step 6. |

---

## Cleanup

The scripts don't change org settings — enforcement is toggled by you in the
dashboard. When you're done, turn **Settings → Security → "Require
sender-constrained tokens (DPoP)"** back off if you don't want it left on for the
demo org. The demo agents it registers (`dpop-proof-A/B-…`) can be removed from
the Agents page.
