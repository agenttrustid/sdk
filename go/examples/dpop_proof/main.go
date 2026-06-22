// Command dpop_proof is a narrated, end-to-end proof that AgentTrust ID's
// runtime authorization is sender-constrained: agent identity is proven by a
// key-bound WIMSE token plus a per-request DPoP proof, not asserted in the
// request body. It runs against a REAL gateway (no mocks) and demonstrates four
// properties, printing ✓/✗ for each. Exits non-zero if any proof fails.
//
// It walks the full token order:
//
//	org API key ─▶ register agent (identity key) ─▶ PoP challenge ─▶
//	WIMSE token (cnf.jkt) ─▶ per-request DPoP proof ─▶ /agenttrust/check
//
// Setup (local stack):
//
//	export AGENTTRUST_URL=http://localhost:8080        # gateway
//	export AGENTTRUST_API_KEY=sk_live_...              # an ORG ADMIN key
//	# The gateway/auth-service MUST run with BASE_URL=http://localhost:8080 so
//	# the DPoP `htu` the server rebuilds matches the URL the SDK signs. If they
//	# differ, even the legitimate check fails with a DPoP URL error.
//	cd sdk/go && go run ./examples/dpop_proof
//
// PRECONDITION: enable the org's enforcement toggle first, in the dashboard at
// Settings → Security → "Require sender-constrained tokens (DPoP)" (that setting
// is admin/session-gated, so the demo can't flip it with an API key). The demo
// detects whether it is on and tells you if it isn't.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	agenttrust "github.com/agenttrustid/sdk/go"
)

const checkPath = "/api/v1/agenttrust/check"

var (
	baseURL  = env("AGENTTRUST_URL", "http://localhost:8080")
	adminKey = os.Getenv("AGENTTRUST_API_KEY")
	failures int
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if adminKey == "" {
		fatal("set AGENTTRUST_API_KEY to an org admin key (sk_live_...)")
	}
	ctx := context.Background()

	banner("AgentTrust ID — sender-constrained runtime auth proof")
	fmt.Printf("  gateway: %s\n", baseURL)
	fmt.Println(strings.TrimSpace(`
  Token order under test:
    1. org API key          who is the ORGANISATION (X-API-Key, control plane)
    2. agent identity key   who is the AGENT (client-held Ed25519; only the public half is registered)
    3. PoP challenge        single-use nonce proving the agent holds its key
    4. WIMSE token          short-lived JWT bound to the agent key via cnf.jkt
    5. DPoP proof           per-request signature proving key possession on THIS call
`))

	client := agenttrust.NewClient(agenttrust.WithBaseURL(baseURL), agenttrust.WithAPIKey(adminKey))

	// ── Token order steps 1–4: register an agent and stand up its credentials ──
	section("Provision: register agents (steps 1–4 of the token order)")
	agentA := mustCreate(ctx, client, "dpop-proof-A")
	agentB := mustCreate(ctx, client, "dpop-proof-B")
	fmt.Printf("  agent A %s — public key registered, private key kept locally\n", agentA.ID)
	fmt.Printf("  agent B %s — a second agent in the same org (for the spoof test)\n", agentB.ID)

	ksA := agenttrust.NewMemoryKeyStore()
	must(ksA.Store(agentA.ID, agentA.PrivateKey), "store agent A key")
	credsA := agenttrust.NewAgentCredentials(client, ksA, agentA.ID, agentA.PublicKey)

	// AgentCredentials runs challenge → sign → issue and caches the WIMSE token.
	tokenA, err := credsA.Token(ctx)
	must(err, "issue WIMSE token for A (proof-of-possession)")
	fmt.Printf("  step 4: WIMSE token issued for A (cnf.jkt-bound): %s…\n", short(tokenA))

	// Precondition: the org must enforce sender-constrained tokens, else the
	// rejection proofs can't fire. Detect it behaviorally (a bearer with no DPoP
	// proof): rejected ⇒ enforcement on; accepted ⇒ the toggle is still off.
	section("Precondition: org enforces sender-constrained tokens")
	if st, _ := rawCheck(tokenA, "", agentA.ID); st == http.StatusUnauthorized || st == http.StatusForbidden {
		pass("enforcement is ON (bearer without a DPoP proof is rejected, HTTP %d)", st)
	} else {
		fatal("enforcement is OFF (bearer without DPoP returned HTTP %d).\n"+
			"  Enable Settings → Security → \"Require sender-constrained tokens (DPoP)\" for this org, then re-run.", st)
	}

	authedClient := agenttrust.NewClient(
		agenttrust.WithBaseURL(baseURL),
		agenttrust.WithAPIKey(adminKey),
		agenttrust.WithAgentCredentials(credsA),
	)

	// ── PROOF 1: legitimate call — bearer + a fresh DPoP proof is accepted ──
	section("PROOF 1 — legitimate agent: WIMSE bearer + DPoP ⇒ accepted")
	_, err = authedClient.Actions.Check(ctx, agenttrust.ActionCheckRequest{AgentID: agentA.ID, ToolName: "read_file"})
	if err == nil {
		pass("check authenticated and evaluated (step 5 DPoP proof verified against cnf.jkt)")
	} else {
		fail("legitimate check rejected: %v", err)
		fmt.Println("  hint: if this is a DPoP URL error, run the gateway with BASE_URL=" + baseURL)
	}

	// ── PROOF 2: a stolen WIMSE token, without the agent's key, is inert ──
	section("PROOF 2 — stolen token without the key ⇒ rejected")
	st, _ := rawCheck(tokenA, "", agentA.ID) // bearer only, no DPoP
	expectRejected("2a: replayed bearer, no DPoP proof", st)

	attacker, err := agenttrust.GenerateAgentKey()
	must(err, "generate attacker key")
	forged, err := agenttrust.MintDPoPProof(attacker.PrivateKeyPEM, http.MethodPost, baseURL+checkPath, tokenA)
	must(err, "mint forged DPoP")
	st, _ = rawCheck(tokenA, forged, agentA.ID) // bearer + DPoP signed by the WRONG key
	expectRejected("2b: bearer + DPoP signed by a different key (cnf.jkt mismatch)", st)

	// ── PROOF 3: identity is taken from the token, not the request body ──
	section("PROOF 3 — body says agent B, token proves agent A ⇒ rejected")
	_, err = authedClient.Actions.Check(ctx, agenttrust.ActionCheckRequest{AgentID: agentB.ID, ToolName: "read_file"})
	if err != nil {
		pass("body agent_id=B with A's proof rejected — identity comes from the token: %v", err)
	} else {
		fail("body agent_id spoof was ACCEPTED (identity trusted from body)")
	}

	// ── PROOF 4: a captured DPoP proof cannot be replayed ──
	section("PROOF 4 — DPoP proof replay ⇒ rejected")
	proof, err := agenttrust.MintDPoPProofWithKeyStore(ksA, agentA.ID, agentA.PublicKey, http.MethodPost, baseURL+checkPath, tokenA)
	must(err, "mint DPoP for replay test")
	st1, _ := rawCheck(tokenA, proof, agentA.ID)
	st2, _ := rawCheck(tokenA, proof, agentA.ID) // same jti again
	if st1 >= 200 && st1 < 300 && (st2 == http.StatusUnauthorized || st2 == http.StatusForbidden) {
		pass("first use accepted (HTTP %d), identical proof replayed ⇒ rejected (HTTP %d)", st1, st2)
	} else {
		fail("replay not prevented: first=%d second=%d (want 2xx then 401/403)", st1, st2)
	}

	// ── Summary ──
	banner("Result")
	if failures == 0 {
		fmt.Println("  ✓ all proofs passed — runtime auth is sender-constrained and token-derived")
		os.Exit(0)
	}
	fmt.Printf("  ✗ %d proof(s) failed\n", failures)
	os.Exit(1)
}

// rawCheck simulates a caller that is NOT the SDK (an attacker or a replay):
// it hand-builds the HTTP request with whatever bearer/DPoP we choose.
func rawCheck(bearer, dpop, bodyAgentID string) (int, string) {
	body, _ := json.Marshal(map[string]string{
		"agent_id": bodyAgentID, "action_name": "read_file", "action_source": "api",
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+checkPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", adminKey) // org auth (control plane) still required
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if dpop != "" {
		req.Header.Set("DPoP", dpop)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("raw check transport error: %v", err)
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func expectRejected(label string, status int) {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		pass("%s ⇒ rejected (HTTP %d)", label, status)
	} else {
		fail("%s ⇒ NOT rejected (HTTP %d)", label, status)
	}
}

func mustCreate(ctx context.Context, c *agenttrust.Client, name string) *agenttrust.Agent {
	a, err := c.Agents.Create(ctx, agenttrust.CreateAgentRequest{Name: name + "-" + time.Now().Format("150405.000"), Framework: "custom"})
	must(err, "create agent "+name)
	if a.PrivateKey == "" {
		fatal("agent %s returned no private key (cannot run the demo)", name)
	}
	return a
}

// --- tiny console helpers ---

func banner(s string) { fmt.Printf("\n══ %s ══\n", s) }
func section(s string) { fmt.Printf("\n── %s ──\n", s) }
func pass(format string, a ...any) { fmt.Printf("  ✓ "+format+"\n", a...) }
func fail(format string, a ...any) { failures++; fmt.Printf("  ✗ "+format+"\n", a...) }
func short(s string) string {
	if len(s) > 18 {
		return s[:18]
	}
	return s
}
func must(err error, what string) {
	if err != nil {
		fatal("%s: %v", what, err)
	}
}
func fatal(format string, a ...any) {
	fmt.Printf("\nFATAL: "+format+"\n", a...)
	os.Exit(2)
}
