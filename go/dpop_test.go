package agenttrust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// parseDPoP splits a compact DPoP JWT and returns its decoded header, payload,
// the signing input, and the raw signature — enough to validate structure and
// verify the signature against the embedded JWK.
func parseDPoP(t *testing.T, proof string) (header, payload map[string]interface{}, signingInput string, sig []byte) {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if err := json.Unmarshal(pb, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return header, payload, parts[0] + "." + parts[1], sig
}

func TestMintDPoPProof_StructureAndSignature(t *testing.T) {
	kp, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const tok = "wimse.token.value"
	proof, err := MintDPoPProof(kp.PrivateKeyPEM, "POST", "https://api.agenttrust.id/api/v1/agenttrust/check", tok)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	header, payload, signingInput, sig := parseDPoP(t, proof)

	if header["typ"] != "dpop+jwt" {
		t.Errorf("typ = %v, want dpop+jwt", header["typ"])
	}
	if header["alg"] != "EdDSA" {
		t.Errorf("alg = %v, want EdDSA", header["alg"])
	}
	jwk, ok := header["jwk"].(map[string]interface{})
	if !ok || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
		t.Fatalf("jwk = %v, want OKP/Ed25519", header["jwk"])
	}
	if payload["htm"] != "POST" {
		t.Errorf("htm = %v, want POST", payload["htm"])
	}
	if payload["htu"] != "https://api.agenttrust.id/api/v1/agenttrust/check" {
		t.Errorf("htu = %v", payload["htu"])
	}
	if payload["jti"] == nil || payload["jti"] == "" {
		t.Error("jti missing")
	}

	// ath must be base64url(sha256(token)).
	sum := sha256.Sum256([]byte(tok))
	if payload["ath"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Errorf("ath = %v, want hash of token", payload["ath"])
	}

	// Signature must verify against the public key embedded in the jwk.
	x, err := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
	if err != nil || len(x) != ed25519.PublicKeySize {
		t.Fatalf("bad jwk.x: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(x), []byte(signingInput), sig) {
		t.Error("DPoP signature did not verify against embedded jwk")
	}
}

func TestMintDPoPProof_NoAccessToken_OmitsATH(t *testing.T) {
	kp, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	proof, err := MintDPoPProof(kp.PrivateKeyPEM, "GET", "https://api.agenttrust.id/v1/agents", "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	_, payload, _, _ := parseDPoP(t, proof)
	if _, present := payload["ath"]; present {
		t.Error("ath should be omitted when no access token is provided")
	}
}

func TestMintDPoPProof_InvalidKeyRejected(t *testing.T) {
	if _, err := MintDPoPProof("not-a-pem", "GET", "https://x/y", ""); err == nil {
		t.Fatal("expected error for invalid private key PEM")
	}
}

func TestMintDPoPProofWithKeyStore_VerifiesAndOmitsExportedKey(t *testing.T) {
	kp, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ks := NewMemoryKeyStore()
	if err := ks.Store("agent-1", kp.PrivateKeyPEM); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Signs through the KeyStore; only the public key PEM is supplied.
	proof, err := MintDPoPProofWithKeyStore(ks, "agent-1", kp.PublicKeyPEM,
		"POST", "https://api.agenttrust.id/api/v1/agenttrust/check", "tok")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	header, payload, signingInput, sig := parseDPoP(t, proof)
	if header["typ"] != "dpop+jwt" || header["alg"] != "EdDSA" {
		t.Fatalf("bad header: %v", header)
	}
	jwk := header["jwk"].(map[string]interface{})
	x, err := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
	if err != nil || len(x) != ed25519.PublicKeySize {
		t.Fatalf("bad jwk.x: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(x), []byte(signingInput), sig) {
		t.Error("KeyStore-minted DPoP did not verify against embedded jwk")
	}
	if payload["jti"] == nil || payload["jti"] == "" {
		t.Error("jti missing")
	}
}

func TestMintDPoPProofWithKeyStore_NilKeyStore(t *testing.T) {
	if _, err := MintDPoPProofWithKeyStore(nil, "a", "", "GET", "https://x/y", ""); err == nil {
		t.Fatal("expected error for nil KeyStore")
	}
}
