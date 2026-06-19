package agenttrust

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// The platform parses public keys with pem.Decode + x509.ParsePKIXPublicKey and
// expects a "PUBLIC KEY" block (see core internal/pkg/crypto/keys.go). These
// tests assert the SDK emits exactly that, so registration interoperates.

func TestGenerateAgentKey_ServerCompatiblePEM(t *testing.T) {
	kp, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("GenerateAgentKey: %v", err)
	}

	block, _ := pem.Decode([]byte(kp.PublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("public key PEM block = %+v, want type PUBLIC KEY", block)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("server-side ParsePKIXPublicKey failed: %v", err)
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Fatal("public key is not Ed25519")
	}

	pblock, _ := pem.Decode([]byte(kp.PrivateKeyPEM))
	if pblock == nil || pblock.Type != "PRIVATE KEY" {
		t.Fatalf("private key PEM block = %+v, want type PRIVATE KEY", pblock)
	}
}

func TestSignWithPrivateKeyPEM_VerifiesAgainstPublic(t *testing.T) {
	kp, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("GenerateAgentKey: %v", err)
	}
	msg := []byte("proof-of-possession challenge")
	sig, err := SignWithPrivateKeyPEM(kp.PrivateKeyPEM, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	block, _ := pem.Decode([]byte(kp.PublicKeyPEM))
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	if !ed25519.Verify(pubAny.(ed25519.PublicKey), msg, sig) {
		t.Fatal("signature did not verify against the generated public key")
	}
}

func TestMemoryKeyStore_StoreSignDelete(t *testing.T) {
	kp, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("GenerateAgentKey: %v", err)
	}
	ks := NewMemoryKeyStore()
	const agentID = "agt-123"

	if err := ks.Store(agentID, kp.PrivateKeyPEM); err != nil {
		t.Fatalf("store: %v", err)
	}
	msg := []byte("hello")
	sig, err := ks.Sign(agentID, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	block, _ := pem.Decode([]byte(kp.PublicKeyPEM))
	pubAny, _ := x509.ParsePKIXPublicKey(block.Bytes)
	if !ed25519.Verify(pubAny.(ed25519.PublicKey), msg, sig) {
		t.Fatal("keystore signature did not verify")
	}

	if err := ks.Delete(agentID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := ks.Sign(agentID, msg); err == nil {
		t.Fatal("expected an error signing after delete")
	}
}

func TestMemoryKeyStore_RejectsInvalidKey(t *testing.T) {
	ks := NewMemoryKeyStore()
	if err := ks.Store("agt", "not-a-pem"); err == nil {
		t.Fatal("expected an error storing an invalid key")
	}
}
