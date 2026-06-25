package agenttrust

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/zalando/go-keyring"
)

// keyring.MockInit() swaps the OS keychain for an in-memory mock so the native
// backend can be exercised in CI without a real Secret Service / Keychain.

func TestKeychainKeyStore_StoreSignDelete(t *testing.T) {
	keyring.MockInit()

	kp, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("GenerateAgentKey: %v", err)
	}
	ks := NewKeychainKeyStore()
	const agentID = "agt-keychain"

	if err := ks.Store(agentID, kp.PrivateKeyPEM); err != nil {
		t.Fatalf("store: %v", err)
	}
	sig, err := ks.Sign(agentID, []byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	block, _ := pem.Decode([]byte(kp.PublicKeyPEM))
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	if !ed25519.Verify(pubAny.(ed25519.PublicKey), []byte("hello"), sig) {
		t.Fatal("keychain signature did not verify")
	}

	if err := ks.Delete(agentID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := ks.Sign(agentID, []byte("hello")); err == nil {
		t.Fatal("expected an error signing after delete")
	}
}

func TestKeychainKeyStore_RejectsInvalidKey(t *testing.T) {
	keyring.MockInit()
	ks := NewKeychainKeyStore()
	if err := ks.Store("agt", "not-a-pem"); err == nil {
		t.Fatal("expected an error storing an invalid key")
	}
}
