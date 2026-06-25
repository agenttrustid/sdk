package agenttrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
)

// AgentKeyPair is an Ed25519 identity keypair, PEM-encoded to match the platform:
// a PKIX ("PUBLIC KEY") SubjectPublicKeyInfo public half and a PKCS#8
// ("PRIVATE KEY") private half. Only PublicKeyPEM is ever sent to the platform;
// the private key stays on the agent.
type AgentKeyPair struct {
	PublicKeyPEM  string
	PrivateKeyPEM string
}

// GenerateAgentKey creates a new Ed25519 identity keypair for an agent. Register
// PublicKeyPEM with the platform (CreateAgentRequest.PublicKey) and keep
// PrivateKeyPEM on the agent — ideally in a KeyStore.
func GenerateAgentKey() (AgentKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return AgentKeyPair{}, fmt.Errorf("generate ed25519 key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return AgentKeyPair{}, fmt.Errorf("marshal public key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return AgentKeyPair{}, fmt.Errorf("marshal private key: %w", err)
	}
	return AgentKeyPair{
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})),
	}, nil
}

// parsePrivateKeyPEM decodes a PKCS#8 PEM-encoded Ed25519 private key.
func parsePrivateKeyPEM(privateKeyPEM string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("invalid private key PEM: no block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return ed, nil
}

// SignWithPrivateKeyPEM signs data with a PKCS#8 PEM-encoded Ed25519 private key.
// Used by KeyStore backends and by the proof-of-possession / DPoP flows.
func SignWithPrivateKeyPEM(privateKeyPEM string, data []byte) ([]byte, error) {
	key, err := parsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, data), nil
}

// KeyStore persists an agent's private key and signs with it. Native backends
// (OS keychain, TPM, KMS) can keep the key non-exportable: callers sign through
// the store rather than handling raw key material.
type KeyStore interface {
	// Store persists the PEM-encoded private key under the agent ID.
	Store(agentID, privateKeyPEM string) error
	// Sign returns an Ed25519 signature over data using the stored key.
	Sign(agentID string, data []byte) ([]byte, error)
	// Delete removes the stored key for the agent ID.
	Delete(agentID string) error
}

// MemoryKeyStore keeps private keys in process memory. Intended for tests and
// ephemeral agents; use a native backend (KeychainKeyStore) for persistence.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]string
}

// NewMemoryKeyStore creates an empty in-memory key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{keys: make(map[string]string)}
}

// Store implements KeyStore.
func (m *MemoryKeyStore) Store(agentID, privateKeyPEM string) error {
	if agentID == "" {
		return errors.New("agentID is required")
	}
	if _, err := parsePrivateKeyPEM(privateKeyPEM); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[agentID] = privateKeyPEM
	return nil
}

// Sign implements KeyStore.
func (m *MemoryKeyStore) Sign(agentID string, data []byte) ([]byte, error) {
	m.mu.RLock()
	privateKeyPEM, ok := m.keys[agentID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no key stored for agent %q", agentID)
	}
	return SignWithPrivateKeyPEM(privateKeyPEM, data)
}

// Delete implements KeyStore.
func (m *MemoryKeyStore) Delete(agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, agentID)
	return nil
}
