package agenttrust

import (
	"fmt"

	"github.com/zalando/go-keyring"
)

// keychainService is the service name under which agent keys are stored in the
// OS keychain.
const keychainService = "agenttrust-id"

// KeychainKeyStore stores agent private keys in the operating system's native
// secret store: macOS Keychain, Windows Credential Manager, or the Linux Secret
// Service (libsecret/gnome-keyring). Keys are persisted by the OS and protected
// by the user's login session.
//
// Requires the go-keyring dependency; run `go mod tidy` after adding this file.
type KeychainKeyStore struct {
	service string
}

// NewKeychainKeyStore returns a KeyStore backed by the OS keychain.
func NewKeychainKeyStore() *KeychainKeyStore {
	return &KeychainKeyStore{service: keychainService}
}

// Store implements KeyStore.
func (k *KeychainKeyStore) Store(agentID, privateKeyPEM string) error {
	if agentID == "" {
		return fmt.Errorf("agentID is required")
	}
	if _, err := parsePrivateKeyPEM(privateKeyPEM); err != nil {
		return err
	}
	if err := keyring.Set(k.service, agentID, privateKeyPEM); err != nil {
		return fmt.Errorf("store key in keychain: %w", err)
	}
	return nil
}

// Sign implements KeyStore.
func (k *KeychainKeyStore) Sign(agentID string, data []byte) ([]byte, error) {
	privateKeyPEM, err := keyring.Get(k.service, agentID)
	if err != nil {
		return nil, fmt.Errorf("load key from keychain: %w", err)
	}
	return SignWithPrivateKeyPEM(privateKeyPEM, data)
}

// Delete implements KeyStore.
func (k *KeychainKeyStore) Delete(agentID string) error {
	if err := keyring.Delete(k.service, agentID); err != nil {
		return fmt.Errorf("delete key from keychain: %w", err)
	}
	return nil
}
