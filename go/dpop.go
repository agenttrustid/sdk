package agenttrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// MintDPoPProof builds an RFC 9449 DPoP proof JWT (EdDSA), signed with the
// agent's Ed25519 private key, for a single request. The proof binds the HTTP
// method (htm), the request URL (htu — scheme+host+path, no query/fragment),
// and, when accessToken is non-empty, the access-token hash (ath). The platform
// verifies the proof signature against the embedded JWK and checks that the
// key's thumbprint matches the access token's RFC 7800 cnf.jkt.
//
// The proof is minted manually (no JWT dependency), producing the exact JOSE
// shape the platform expects:
//
//	header:  {"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":...}}
//	payload: {"htm","htu","iat","jti","ath"?}
func MintDPoPProof(privateKeyPEM, method, url, accessToken string) (string, error) {
	priv, err := parsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return "", err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("private key is not Ed25519")
	}
	return buildDPoPProof(pub, func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil }, method, url, accessToken)
}

// MintDPoPProofWithKeyStore mints a DPoP proof by signing through a KeyStore, so
// the private key can stay non-exportable (OS keychain / TPM / KMS). Only the
// agent's public key (publicKeyPEM) is handled in the clear, to populate the
// embedded JWK. This is the primitive the auto-managed runtime auth uses.
func MintDPoPProofWithKeyStore(ks KeyStore, agentID, publicKeyPEM, method, url, accessToken string) (string, error) {
	if ks == nil {
		return "", fmt.Errorf("a KeyStore is required")
	}
	pub, err := parsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return "", err
	}
	return buildDPoPProof(pub, func(b []byte) ([]byte, error) { return ks.Sign(agentID, b) }, method, url, accessToken)
}

// buildDPoPProof assembles and signs the compact DPoP JWT. pub is embedded in
// the JWK header; sign produces the Ed25519 signature over the JWS signing input.
func buildDPoPProof(pub ed25519.PublicKey, sign func([]byte) ([]byte, error), method, url, accessToken string) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key")
	}
	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "EdDSA",
		"jwk": map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
		},
	}

	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	payload := map[string]interface{}{
		"htm": method,
		"htu": url,
		"iat": time.Now().Unix(),
		"jti": hex.EncodeToString(jti),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		payload["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}

	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("sign DPoP proof: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// parsePublicKeyPEM decodes a PKIX PEM-encoded Ed25519 public key.
func parsePublicKeyPEM(publicKeyPEM string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}
	return ed, nil
}
