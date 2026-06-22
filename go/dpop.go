package agenttrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
// The proof is minted manually (no JWT dependency) to keep the SDK lightweight,
// producing the exact JOSE shape the platform expects:
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
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
