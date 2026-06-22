//! RFC 9449 DPoP proof minting.
//!
//! Produces the exact JOSE shape the platform verifies, signed with the agent's
//! Ed25519 key (reusing the SDK's `ed25519-dalek` keys and the same base64url
//! encoding as proof-of-possession):
//!
//! ```text
//! header:  {"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":...}}
//! payload: {"htm","htu","iat","jti","ath"?}
//! ```
//!
//! The platform verifies the signature against the embedded JWK and checks the
//! key's thumbprint against the access token's RFC 7800 `cnf.jkt`.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{AgentTrustError, Result};
use crate::keys::{parse_public_key, sign_with_private_key_pem, KeyStore};
use crate::wimse::base64url_no_pad;

#[derive(Serialize)]
struct Jwk {
    kty: &'static str,
    crv: &'static str,
    x: String,
}

#[derive(Serialize)]
struct Header<'a> {
    typ: &'static str,
    alg: &'static str,
    jwk: &'a Jwk,
}

#[derive(Serialize)]
struct Payload {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

fn jwk_from_verifying_key(vk: &VerifyingKey) -> Jwk {
    Jwk {
        kty: "OKP",
        crv: "Ed25519",
        x: base64url_no_pad(vk.as_bytes()),
    }
}

fn build_proof(
    jwk: &Jwk,
    sign: impl Fn(&[u8]) -> Result<Vec<u8>>,
    method: &str,
    url: &str,
    access_token: &str,
) -> Result<String> {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let ath = if access_token.is_empty() {
        None
    } else {
        let mut h = Sha256::new();
        h.update(access_token.as_bytes());
        let digest = h.finalize();
        Some(base64url_no_pad(digest.as_slice()))
    };

    let header = Header {
        typ: "dpop+jwt",
        alg: "EdDSA",
        jwk,
    };
    let payload = Payload {
        htm: method.to_string(),
        htu: url.to_string(),
        iat,
        jti: Uuid::new_v4().to_string(),
        ath,
    };

    let header_json = serde_json::to_vec(&header)?;
    let payload_json = serde_json::to_vec(&payload)?;
    let signing_input = format!(
        "{}.{}",
        base64url_no_pad(&header_json),
        base64url_no_pad(&payload_json)
    );
    let sig = sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", base64url_no_pad(&sig)))
}

/// Mint a DPoP proof signed with the agent's Ed25519 private key (PKCS#8 PEM).
///
/// # Errors
///
/// Returns [`AgentTrustError::Crypto`] if the private key PEM cannot be parsed.
pub fn mint_dpop_proof(
    private_key_pem: &str,
    method: &str,
    url: &str,
    access_token: &str,
) -> Result<String> {
    let signing = SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
        AgentTrustError::Crypto {
            message: e.to_string(),
        }
    })?;
    let jwk = jwk_from_verifying_key(&signing.verifying_key());
    build_proof(
        &jwk,
        |m| sign_with_private_key_pem(private_key_pem, m),
        method,
        url,
        access_token,
    )
}

/// Mint a DPoP proof signing through a [`KeyStore`], so the private key stays
/// non-exportable; only the public key (PKIX PEM) is handled in the clear.
///
/// # Errors
///
/// Returns [`AgentTrustError::Crypto`] if the public key PEM cannot be parsed or
/// the key store cannot sign.
pub fn mint_dpop_proof_with_key_store(
    key_store: &dyn KeyStore,
    agent_id: &str,
    public_key_pem: &str,
    method: &str,
    url: &str,
    access_token: &str,
) -> Result<String> {
    let vk = parse_public_key(public_key_pem)?;
    let jwk = jwk_from_verifying_key(&vk);
    build_proof(
        &jwk,
        |m| key_store.sign(agent_id, m),
        method,
        url,
        access_token,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_agent_key, parse_public_key, InMemoryKeyStore, KeyStore};
    use ed25519_dalek::Verifier;

    const CHECK_URL: &str = "https://api.agenttrust.id/api/v1/agenttrust/check";

    fn b64url_decode(s: &str) -> Vec<u8> {
        // Minimal base64url (no pad) decoder for tests.
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut lut = [255u8; 256];
        for (i, &c) in ALPHABET.iter().enumerate() {
            lut[c as usize] = i as u8;
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
        for chunk in bytes.chunks(4) {
            let mut n = 0u32;
            let mut bits = 0;
            for &c in chunk {
                n = (n << 6) | lut[c as usize] as u32;
                bits += 6;
            }
            // Drop the leftover low bits that don't form a full byte.
            let nbytes = bits / 8;
            n >>= bits % 8;
            let be = n.to_be_bytes();
            out.extend_from_slice(&be[4 - nbytes..]);
        }
        out
    }

    fn parts(proof: &str) -> (serde_json::Value, serde_json::Value, String, Vec<u8>) {
        let segs: Vec<&str> = proof.split('.').collect();
        let header = serde_json::from_slice(&b64url_decode(segs[0])).unwrap();
        let payload = serde_json::from_slice(&b64url_decode(segs[1])).unwrap();
        let signing_input = format!("{}.{}", segs[0], segs[1]);
        let sig = b64url_decode(segs[2]);
        (header, payload, signing_input, sig)
    }

    fn verify(proof: &str, public_key_pem: &str) -> bool {
        let (_, _, signing_input, sig) = parts(proof);
        let vk = parse_public_key(public_key_pem).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        vk.verify(signing_input.as_bytes(), &signature).is_ok()
    }

    #[test]
    fn mints_verifiable_proof_with_expected_claims() {
        let kp = generate_agent_key().unwrap();
        let proof = mint_dpop_proof(&kp.private_key_pem, "POST", CHECK_URL, "access-tok").unwrap();
        let (header, payload, _, _) = parts(&proof);

        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["jwk"]["kty"], "OKP");
        assert_eq!(header["jwk"]["crv"], "Ed25519");
        assert!(header["jwk"]["x"].is_string());

        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["htu"], CHECK_URL);
        assert!(payload["iat"].is_number());
        assert!(payload["jti"].is_string());

        let mut h = Sha256::new();
        h.update(b"access-tok");
        let digest = h.finalize();
        assert_eq!(payload["ath"], base64url_no_pad(digest.as_slice()));

        assert!(verify(&proof, &kp.public_key_pem));
    }

    #[test]
    fn omits_ath_without_access_token() {
        let kp = generate_agent_key().unwrap();
        let proof = mint_dpop_proof(&kp.private_key_pem, "GET", "https://x/y", "").unwrap();
        let (_, payload, _, _) = parts(&proof);
        assert!(payload.get("ath").is_none());
    }

    #[test]
    fn mints_unique_jti_per_call() {
        let kp = generate_agent_key().unwrap();
        let (_, a, _, _) = parts(&mint_dpop_proof(&kp.private_key_pem, "POST", CHECK_URL, "t").unwrap());
        let (_, b, _, _) = parts(&mint_dpop_proof(&kp.private_key_pem, "POST", CHECK_URL, "t").unwrap());
        assert_ne!(a["jti"], b["jti"]);
    }

    #[test]
    fn key_store_variant_verifies() {
        let kp = generate_agent_key().unwrap();
        let mut ks = InMemoryKeyStore::new();
        ks.store("agent-1", &kp.private_key_pem).unwrap();
        let proof = mint_dpop_proof_with_key_store(
            &ks,
            "agent-1",
            &kp.public_key_pem,
            "POST",
            CHECK_URL,
            "tok",
        )
        .unwrap();
        assert!(verify(&proof, &kp.public_key_pem));
    }

    #[test]
    fn rejects_invalid_private_key() {
        assert!(matches!(
            mint_dpop_proof("not-a-pem", "POST", CHECK_URL, ""),
            Err(AgentTrustError::Crypto { .. })
        ));
    }
}
