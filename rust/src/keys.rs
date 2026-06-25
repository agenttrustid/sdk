//! Client-side Ed25519 identity keys.
//!
//! The agent generates its own Ed25519 keypair locally. Only the PKIX/SPKI
//! **public** key (`-----BEGIN PUBLIC KEY-----`) is registered with the
//! platform; the PKCS#8 **private** key (`-----BEGIN PRIVATE KEY-----`) never
//! leaves the process. This is the wire contract shared by every AgentTrust ID
//! SDK and the server-side parser, so keys generated here interoperate with the
//! Go, Python, TypeScript and Java SDKs.
//!
//! # Example
//!
//! ```rust
//! use agenttrustid::keys::{generate_agent_key, InMemoryKeyStore, KeyStore};
//!
//! let kp = generate_agent_key().unwrap();
//! assert!(kp.public_key_pem.contains("BEGIN PUBLIC KEY"));
//!
//! let mut store = InMemoryKeyStore::new();
//! store.store("agent-123", &kp.private_key_pem).unwrap();
//! let sig = store.sign("agent-123", b"proof-of-possession challenge").unwrap();
//! assert_eq!(sig.len(), 64);
//! ```

use std::collections::HashMap;

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::spki::EncodePublicKey;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signer, SigningKey};

use crate::error::{AgentTrustError, Result};

/// A freshly generated Ed25519 identity keypair, PEM-encoded for the platform.
#[derive(Debug, Clone)]
pub struct AgentKeyPair {
    /// PKIX/SubjectPublicKeyInfo PEM (`-----BEGIN PUBLIC KEY-----`). Safe to
    /// register with the platform.
    pub public_key_pem: String,
    /// PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). Keep this secret — it is the
    /// agent's signing key and is never sent to the platform.
    pub private_key_pem: String,
}

fn crypto<E: std::fmt::Display>(e: E) -> AgentTrustError {
    AgentTrustError::Crypto {
        message: e.to_string(),
    }
}

/// Generate a new Ed25519 keypair locally using the OS CSPRNG.
///
/// The private key stays in this process; register only `public_key_pem`.
///
/// # Errors
///
/// Returns [`AgentTrustError::Crypto`] if PEM encoding fails.
pub fn generate_agent_key() -> Result<AgentKeyPair> {
    let signing = SigningKey::generate(&mut rand_core::OsRng);
    let private_key_pem = signing
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(crypto)?
        .to_string();
    let public_key_pem = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(crypto)?;
    Ok(AgentKeyPair {
        public_key_pem,
        private_key_pem,
    })
}

/// Sign `message` with a PKCS#8 PEM private key, returning the raw 64-byte
/// Ed25519 signature.
///
/// # Errors
///
/// Returns [`AgentTrustError::Crypto`] if the PEM cannot be parsed.
pub fn sign_with_private_key_pem(private_key_pem: &str, message: &[u8]) -> Result<Vec<u8>> {
    let signing = SigningKey::from_pkcs8_pem(private_key_pem).map_err(crypto)?;
    Ok(signing.sign(message).to_bytes().to_vec())
}

/// Parse a PKIX/SPKI public-key PEM into a verifying key (useful for verifying
/// proof-of-possession signatures locally).
///
/// # Errors
///
/// Returns [`AgentTrustError::Crypto`] if the PEM cannot be parsed.
pub fn parse_public_key(public_key_pem: &str) -> Result<ed25519_dalek::VerifyingKey> {
    use ed25519_dalek::pkcs8::spki::DecodePublicKey;
    ed25519_dalek::VerifyingKey::from_public_key_pem(public_key_pem).map_err(crypto)
}

/// Storage for an agent's private signing key.
///
/// Implementations decide where the PKCS#8 PEM lives. [`InMemoryKeyStore`] keeps
/// it in process memory; [`KeychainKeyStore`] delegates to an OS keychain.
pub trait KeyStore {
    /// Persist `private_key_pem` for `agent_id`. The PEM is validated first.
    fn store(&mut self, agent_id: &str, private_key_pem: &str) -> Result<()>;
    /// Sign `message` with the stored key for `agent_id`.
    fn sign(&self, agent_id: &str, message: &[u8]) -> Result<Vec<u8>>;
    /// Remove the stored key for `agent_id` (idempotent).
    fn delete(&mut self, agent_id: &str) -> Result<()>;
}

/// In-process key store backed by a `HashMap`. Keys are lost when the process
/// exits — use [`KeychainKeyStore`] for durable storage.
#[derive(Debug, Default)]
pub struct InMemoryKeyStore {
    keys: HashMap<String, String>,
}

impl InMemoryKeyStore {
    /// Create an empty in-memory key store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for InMemoryKeyStore {
    fn store(&mut self, agent_id: &str, private_key_pem: &str) -> Result<()> {
        // Validate the PEM before storing so bad input fails fast.
        SigningKey::from_pkcs8_pem(private_key_pem).map_err(crypto)?;
        self.keys
            .insert(agent_id.to_string(), private_key_pem.to_string());
        Ok(())
    }

    fn sign(&self, agent_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let pem = self
            .keys
            .get(agent_id)
            .ok_or_else(|| AgentTrustError::Crypto {
                message: format!("no key stored for agent {agent_id}"),
            })?;
        sign_with_private_key_pem(pem, message)
    }

    fn delete(&mut self, agent_id: &str) -> Result<()> {
        self.keys.remove(agent_id);
        Ok(())
    }
}

/// A secret-storage backend for [`KeychainKeyStore`].
///
/// The backend is injectable so the store can be unit-tested with an in-memory
/// fake; the real OS keychain implementation lives behind the `keychain`
/// feature ([`SystemKeychain`]).
pub trait KeychainBackend {
    /// Store `secret` under (`service`, `account`).
    fn set(&self, service: &str, account: &str, secret: &str) -> Result<()>;
    /// Retrieve the secret for (`service`, `account`).
    fn get(&self, service: &str, account: &str) -> Result<String>;
    /// Delete the secret for (`service`, `account`).
    fn delete(&self, service: &str, account: &str) -> Result<()>;
}

/// A [`KeyStore`] that persists keys in an OS keychain via a [`KeychainBackend`].
pub struct KeychainKeyStore<B: KeychainBackend> {
    backend: B,
    service: String,
}

impl<B: KeychainBackend> KeychainKeyStore<B> {
    /// Create a keychain-backed store using `service` as the keychain service
    /// name (agent IDs become accounts).
    pub fn new(backend: B, service: impl Into<String>) -> Self {
        Self {
            backend,
            service: service.into(),
        }
    }
}

impl<B: KeychainBackend> KeyStore for KeychainKeyStore<B> {
    fn store(&mut self, agent_id: &str, private_key_pem: &str) -> Result<()> {
        SigningKey::from_pkcs8_pem(private_key_pem).map_err(crypto)?;
        self.backend.set(&self.service, agent_id, private_key_pem)
    }

    fn sign(&self, agent_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let pem = self.backend.get(&self.service, agent_id)?;
        sign_with_private_key_pem(&pem, message)
    }

    fn delete(&mut self, agent_id: &str) -> Result<()> {
        self.backend.delete(&self.service, agent_id)
    }
}

/// Real OS-keychain backend (macOS Keychain, Windows Credential Manager, Linux
/// Secret Service) backed by the `keyring` crate. Compiled only with the
/// `keychain` feature so the SDK stays dependency-light by default.
#[cfg(feature = "keychain")]
pub struct SystemKeychain;

#[cfg(feature = "keychain")]
impl KeychainBackend for SystemKeychain {
    fn set(&self, service: &str, account: &str, secret: &str) -> Result<()> {
        keyring::Entry::new(service, account)
            .and_then(|e| e.set_password(secret))
            .map_err(crypto)
    }

    fn get(&self, service: &str, account: &str) -> Result<String> {
        keyring::Entry::new(service, account)
            .and_then(|e| e.get_password())
            .map_err(crypto)
    }

    fn delete(&self, service: &str, account: &str) -> Result<()> {
        keyring::Entry::new(service, account)
            .and_then(|e| e.delete_credential())
            .map_err(crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify(public_key_pem: &str, msg: &[u8], sig: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        let vk = parse_public_key(public_key_pem).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(sig).unwrap();
        vk.verify(msg, &signature).is_ok()
    }

    #[test]
    fn generates_server_compatible_pem() {
        let kp = generate_agent_key().unwrap();
        // The platform expects PKIX "PUBLIC KEY" and PKCS#8 "PRIVATE KEY" PEM.
        assert!(kp.public_key_pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(kp.private_key_pem.contains("-----BEGIN PRIVATE KEY-----"));
        // Each call produces a distinct key.
        let kp2 = generate_agent_key().unwrap();
        assert_ne!(kp.public_key_pem, kp2.public_key_pem);
        assert!(parse_public_key(&kp.public_key_pem).is_ok());
    }

    #[test]
    fn sign_verifies_against_public_key() {
        let kp = generate_agent_key().unwrap();
        let msg = b"proof-of-possession challenge";
        let sig = sign_with_private_key_pem(&kp.private_key_pem, msg).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify(&kp.public_key_pem, msg, &sig));
    }

    #[test]
    fn sign_rejects_invalid_pem() {
        let err = sign_with_private_key_pem("not-a-pem", b"x");
        assert!(matches!(err, Err(AgentTrustError::Crypto { .. })));
    }

    #[test]
    fn parse_public_key_rejects_garbage() {
        assert!(parse_public_key("nope").is_err());
    }

    #[test]
    fn in_memory_store_sign_delete() {
        let kp = generate_agent_key().unwrap();
        let mut store = InMemoryKeyStore::new();
        store.store("agt-1", &kp.private_key_pem).unwrap();

        let sig = store.sign("agt-1", b"hello").unwrap();
        assert!(verify(&kp.public_key_pem, b"hello", &sig));
        // Signing through the store matches signing the PEM directly.
        assert_eq!(
            sign_with_private_key_pem(&kp.private_key_pem, b"hello").unwrap(),
            sig
        );

        store.delete("agt-1").unwrap();
        assert!(store.sign("agt-1", b"hello").is_err());
    }

    #[test]
    fn in_memory_store_rejects_invalid_key() {
        let mut store = InMemoryKeyStore::new();
        assert!(matches!(
            store.store("agt", "not-a-pem"),
            Err(AgentTrustError::Crypto { .. })
        ));
    }

    #[test]
    fn keychain_store_uses_injected_backend() {
        use std::cell::RefCell;

        #[derive(Default)]
        struct FakeBackend {
            map: RefCell<HashMap<String, String>>,
        }
        impl KeychainBackend for FakeBackend {
            fn set(&self, service: &str, account: &str, secret: &str) -> Result<()> {
                self.map
                    .borrow_mut()
                    .insert(format!("{service}:{account}"), secret.to_string());
                Ok(())
            }
            fn get(&self, service: &str, account: &str) -> Result<String> {
                self.map
                    .borrow()
                    .get(&format!("{service}:{account}"))
                    .cloned()
                    .ok_or_else(|| AgentTrustError::Crypto {
                        message: "not found".to_string(),
                    })
            }
            fn delete(&self, service: &str, account: &str) -> Result<()> {
                self.map
                    .borrow_mut()
                    .remove(&format!("{service}:{account}"));
                Ok(())
            }
        }

        let kp = generate_agent_key().unwrap();
        let mut store = KeychainKeyStore::new(FakeBackend::default(), "agenttrust-id");
        store.store("agt-1", &kp.private_key_pem).unwrap();

        let sig = store.sign("agt-1", b"hello").unwrap();
        assert!(verify(&kp.public_key_pem, b"hello", &sig));

        store.delete("agt-1").unwrap();
        assert!(store.sign("agt-1", b"hello").is_err());
    }
}
