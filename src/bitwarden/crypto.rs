//! Bitwarden Cryptography
//!
//! Implements the cryptographic operations required for Bitwarden:
//! - Master password hashing (Argon2id or PBKDF2)
//! - Key derivation (HKDF)
//! - Vault decryption (AES-256-GCM)

use crate::bitwarden::types::{KdfType, PreloginResponse};
use crate::error::Result;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hkdf::Hkdf;
use hmac::Mac;
use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Master key derived from password
#[derive(Clone)]
pub struct MasterKey(Zeroizing<Vec<u8>>);

/// Symmetric key for vault encryption
#[derive(Clone)]
pub struct SymmetricKey {
    pub key: Zeroizing<Vec<u8>>,
    pub mac_key: Zeroizing<Vec<u8>>,
}

impl MasterKey {
    /// Derive master key from password using the specified KDF
    pub fn derive(
        email: &str,
        password: &SecretString,
        kdf_params: &PreloginResponse,
    ) -> Result<Self> {
        let password_bytes = password.expose_secret().as_bytes();

        // Use salt from prelogin response, or fall back to email
        // The salt from prelogin is typically the email or base64-encoded
        let salt_bytes = if !kdf_params.salt.is_empty() {
            // Try base64 decoding first (for newer accounts)
            match BASE64.decode(&kdf_params.salt) {
                Ok(decoded) => {
                    tracing::debug!("Using base64-decoded salt ({} bytes)", decoded.len());
                    decoded
                }
                Err(_) => {
                    // Fall back to using salt as UTF-8 bytes (usually email)
                    tracing::debug!(
                        "Using salt as UTF-8 ({} bytes)",
                        kdf_params.salt.len()
                    );
                    kdf_params.salt.as_bytes().to_vec()
                }
            }
        } else {
            tracing::debug!("No salt in prelogin, using email as salt");
            email.to_lowercase().as_bytes().to_vec()
        };

        let master_key = match kdf_params.kdf_type {
            KdfType::Pbkdf2Sha256 => {
                let mut key = Zeroizing::new([0u8; 32]);
                tracing::debug!(
                    "PBKDF2-SHA256 with {} iterations, salt len={}",
                    kdf_params.kdf_iterations,
                    salt_bytes.len()
                );
                pbkdf2_hmac::<Sha256>(
                    password_bytes,
                    &salt_bytes,
                    kdf_params.kdf_iterations,
                    key.as_mut(),
                );
                key.to_vec()
            }
            KdfType::Argon2id => {
                let memory = kdf_params.kdf_memory.unwrap_or(64) * 1024; // Convert MB to KB
                let parallelism = kdf_params.kdf_parallelism.unwrap_or(4);
                let iterations = kdf_params.kdf_iterations;

                // For Argon2, the salt is SHA256 of the email/salt
                let mut hasher = Sha256::new();
                hasher.update(&salt_bytes);
                let argon_salt = hasher.finalize();

                tracing::debug!(
                    "Argon2id with mem={}, iter={}, parallel={}, salt hash len={}",
                    memory,
                    iterations,
                    parallelism,
                    argon_salt.len()
                );

                let params =
                    Params::new(memory, iterations, parallelism, Some(32)).map_err(|e| {
                        crate::error::BitwardenAutofillError::CryptoError(e.to_string())
                    })?;

                let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

                let mut key = Zeroizing::new([0u8; 32]);
                argon2
                    .hash_password_into(password_bytes, &argon_salt, key.as_mut())
                    .map_err(|e| {
                        crate::error::BitwardenAutofillError::CryptoError(e.to_string())
                    })?;

                key.to_vec()
            }
        };

        Ok(Self(Zeroizing::new(master_key)))
    }

    /// Expose the raw key bytes
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Get the master password hash for API authentication
    pub fn get_password_hash(&self, password: &SecretString) -> String {
        let mut key = Zeroizing::new([0u8; 32]);
        pbkdf2_hmac::<Sha256>(
            &self.0,
            password.expose_secret().as_bytes(),
            1,
            key.as_mut(),
        );
        BASE64.encode(*key)
    }

    /// Stretch the master key to get encryption and MAC keys
    /// Uses HKDF-Expand with info strings "enc" and "mac"
    pub fn stretch(&self) -> Result<SymmetricKey> {
        // The master key is already a valid PRK (from PBKDF2/Argon2)
        // so we use from_prk to skip the extract phase and only do expand
        let hk = Hkdf::<Sha256>::from_prk(&self.0)
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;

        let mut enc_key = Zeroizing::new([0u8; 32]);
        let mut mac_key = Zeroizing::new([0u8; 32]);

        hk.expand(b"enc", enc_key.as_mut())
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;
        hk.expand(b"mac", mac_key.as_mut())
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;

        Ok(SymmetricKey {
            key: Zeroizing::new(enc_key.to_vec()),
            mac_key: Zeroizing::new(mac_key.to_vec()),
        })
    }
}

impl SymmetricKey {
    /// Create a SymmetricKey from raw 64-byte key data
    /// The first 32 bytes are the encryption key, the last 32 bytes are the MAC key
    pub fn from_bytes(key_data: &[u8]) -> Result<Self> {
        if key_data.len() != 64 {
            return Err(crate::error::BitwardenAutofillError::CryptoError(
                format!("User key must be 64 bytes, got {}", key_data.len()),
            ));
        }

        Ok(Self {
            key: Zeroizing::new(key_data[..32].to_vec()),
            mac_key: Zeroizing::new(key_data[32..].to_vec()),
        })
    }

    /// Expose the encryption key bytes
    pub fn expose_secret(&self) -> &[u8] {
        &self.key
    }

    /// Decrypt a Bitwarden encrypted string to text
    /// Format: "2.iv|ciphertext|mac" (AES-256-CBC + HMAC-SHA256)
    /// Or: "3.nonce|ciphertext" (AES-256-GCM)
    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        let bytes = self.decrypt_to_bytes(encrypted)?;
        String::from_utf8(bytes)
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))
    }

    /// Decrypt a Bitwarden encrypted string to raw bytes
    /// Use this for binary data like encryption keys
    pub fn decrypt_to_bytes(&self, encrypted: &str) -> Result<Vec<u8>> {
        let parts: Vec<&str> = encrypted.split('.').collect();
        if parts.len() != 2 {
            return Err(crate::error::BitwardenAutofillError::CryptoError(
                "Invalid encrypted string format".to_string(),
            ));
        }

        let enc_type: u8 = parts[0].parse().map_err(|_| {
            crate::error::BitwardenAutofillError::CryptoError(
                "Invalid encryption type".to_string(),
            )
        })?;

        let data_parts: Vec<&str> = parts[1].split('|').collect();

        match enc_type {
            2 => {
                // AES-256-CBC + HMAC-SHA256 (legacy, still common)
                self.decrypt_aes_cbc_bytes(&data_parts)
            }
            3 => {
                // AES-256-GCM (newer)
                self.decrypt_aes_gcm_bytes(&data_parts)
            }
            _ => Err(crate::error::BitwardenAutofillError::CryptoError(
                format!("Unsupported encryption type: {}", enc_type),
            )),
        }
    }

    fn decrypt_aes_gcm_bytes(&self, parts: &[&str]) -> Result<Vec<u8>> {
        if parts.len() != 2 {
            return Err(crate::error::BitwardenAutofillError::CryptoError(
                "Invalid AES-GCM format".to_string(),
            ));
        }

        let nonce = BASE64
            .decode(parts[0])
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;
        let ciphertext = BASE64
            .decode(parts[1])
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;

        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;

        Ok(plaintext)
    }

    fn decrypt_aes_cbc_bytes(&self, parts: &[&str]) -> Result<Vec<u8>> {
        if parts.len() != 3 {
            return Err(crate::error::BitwardenAutofillError::CryptoError(
                "Invalid AES-CBC format".to_string(),
            ));
        }

        let iv = BASE64
            .decode(parts[0])
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;
        let ciphertext = BASE64
            .decode(parts[1])
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;
        let mac = BASE64
            .decode(parts[2])
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;

        // Verify MAC first
        type HmacSha256 = hmac::Hmac<Sha256>;
        let mut hmac_instance = <HmacSha256 as Mac>::new_from_slice(&self.mac_key)
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;
        hmac_instance.update(&iv);
        hmac_instance.update(&ciphertext);
        hmac_instance.verify_slice(&mac).map_err(|_| {
            crate::error::BitwardenAutofillError::CryptoError(
                "MAC verification failed".to_string(),
            )
        })?;

        // AES-CBC decryption
        use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

        let cipher = Aes256CbcDec::new_from_slices(&self.key, &iv)
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;

        let mut buffer = ciphertext.clone();
        let plaintext = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| crate::error::BitwardenAutofillError::CryptoError(e.to_string()))?;

        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_derivation() {
        // Test PBKDF2 key derivation
        let params = PreloginResponse {
            kdf_type: KdfType::Pbkdf2Sha256,
            kdf_iterations: 100000,
            kdf_memory: None,
            kdf_parallelism: None,
            kdf_settings: None,
            salt: String::new(),
        };

        let password = SecretString::from("testpassword");
        let result = MasterKey::derive("test@example.com", &password, &params);
        assert!(result.is_ok());
    }
}
