//! Vault Management
//!
//! Parses and decrypts vault data from Bitwarden sync responses.

use crate::bitwarden::crypto::SymmetricKey;
use crate::bitwarden::types::{
    CipherResponse, LoginItem, LoginUri, SyncResponse, UriMatchType, VaultData,
};
use crate::error::{BitwardenAutofillError, Result};
use secrecy::SecretString;
use tracing::{debug, warn};

/// Cipher types from Bitwarden
const CIPHER_TYPE_LOGIN: u8 = 1;

/// Parse a sync response into vault data
pub fn parse_sync_response(sync: &SyncResponse, key: &SymmetricKey) -> Result<VaultData> {
    let mut logins = Vec::new();

    for cipher in &sync.ciphers {
        // Only process login items
        if cipher.cipher_type != CIPHER_TYPE_LOGIN {
            continue;
        }

        match parse_login_cipher(cipher, key) {
            Ok(login) => logins.push(login),
            Err(e) => {
                warn!("Failed to decrypt cipher {}: {}", cipher.id, e);
                // Continue processing other items
            }
        }
    }

    debug!("Parsed {} login items from sync response", logins.len());

    Ok(VaultData {
        logins,
        last_sync: chrono::Utc::now(),
    })
}

/// Parse a single login cipher
fn parse_login_cipher(cipher: &CipherResponse, key: &SymmetricKey) -> Result<LoginItem> {
    let name = decrypt_optional(&cipher.name, key)?.unwrap_or_else(|| "(No name)".to_string());

    let login_data = cipher.login.as_ref().ok_or_else(|| {
        BitwardenAutofillError::CryptoError("Login cipher missing login data".to_string())
    })?;

    let username = match &login_data.username {
        Some(u) if !u.is_empty() => decrypt_optional(u, key)?,
        _ => None,
    };

    let password = match &login_data.password {
        Some(p) if !p.is_empty() => decrypt_optional(p, key)?.map(SecretString::from),
        _ => None,
    };

    let uris = match &login_data.uris {
        Some(uris) => parse_uris(uris, key),
        None => Vec::new(),
    };

    let notes = match &cipher.notes {
        Some(n) if !n.is_empty() => decrypt_optional(n, key)?,
        _ => None,
    };

    Ok(LoginItem {
        id: cipher.id,
        name,
        username,
        password,
        uris,
        notes,
        folder_id: cipher.folder_id,
        favorite: cipher.favorite,
    })
}

/// Parse login URIs
fn parse_uris(uris: &[crate::bitwarden::types::UriResponse], key: &SymmetricKey) -> Vec<LoginUri> {
    uris.iter()
        .map(|uri| {
            let decrypted_uri = uri
                .uri
                .as_ref()
                .and_then(|u| decrypt_optional(u, key).ok().flatten());

            LoginUri {
                uri: decrypted_uri,
                r#match: uri.r#match.map(|m| match m {
                    0 => UriMatchType::Domain,
                    1 => UriMatchType::Host,
                    2 => UriMatchType::StartsWith,
                    3 => UriMatchType::Exact,
                    4 => UriMatchType::RegularExpression,
                    5 => UriMatchType::Never,
                    _ => UriMatchType::Domain,
                }),
            }
        })
        .collect()
}

/// Decrypt an optional encrypted string
fn decrypt_optional(encrypted: &str, key: &SymmetricKey) -> Result<Option<String>> {
    if encrypted.is_empty() {
        return Ok(None);
    }

    // Check if it's an encrypted string (starts with type number and dot)
    if encrypted
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
        && encrypted.contains('.')
    {
        match key.decrypt(encrypted) {
            Ok(decrypted) => Ok(Some(decrypted)),
            Err(e) => {
                debug!("Failed to decrypt: {}", e);
                Ok(None)
            }
        }
    } else {
        // Not encrypted, return as-is
        Ok(Some(encrypted.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    #[test]
    fn test_parse_empty_sync() {
        let sync = SyncResponse {
            ciphers: Vec::new(),
            folders: Vec::new(),
            profile: crate::bitwarden::types::ProfileResponse {
                id: Uuid::new_v4(),
                email: "test@example.com".to_string(),
                name: None,
                key: None,
                private_key: None,
            },
        };

        // Create a dummy key for testing
        let key = SymmetricKey {
            key: Zeroizing::new(vec![0u8; 32]),
            mac_key: Zeroizing::new(vec![0u8; 32]),
        };

        let result = parse_sync_response(&sync, &key);
        assert!(result.is_ok());
        assert!(result.unwrap().logins.is_empty());
    }
}
