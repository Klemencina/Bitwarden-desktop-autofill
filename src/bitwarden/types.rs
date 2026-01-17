//! Bitwarden Data Types
//!
//! Data structures for Bitwarden API responses and vault items.

use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

/// A login item from the Bitwarden vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginItem {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    #[serde(skip_serializing)]
    pub password: Option<SecretString>,
    pub uris: Vec<LoginUri>,
    pub notes: Option<String>,
    pub folder_id: Option<Uuid>,
    pub favorite: bool,
}

/// URI associated with a login item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginUri {
    pub uri: Option<String>,
    pub r#match: Option<UriMatchType>,
}

/// URI matching types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

/// Complete vault data after sync
#[derive(Debug, Clone)]
pub struct VaultData {
    pub logins: Vec<LoginItem>,
    pub last_sync: chrono::DateTime<chrono::Utc>,
}

impl VaultData {
    pub fn new() -> Self {
        Self {
            logins: Vec::new(),
            last_sync: chrono::Utc::now(),
        }
    }

    /// Search for logins matching a query
    pub fn search(&self, query: &str) -> Vec<&LoginItem> {
        let query_lower = query.to_lowercase();
        self.logins
            .iter()
            .filter(|login| {
                login.name.to_lowercase().contains(&query_lower)
                    || login.uris.iter().any(|uri| {
                        uri.uri
                            .as_ref()
                            .map(|u| u.to_lowercase().contains(&query_lower))
                            .unwrap_or(false)
                    })
            })
            .collect()
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// API Response Types
// ============================================================================

/// Pre-login response with KDF parameters
#[derive(Debug, Clone, Deserialize)]
pub struct PreloginResponse {
    #[serde(rename = "kdf")]
    pub kdf_type: KdfType,
    #[serde(rename = "kdfIterations")]
    pub kdf_iterations: u32,
    #[serde(rename = "kdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(rename = "kdfParallelism")]
    pub kdf_parallelism: Option<u32>,
    #[serde(rename = "kdfSettings")]
    pub kdf_settings: Option<KdfSettings>,
    #[serde(rename = "salt", default)]
    pub salt: String,
}

/// KDF settings from prelogin response
#[derive(Debug, Clone, Deserialize)]
pub struct KdfSettings {
    #[serde(rename = "kdfType")]
    pub kdf_type: KdfType,
    #[serde(rename = "iterations")]
    pub iterations: u32,
    #[serde(rename = "memory")]
    pub memory: Option<u32>,
    #[serde(rename = "parallelism")]
    pub parallelism: Option<u32>,
}

/// KDF algorithm types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KdfType {
    Pbkdf2Sha256 = 0,
    Argon2id = 1,
}

impl<'de> Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            0 => Ok(KdfType::Pbkdf2Sha256),
            1 => Ok(KdfType::Argon2id),
            v => Err(serde::de::Error::custom(format!("unknown KDF type {}", v))),
        }
    }
}

/// Login response from identity server
#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub token_type: String,
    #[serde(rename = "Key")]
    pub key: Option<String>,
    #[serde(rename = "PrivateKey")]
    pub private_key: Option<String>,
    #[serde(rename = "TwoFactorToken")]
    pub two_factor_token: Option<String>,
}

/// Two-factor authentication requirement
#[derive(Debug, Clone, Deserialize)]
pub struct TwoFactorRequired {
    #[serde(rename = "TwoFactorProviders")]
    pub providers: Vec<TwoFactorProvider>,
}

/// Two-factor provider types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TwoFactorProvider {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl<'de> Deserialize<'de> for TwoFactorProvider {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            0 => Ok(TwoFactorProvider::Authenticator),
            1 => Ok(TwoFactorProvider::Email),
            2 => Ok(TwoFactorProvider::Duo),
            3 => Ok(TwoFactorProvider::YubiKey),
            4 => Ok(TwoFactorProvider::U2f),
            5 => Ok(TwoFactorProvider::Remember),
            6 => Ok(TwoFactorProvider::OrganizationDuo),
            7 => Ok(TwoFactorProvider::WebAuthn),
            v => Err(serde::de::Error::custom(format!(
                "unknown 2FA provider {}",
                v
            ))),
        }
    }
}

/// Sync response containing vault data
#[derive(Debug, Clone, Deserialize)]
pub struct SyncResponse {
    #[serde(alias = "Ciphers", alias = "ciphers", default)]
    pub ciphers: Vec<CipherResponse>,
    #[serde(alias = "Folders", alias = "folders", default)]
    pub folders: Vec<FolderResponse>,
    #[serde(alias = "Profile", alias = "profile")]
    pub profile: ProfileResponse,
}

/// Encrypted cipher (vault item) from API
#[derive(Debug, Clone, Deserialize)]
pub struct CipherResponse {
    #[serde(alias = "Id", alias = "id")]
    pub id: Uuid,
    #[serde(alias = "Type", alias = "type")]
    pub cipher_type: u8,
    #[serde(alias = "Name", alias = "name")]
    pub name: String,
    #[serde(alias = "Login", alias = "login")]
    pub login: Option<LoginResponse2>,
    #[serde(alias = "FolderId", alias = "folderId")]
    pub folder_id: Option<Uuid>,
    #[serde(alias = "Favorite", alias = "favorite", default)]
    pub favorite: bool,
    #[serde(alias = "Notes", alias = "notes")]
    pub notes: Option<String>,
}

/// Login data within a cipher
#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse2 {
    #[serde(alias = "Username", alias = "username")]
    pub username: Option<String>,
    #[serde(alias = "Password", alias = "password")]
    pub password: Option<String>,
    #[serde(alias = "Uris", alias = "uris")]
    pub uris: Option<Vec<UriResponse>>,
    #[serde(alias = "Totp", alias = "totp")]
    pub totp: Option<String>,
}

/// URI in login response
#[derive(Debug, Clone, Deserialize)]
pub struct UriResponse {
    #[serde(alias = "Uri", alias = "uri")]
    pub uri: Option<String>,
    #[serde(alias = "Match", alias = "match")]
    pub r#match: Option<u8>,
}

/// Folder response
#[derive(Debug, Clone, Deserialize)]
pub struct FolderResponse {
    #[serde(alias = "Id", alias = "id")]
    pub id: Uuid,
    #[serde(alias = "Name", alias = "name")]
    pub name: String,
}

/// User profile response
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileResponse {
    #[serde(alias = "Id", alias = "id")]
    pub id: Uuid,
    #[serde(alias = "Email", alias = "email")]
    pub email: String,
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Key", alias = "key")]
    pub key: Option<String>,
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
}
