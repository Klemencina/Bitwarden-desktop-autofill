//! Bitwarden Client
//!
//! High-level client for interacting with Bitwarden.
//! Handles the complete flow: authentication, sync, and credential retrieval.

use crate::bitwarden::auth::{self, DeviceInfo, LoginResult};
use crate::bitwarden::crypto::{MasterKey, SymmetricKey};
use crate::bitwarden::types::{
    LoginItem, LoginResponse, SyncResponse, TwoFactorProvider, VaultData,
};
use crate::bitwarden::vault;
use crate::error::{BitwardenAutofillError, Result};

use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// State of the Bitwarden client
#[derive(Debug, Clone, PartialEq)]
pub enum ClientState {
    /// Not logged in
    LoggedOut,
    /// Awaiting 2FA code
    AwaitingTwoFactor(Vec<TwoFactorProvider>),
    /// Logged in and vault is unlocked
    Unlocked,
}

/// High-level Bitwarden client
pub struct BitwardenClient {
    http_client: Client,
    _identity_url: String,
    api_url: String,
    device: DeviceInfo,

    // Authentication state
    email: Option<String>,
    master_key: Option<MasterKey>,
    password: Option<SecretString>,
    access_token: Option<SecretString>,
    _refresh_token: Option<SecretString>,
    user_key: Option<SymmetricKey>,

    // Vault data
    vault: Arc<RwLock<VaultData>>,

    // State
    state: ClientState,
}

/// Bitwarden Server Region
#[derive(Debug, Clone)]
pub enum ServerRegion {
    US,
    EU,
    SelfHosted { identity: String, api: String },
}

impl BitwardenClient {
    /// Create a new Bitwarden client
    pub fn new() -> Self {
        Self {
            http_client: Client::builder()
                .user_agent("Bitwarden_Desktop/2024.12.0")
                .build()
                .unwrap_or_else(|err| {
                    warn!(
                        "Failed to build HTTP client with custom user agent: {}",
                        err
                    );
                    Client::new()
                }),
            _identity_url: "https://identity.bitwarden.com".to_string(),
            api_url: "https://api.bitwarden.com".to_string(),
            device: DeviceInfo::default(),
            email: None,
            master_key: None,
            password: None,
            access_token: None,
            _refresh_token: None,
            user_key: None,
            vault: Arc::new(RwLock::new(VaultData::new())),
            state: ClientState::LoggedOut,
        }
    }

    /// Get current client state
    pub fn state(&self) -> &ClientState {
        &self.state
    }

    /// Set the server region
    pub fn set_server(&mut self, region: ServerRegion) {
        match region {
            ServerRegion::US => {
                self._identity_url = "https://identity.bitwarden.com".to_string();
                self.api_url = "https://api.bitwarden.com".to_string();
            }
            ServerRegion::EU => {
                self._identity_url = "https://identity.bitwarden.eu".to_string();
                self.api_url = "https://api.bitwarden.eu".to_string();
            }
            ServerRegion::SelfHosted { identity, api } => {
                self._identity_url = identity;
                self.api_url = api;
            }
        }
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, ClientState::Unlocked)
    }

    /// Get the current server region based on API URL
    pub fn get_server_region(&self) -> ServerRegion {
        if self.api_url.contains("bitwarden.eu") {
            ServerRegion::EU
        } else if self.api_url.contains("bitwarden.com") {
            ServerRegion::US
        } else {
            ServerRegion::SelfHosted {
                identity: self._identity_url.clone(),
                api: self.api_url.clone(),
            }
        }
    }

    /// Login with email and password
    pub async fn login(&mut self, email: &str, password: SecretString) -> Result<()> {
        info!("Starting login");

        // Step 1: Pre-login to get KDF parameters
        let prelogin = auth::prelogin(&self.http_client, &self._identity_url, email).await?;

        // Step 2: Derive master key from password
        let master_key = MasterKey::derive(email, &password, &prelogin)?;

        // Step 3: Attempt login
        let result = auth::login(
            &self.http_client,
            &self._identity_url,
            email,
            &master_key,
            &password,
            &self.device,
        )
        .await?;

        // Store email, password (for 2FA), and master key
        self.email = Some(email.to_string());
        self.password = Some(password);
        self.master_key = Some(master_key);

        match result {
            LoginResult::Success(login_resp) => {
                self.complete_login(login_resp).await?;
            }
            LoginResult::TwoFactorRequired(providers) => {
                info!("2FA required, providers: {:?}", providers);
                self.state = ClientState::AwaitingTwoFactor(providers);
            }
        }

        Ok(())
    }

    /// Complete 2FA login
    pub async fn submit_2fa(&mut self, provider: TwoFactorProvider, code: &str) -> Result<()> {
        if !matches!(self.state, ClientState::AwaitingTwoFactor(_)) {
            return Err(BitwardenAutofillError::InvalidState(
                "Not awaiting 2FA".to_string(),
            ));
        }

        let email = self
            .email
            .as_ref()
            .ok_or_else(|| BitwardenAutofillError::InvalidState("No email".to_string()))?;
        let master_key = self
            .master_key
            .as_ref()
            .ok_or_else(|| BitwardenAutofillError::InvalidState("No master key".to_string()))?;
        let password = self
            .password
            .as_ref()
            .ok_or_else(|| BitwardenAutofillError::InvalidState("No password".to_string()))?;

        let login_resp = auth::login_2fa(
            &self.http_client,
            &self._identity_url,
            email,
            master_key,
            password,
            &self.device,
            provider,
            code,
        )
        .await?;

        self.complete_login(login_resp).await
    }

    /// Complete the login process after successful authentication
    async fn complete_login(&mut self, login_resp: LoginResponse) -> Result<()> {
        // Store tokens
        self.access_token = Some(SecretString::from(login_resp.access_token));
        if let Some(refresh) = login_resp.refresh_token {
            self._refresh_token = Some(SecretString::from(refresh));
        }

        // Derive user key from master key and encrypted key
        if let Some(encrypted_key) = &login_resp.key {
            let master_key = self.master_key.as_ref().ok_or_else(|| {
                BitwardenAutofillError::InvalidState("No master key".to_string())
            })?;

            // Step 1: Stretch the master key to get enc/mac keys for decrypting the user key
            let stretched_key = master_key.stretch()?;

            // Step 2: Decrypt the protected symmetric key to get the 64-byte user key
            let user_key_data = stretched_key.decrypt_to_bytes(encrypted_key)?;

            info!("Decrypted user key: {} bytes", user_key_data.len());

            // Step 3: Parse the 64-byte key into enc_key (32) + mac_key (32)
            let user_key = SymmetricKey::from_bytes(&user_key_data)?;

            self.user_key = Some(user_key);
        }

        self.state = ClientState::Unlocked;

        // Clear password from memory
        self.password = None;

        info!("Login completed, vault unlocked");

        // Auto-sync vault
        self.sync().await?;

        Ok(())
    }

    /// Sync vault data from server
    pub async fn sync(&mut self) -> Result<()> {
        if !self.is_unlocked() {
            return Err(BitwardenAutofillError::VaultLocked);
        }

        let access_token = self
            .access_token
            .as_ref()
            .ok_or(BitwardenAutofillError::VaultLocked)?;
        let user_key = self
            .user_key
            .as_ref()
            .ok_or(BitwardenAutofillError::VaultLocked)?;

        info!("Syncing vault...");

        let response = self
            .http_client
            .get(format!("{}/sync", self.api_url))
            .bearer_auth(access_token.expose_secret())
            .query(&[("excludeDomains", "true")])
            .send()
            .await
            .map_err(|e| BitwardenAutofillError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(BitwardenAutofillError::ApiError(format!(
                "Sync failed: {} - {}",
                status, body
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| BitwardenAutofillError::NetworkError(e.to_string()))?;

        let sync_resp: SyncResponse = serde_json::from_str(&body).map_err(|e| {
            BitwardenAutofillError::ApiError(format!("Sync response parse error: {}", e))
        })?;

        // Parse and decrypt ciphers
        let vault_data = vault::parse_sync_response(&sync_resp, user_key)?;

        let mut vault = self.vault.write().await;
        *vault = vault_data;

        info!("Vault synced, {} items", vault.logins.len());

        Ok(())
    }

    /// Search for login items matching a query
    pub async fn search(&self, query: &str) -> Vec<LoginItem> {
        let vault = self.vault.read().await;
        vault.search(query).into_iter().cloned().collect()
    }

    /// Get all login items
    pub async fn get_logins(&self) -> Vec<LoginItem> {
        let vault = self.vault.read().await;
        vault.logins.clone()
    }

    /// Login with API Key (client_credentials grant)
    ///
    /// This is an alternative login method that uses a Bitwarden Personal API Key
    /// instead of the standard password-based authentication.
    pub async fn login_api_key(
        &mut self,
        email: &str,
        password: SecretString,
        client_id: &str,
        client_secret: &str,
    ) -> Result<()> {
        info!("Starting API Key login");

        // Step 1: Pre-login to get KDF parameters (still needed for vault decryption)
        let prelogin = auth::prelogin(&self.http_client, &self._identity_url, email).await?;

        // Step 2: Derive master key from password (needed for vault decryption)
        let master_key = MasterKey::derive(email, &password, &prelogin)?;

        // Step 3: Authenticate with API Key
        let login_resp = auth::login_client_credentials(
            &self.http_client,
            &self._identity_url,
            client_id,
            client_secret,
            &self.device,
        )
        .await?;

        // Store state
        self.email = Some(email.to_string());
        self.master_key = Some(master_key);

        // Complete the login process
        self.complete_login(login_resp).await?;

        Ok(())
    }

    /// Logout and clear all sensitive data
    pub fn logout(&mut self) {
        info!("Logging out");

        self.email = None;
        self.master_key = None;
        self.password = None;
        self.access_token = None;
        self._refresh_token = None;
        self.user_key = None;
        self.state = ClientState::LoggedOut;

        // Clear vault (but keep the Arc for shared access)
        if let Ok(mut vault) = self.vault.try_write() {
            *vault = VaultData::new();
        }
    }
}

impl Default for BitwardenClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = BitwardenClient::new();
        assert_eq!(client.state(), &ClientState::LoggedOut);
        assert!(!client.is_unlocked());
    }
}
