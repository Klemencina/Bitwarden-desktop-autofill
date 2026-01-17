//! Bitwarden Authentication
//!
//! Handles the authentication flow with Bitwarden servers:
//! - Pre-login to get KDF parameters
//! - Password-based login
//! - Two-factor authentication
//! - Token refresh

use crate::bitwarden::crypto::MasterKey;
use crate::bitwarden::types::{LoginResponse, PreloginResponse, TwoFactorProvider};
use crate::error::{BitwardenAutofillError, Result};
use reqwest::Client;
use secrecy::SecretString;
use serde::Serialize;
use tracing::{debug, info};

/// Bitwarden API endpoints (default: Bitwarden Cloud)
pub const IDENTITY_URL: &str = "https://identity.bitwarden.com";
pub const API_URL: &str = "https://api.bitwarden.com";

/// Device information for API requests
#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    #[serde(rename = "deviceType")]
    pub device_type: u8,
    #[serde(rename = "deviceIdentifier")]
    pub device_identifier: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self {
            device_type: 6, // WindowsDesktop = 6 per Bitwarden DeviceType enum
            device_identifier: uuid::Uuid::new_v4().to_string(),
            device_name: "Bitwarden Desktop Autofill".to_string(),
        }
    }
}

/// Pre-login request to get KDF parameters
pub async fn prelogin(
    client: &Client,
    identity_url: &str,
    email: &str,
) -> Result<PreloginResponse> {
    debug!("Performing pre-login");

    #[derive(Serialize)]
    struct PreloginRequest<'a> {
        email: &'a str,
    }

    let response = client
        .post(format!("{}/accounts/prelogin", identity_url))
        .json(&PreloginRequest { email })
        .send()
        .await
        .map_err(|e| BitwardenAutofillError::NetworkError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(BitwardenAutofillError::ApiError(format!(
            "Pre-login failed: {} - {}",
            status, body
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| BitwardenAutofillError::NetworkError(e.to_string()))?;

    let mut prelogin: PreloginResponse = serde_json::from_str(&body).map_err(|e| {
        BitwardenAutofillError::ApiError(format!("Invalid prelogin response: {}", e))
    })?;

    // Trim null characters from salt
    prelogin.salt = prelogin.salt.trim_matches('\0').to_string();

    info!(
        "Pre-login successful, KDF: {:?}, iterations: {}",
        prelogin.kdf_type, prelogin.kdf_iterations
    );

    Ok(prelogin)
}

/// Perform password-based login
pub async fn login(
    client: &Client,
    identity_url: &str,
    email: &str,
    master_key: &MasterKey,
    password: &SecretString,
    device: &DeviceInfo,
) -> Result<LoginResult> {
    debug!("Attempting login");

    let password_hash = master_key.get_password_hash(password);

    let device_type_str = device.device_type.to_string();
    let params = [
        ("grant_type", "password"),
        ("username", email),
        ("password", password_hash.as_str()),
        ("scope", "api offline_access"),
        ("client_id", "cli"),
        ("deviceType", device_type_str.as_str()),
        ("deviceIdentifier", device.device_identifier.as_str()),
        ("deviceName", device.device_name.as_str()),
    ];

    debug!(
        "Login request prepared (client_id={}, deviceType={})",
        params[4].1, params[5].1
    );

    let response = client
        .post(format!("{}/connect/token", identity_url))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .map_err(|e| BitwardenAutofillError::NetworkError(e.to_string()))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| BitwardenAutofillError::ApiError(e.to_string()))?;

    if status.is_success() {
        let login_resp: LoginResponse = serde_json::from_str(&body).map_err(|e| {
            BitwardenAutofillError::ApiError(format!("Invalid login response: {}", e))
        })?;

        info!("Login successful");
        Ok(LoginResult::Success(login_resp))
    } else if status.as_u16() == 400 {
        debug!("Login returned 400 status");
        // Check if 2FA is required
        // Try parsing error response which might contain TwoFactorProviders
        if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(providers) = json_body.get("TwoFactorProviders") {
                let providers: Vec<TwoFactorProvider> =
                    serde_json::from_value(providers.clone()).unwrap_or_default();
                info!("Two-factor authentication required");
                return Ok(LoginResult::TwoFactorRequired(providers));
            }

            if let Some(error) = json_body.get("error").and_then(|v| v.as_str()) {
                let desc = json_body
                    .get("error_description")
                    .and_then(|v| v.as_str())
                    .unwrap_or(error);
                return Err(BitwardenAutofillError::AuthenticationFailed(
                    desc.to_string(),
                ));
            }

            let error_msg = json_body
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");

            return Err(BitwardenAutofillError::AuthenticationFailed(
                error_msg.to_string(),
            ));
        }

        Err(BitwardenAutofillError::AuthenticationFailed(format!(
            "Bad Request: {}",
            body
        )))
    } else {
        Err(BitwardenAutofillError::ApiError(format!(
            "Login failed: {} - {}",
            status, body
        )))
    }
}

/// Login with two-factor authentication
pub async fn login_2fa(
    client: &Client,
    identity_url: &str,
    email: &str,
    master_key: &MasterKey,
    password: &SecretString,
    device: &DeviceInfo,
    provider: TwoFactorProvider,
    code: &str,
) -> Result<LoginResponse> {
    debug!("Attempting 2FA login");

    let password_hash = master_key.get_password_hash(password);

    let params = [
        ("grant_type", "password"),
        ("username", email),
        ("password", &password_hash),
        ("scope", "api offline_access"),
        ("client_id", "cli"),
        ("deviceType", &device.device_type.to_string()),
        ("deviceIdentifier", &device.device_identifier),
        ("deviceName", &device.device_name),
        ("twoFactorProvider", &(provider as u8).to_string()),
        ("twoFactorToken", code),
        ("twoFactorRemember", "1"),
    ];

    let response = client
        .post(format!("{}/connect/token", identity_url))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .map_err(|e| BitwardenAutofillError::NetworkError(e.to_string()))?;

    if response.status().is_success() {
        let login_resp: LoginResponse = response
            .json()
            .await
            .map_err(|e| BitwardenAutofillError::ApiError(e.to_string()))?;

        info!("2FA login successful");
        Ok(login_resp)
    } else {
        let body = response.text().await.unwrap_or_default();
        Err(BitwardenAutofillError::AuthenticationFailed(format!(
            "2FA login failed: {}",
            body
        )))
    }
}

/// Login with API Key (client_credentials)
///
/// Note: For Personal API Keys, device parameters are NOT required and
/// including them can cause `invalid_request` errors.
pub async fn login_client_credentials(
    client: &Client,
    identity_url: &str,
    client_id: &str,
    client_secret: &str,
    device: &DeviceInfo,
) -> Result<LoginResponse> {
    debug!("Attempting API Key login (client_credentials)");

    // Try with device parameters - some Bitwarden endpoints may require them
    let device_type_str = device.device_type.to_string();
    let params = [
        ("grant_type", "client_credentials"),
        ("scope", "api"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("deviceType", device_type_str.as_str()),
        ("deviceIdentifier", device.device_identifier.as_str()),
        ("deviceName", device.device_name.as_str()),
    ];

    let url = format!("{}/connect/token", identity_url);
    debug!(
        "API Key request prepared (grant_type=client_credentials, scope=api, deviceType={})",
        device.device_type
    );

    let response = client
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .map_err(|e| BitwardenAutofillError::NetworkError(e.to_string()))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| BitwardenAutofillError::ApiError(e.to_string()))?;

    if status.is_success() {
        let login_resp: LoginResponse = serde_json::from_str(&body).map_err(|e| {
            BitwardenAutofillError::ApiError(format!("Invalid login response: {}", e))
        })?;

        info!("API Key Login successful");
        Ok(login_resp)
    } else {
        Err(BitwardenAutofillError::AuthenticationFailed(format!(
            "API Key Login failed: {}",
            status
        )))
    }
}

/// Result of a login attempt
#[derive(Debug)]
pub enum LoginResult {
    Success(LoginResponse),
    TwoFactorRequired(Vec<TwoFactorProvider>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_info_default() {
        let device = DeviceInfo::default();
        assert_eq!(device.device_type, 6);
        assert!(!device.device_identifier.is_empty());
    }
}
