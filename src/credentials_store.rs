//! Windows Credential Manager storage

use crate::bitwarden::client::ServerRegion;
use crate::error::{BitwardenAutofillError, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

const KEYRING_SERVICE: &str = "bitwarden-desktop-autofill";
const KEYRING_USERNAME: &str = "login";

#[derive(Debug, Clone)]
pub struct SavedLogin {
    pub server: ServerRegion,
    pub email: String,
    pub client_id: String,
    pub client_secret: SecretString,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StoredServerRegion {
    Us,
    Eu,
    SelfHosted { identity: String, api: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredLogin {
    server: StoredServerRegion,
    email: String,
    client_id: String,
    client_secret: String,
}

impl From<&ServerRegion> for StoredServerRegion {
    fn from(region: &ServerRegion) -> Self {
        match region {
            ServerRegion::US => StoredServerRegion::Us,
            ServerRegion::EU => StoredServerRegion::Eu,
            ServerRegion::SelfHosted { identity, api } => StoredServerRegion::SelfHosted {
                identity: identity.clone(),
                api: api.clone(),
            },
        }
    }
}

impl From<StoredServerRegion> for ServerRegion {
    fn from(region: StoredServerRegion) -> Self {
        match region {
            StoredServerRegion::Us => ServerRegion::US,
            StoredServerRegion::Eu => ServerRegion::EU,
            StoredServerRegion::SelfHosted { identity, api } => {
                ServerRegion::SelfHosted { identity, api }
            }
        }
    }
}

impl From<&SavedLogin> for StoredLogin {
    fn from(saved: &SavedLogin) -> Self {
        Self {
            server: StoredServerRegion::from(&saved.server),
            email: saved.email.clone(),
            client_id: saved.client_id.clone(),
            client_secret: saved.client_secret.expose_secret().to_string(),
        }
    }
}

impl From<StoredLogin> for SavedLogin {
    fn from(stored: StoredLogin) -> Self {
        Self {
            server: stored.server.into(),
            email: stored.email,
            client_id: stored.client_id,
            client_secret: SecretString::new(stored.client_secret.into()),
        }
    }
}

fn keyring_entry() -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)
        .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))
}

pub fn load_saved_login() -> Result<Option<SavedLogin>> {
    let entry = keyring_entry()?;
    match entry.get_password() {
        Ok(payload) => {
            let stored: StoredLogin = serde_json::from_str(&payload)
                .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))?;
            Ok(Some(stored.into()))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(BitwardenAutofillError::KeyringError(e.to_string())),
    }
}

pub fn save_login(login: &SavedLogin) -> Result<()> {
    let entry = keyring_entry()?;
    let payload = serde_json::to_string(&StoredLogin::from(login))
        .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))?;
    entry
        .set_password(&payload)
        .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))
}

pub fn clear_login() -> Result<()> {
    let entry = keyring_entry()?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(BitwardenAutofillError::KeyringError(e.to_string())),
    }
}
