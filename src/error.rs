//! Error Types for Bitwarden Desktop Autofill
//!
//! Comprehensive error handling for all operations.

use thiserror::Error;

/// Result type alias using our error type
pub type Result<T> = std::result::Result<T, BitwardenAutofillError>;

/// Main error type for the application
#[derive(Error, Debug)]
pub enum BitwardenAutofillError {
    // ===== Bitwarden API Errors =====
    /// Network/HTTP request failed
    #[error("Network error: {0}")]
    NetworkError(String),

    /// API returned an error response
    #[error("API error: {0}")]
    ApiError(String),

    /// Authentication failed (wrong password, etc.)
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Two-factor authentication required
    #[error("Two-factor authentication required")]
    TwoFactorRequired,

    /// Vault is locked
    #[error("Vault is locked - please unlock first")]
    VaultLocked,

    /// Invalid client state for operation
    #[error("Invalid state: {0}")]
    InvalidState(String),

    // ===== Cryptography Errors =====
    /// Cryptographic operation failed
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),

    // ===== UI Automation Errors =====
    /// UI Automation initialization failed
    #[error("UI Automation initialization failed: {0}")]
    UIAutomationInitFailed(String),

    /// No focused element found
    #[error("No focused element found")]
    NoFocusedElement,

    /// Failed to get element property
    #[error("Failed to get element property: {0}")]
    ElementPropertyError(String),

    // ===== Input Injection Errors =====
    /// Failed to inject keystrokes
    #[error("Failed to inject keystrokes: {0}")]
    InputInjectionFailed(String),

    // ===== Credential Errors =====
    /// No matching credentials found
    #[error("No credentials found for: {0}")]
    NoCredentialsFound(String),

    /// Multiple credentials found, selection required
    #[error("Multiple credentials found, selection required")]
    MultipleCredentialsFound,

    // ===== System Tray Errors =====
    /// System tray initialization failed
    #[error("System tray error: {0}")]
    TrayError(String),

    // ===== Password Dialog Errors =====
    /// Password dialog was cancelled
    #[error("Password dialog cancelled")]
    PasswordDialogCancelled,

    /// Password dialog failed
    #[error("Password dialog failed: {0}")]
    PasswordDialogFailed(String),

    // ===== I/O Errors =====
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    // ===== Keyring Errors =====
    /// Keyring/credential storage error
    #[error("Keyring error: {0}")]
    KeyringError(String),
}

impl BitwardenAutofillError {
    /// Check if this error requires the user to unlock the vault
    pub fn requires_unlock(&self) -> bool {
        matches!(self, BitwardenAutofillError::VaultLocked)
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            BitwardenAutofillError::NoCredentialsFound(_)
                | BitwardenAutofillError::MultipleCredentialsFound
                | BitwardenAutofillError::PasswordDialogCancelled
        )
    }
}

