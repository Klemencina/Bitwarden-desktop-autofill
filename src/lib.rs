//! Bitwarden Desktop Autofill
//!
//! A Windows desktop autofill tool that integrates with Bitwarden to automatically
//! fill credentials in native Windows applications using Microsoft UI Automation.
//!
//! ## Features
//! - Global hotkey (Ctrl+Alt+P) to trigger autofill
//! - Detects password fields using Windows UI Automation
//! - Fuzzy matches window titles to vault entries
//! - Types credentials securely (no clipboard)
//!
//! ## Architecture
//! - `bitwarden` - Bitwarden API client, authentication, vault management
//! - `ui_automation` - Windows UI Automation for field detection
//! - `input_injector` - SendInput for secure typing
//! - `tray` - System tray integration

pub mod bitwarden;
pub mod config;
pub mod credentials_store;
pub mod error;
pub mod input_injector;
pub mod native_ui;
pub mod tray;
pub mod ui_automation;

pub use error::{BitwardenAutofillError, Result};
