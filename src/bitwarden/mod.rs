//! Bitwarden Module
//!
//! This module provides integration with the Bitwarden password manager.
//! It handles authentication, vault synchronization, and credential retrieval.

pub mod auth;
pub mod client;
pub mod crypto;
pub mod types;
pub mod vault;

pub use client::BitwardenClient;
pub use types::{LoginItem, VaultData};
