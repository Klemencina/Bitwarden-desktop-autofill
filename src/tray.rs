//! System Tray Module
//!
//! This module provides system tray functionality with a status icon and context menu.
//! The icon reflects the current vault lock state.

use crate::error::{BitwardenAutofillError, Result};
use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

#[cfg(target_os = "windows")]
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

/// Menu item IDs for tray menu actions
pub mod menu_ids {
    pub const UNLOCK: &str = "unlock";
    pub const LOCK: &str = "lock";
    pub const SYNC: &str = "sync";
    pub const SETTINGS: &str = "settings";
    pub const QUIT: &str = "quit";
}

/// Represents the current state of the vault for tray display
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Locked,
    Unlocked,
    Syncing,
}

/// Actions that can be triggered from the tray menu
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    Unlock,
    Lock,
    Sync,
    OpenSettings,
    Quit,
    Unknown(String),
}

impl From<&str> for TrayAction {
    fn from(id: &str) -> Self {
        match id {
            menu_ids::UNLOCK => TrayAction::Unlock,
            menu_ids::LOCK => TrayAction::Lock,
            menu_ids::SYNC => TrayAction::Sync,
            menu_ids::SETTINGS => TrayAction::OpenSettings,
            menu_ids::QUIT => TrayAction::Quit,
            other => TrayAction::Unknown(other.to_string()),
        }
    }
}

/// System tray manager for VisionVault
pub struct TrayManager {
    #[cfg(target_os = "windows")]
    tray_icon: Option<TrayIcon>,
    menu: Menu,
    unlock_item: MenuItem,
    lock_item: MenuItem,
    sync_item: MenuItem,
    is_unlocked: Arc<AtomicBool>,
}

impl TrayManager {
    /// Create a new tray manager
    pub fn new() -> Result<Self> {
        info!("Initializing system tray");

        // Create menu items
        let unlock_item = MenuItem::with_id(
            menu_ids::UNLOCK,
            "Unlock Vault",
            true, // enabled
            None, // no accelerator
        );

        let lock_item = MenuItem::with_id(
            menu_ids::LOCK,
            "Lock Vault",
            false, // disabled initially (vault starts locked)
            None,
        );

        let sync_item = MenuItem::with_id(
            menu_ids::SYNC,
            "Sync Vault",
            false, // disabled until unlocked
            None,
        );

        let settings_item = MenuItem::with_id(menu_ids::SETTINGS, "Settings...", true, None);

        let quit_item = MenuItem::with_id(menu_ids::QUIT, "Quit", true, None);

        // Build the menu
        let menu = Menu::new();
        menu.append(&unlock_item).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to add menu item: {}", e))
        })?;
        menu.append(&lock_item).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to add menu item: {}", e))
        })?;
        menu.append(&sync_item).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to add menu item: {}", e))
        })?;
        menu.append(&PredefinedMenuItem::separator()).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to add separator: {}", e))
        })?;
        menu.append(&settings_item).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to add menu item: {}", e))
        })?;
        menu.append(&PredefinedMenuItem::separator()).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to add separator: {}", e))
        })?;
        menu.append(&quit_item).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to add menu item: {}", e))
        })?;

        Ok(Self {
            #[cfg(target_os = "windows")]
            tray_icon: None,
            menu,
            unlock_item,
            lock_item,
            sync_item,
            is_unlocked: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Initialize and show the tray icon
    #[cfg(target_os = "windows")]
    pub fn show(&mut self) -> Result<()> {
        let icon = self.create_locked_icon()?;

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(self.menu.clone()))
            .with_tooltip("Bitwarden - Locked")
            .with_icon(icon)
            .build()
            .map_err(|e| BitwardenAutofillError::TrayError(e.to_string()))?;

        self.tray_icon = Some(tray);
        info!("System tray icon created");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn show(&mut self) -> Result<()> {
        Err(BitwardenAutofillError::TrayError(
            "System tray is only supported on Windows".to_string(),
        ))
    }

    /// Update the tray to reflect vault state
    pub fn set_vault_state(&mut self, state: VaultState) -> Result<()> {
        debug!("Setting vault state to {:?}", state);

        let (unlock_enabled, lock_enabled, sync_enabled, tooltip) = match state {
            VaultState::Locked => {
                self.is_unlocked.store(false, Ordering::SeqCst);
                (true, false, false, "Bitwarden - Locked")
            }
            VaultState::Unlocked => {
                self.is_unlocked.store(true, Ordering::SeqCst);
                (
                    false,
                    true,
                    true,
                    "Bitwarden - Unlocked (Ctrl+Alt+P to autofill)",
                )
            }
            VaultState::Syncing => (false, false, false, "Bitwarden - Syncing..."),
        };

        // Update menu item states
        self.unlock_item.set_enabled(unlock_enabled);
        self.lock_item.set_enabled(lock_enabled);
        self.sync_item.set_enabled(sync_enabled);

        // Update tray icon and tooltip
        #[cfg(target_os = "windows")]
        if let Some(ref tray) = self.tray_icon {
            tray.set_tooltip(Some(tooltip))
                .map_err(|e| BitwardenAutofillError::TrayError(e.to_string()))?;

            let icon = match state {
                VaultState::Locked => self.create_locked_icon()?,
                VaultState::Unlocked => self.create_unlocked_icon()?,
                VaultState::Syncing => self.create_syncing_icon()?,
            };
            tray.set_icon(Some(icon))
                .map_err(|e| BitwardenAutofillError::TrayError(e.to_string()))?;
        }

        Ok(())
    }

    /// Check if the vault is currently unlocked (based on tray state)
    pub fn is_unlocked(&self) -> bool {
        self.is_unlocked.load(Ordering::SeqCst)
    }

    /// Process a menu event and return the corresponding action
    pub fn handle_menu_event(event: &MenuEvent) -> TrayAction {
        TrayAction::from(event.id.0.as_str())
    }

    /// Create an icon for the locked state (red/gray)
    #[cfg(target_os = "windows")]
    fn create_locked_icon(&self) -> Result<Icon> {
        // Create a simple 32x32 icon programmatically
        // Red color for locked state
        let size = 32u32;
        let mut rgba = vec![0u8; (size * size * 4) as usize];

        // Draw a simple lock icon (filled circle with lock shape)
        for y in 0..size {
            for x in 0..size {
                let idx = ((y * size + x) * 4) as usize;
                let cx = (x as f32) - 16.0;
                let cy = (y as f32) - 16.0;
                let dist = (cx * cx + cy * cy).sqrt();

                if dist < 14.0 {
                    // Red color for locked
                    rgba[idx] = 220; // R
                    rgba[idx + 1] = 53; // G
                    rgba[idx + 2] = 69; // B
                    rgba[idx + 3] = 255; // A
                } else if dist < 16.0 {
                    // Border
                    rgba[idx] = 150;
                    rgba[idx + 1] = 30;
                    rgba[idx + 2] = 40;
                    rgba[idx + 3] = 255;
                }
            }
        }

        Icon::from_rgba(rgba, size, size).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to create icon: {}", e))
        })
    }

    /// Create an icon for the unlocked state (green)
    #[cfg(target_os = "windows")]
    fn create_unlocked_icon(&self) -> Result<Icon> {
        let size = 32u32;
        let mut rgba = vec![0u8; (size * size * 4) as usize];

        for y in 0..size {
            for x in 0..size {
                let idx = ((y * size + x) * 4) as usize;
                let cx = (x as f32) - 16.0;
                let cy = (y as f32) - 16.0;
                let dist = (cx * cx + cy * cy).sqrt();

                if dist < 14.0 {
                    // Green color for unlocked
                    rgba[idx] = 40; // R
                    rgba[idx + 1] = 167; // G
                    rgba[idx + 2] = 69; // B
                    rgba[idx + 3] = 255; // A
                } else if dist < 16.0 {
                    // Border
                    rgba[idx] = 30;
                    rgba[idx + 1] = 120;
                    rgba[idx + 2] = 50;
                    rgba[idx + 3] = 255;
                }
            }
        }

        Icon::from_rgba(rgba, size, size).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to create icon: {}", e))
        })
    }

    /// Create an icon for the syncing state (yellow/orange)
    #[cfg(target_os = "windows")]
    fn create_syncing_icon(&self) -> Result<Icon> {
        let size = 32u32;
        let mut rgba = vec![0u8; (size * size * 4) as usize];

        for y in 0..size {
            for x in 0..size {
                let idx = ((y * size + x) * 4) as usize;
                let cx = (x as f32) - 16.0;
                let cy = (y as f32) - 16.0;
                let dist = (cx * cx + cy * cy).sqrt();

                if dist < 14.0 {
                    // Orange/yellow color for syncing
                    rgba[idx] = 255; // R
                    rgba[idx + 1] = 193; // G
                    rgba[idx + 2] = 7; // B
                    rgba[idx + 3] = 255; // A
                } else if dist < 16.0 {
                    // Border
                    rgba[idx] = 200;
                    rgba[idx + 1] = 150;
                    rgba[idx + 2] = 5;
                    rgba[idx + 3] = 255;
                }
            }
        }

        Icon::from_rgba(rgba, size, size).map_err(|e| {
            BitwardenAutofillError::TrayError(format!("Failed to create icon: {}", e))
        })
    }
}

impl Drop for TrayManager {
    fn drop(&mut self) {
        debug!("Cleaning up tray manager");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tray_action_from_str() {
        assert_eq!(TrayAction::from(menu_ids::UNLOCK), TrayAction::Unlock);
        assert_eq!(TrayAction::from(menu_ids::QUIT), TrayAction::Quit);
        assert_eq!(
            TrayAction::from("unknown"),
            TrayAction::Unknown("unknown".to_string())
        );
    }
}
