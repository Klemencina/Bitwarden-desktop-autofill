//! Application configuration storage

use crate::error::{BitwardenAutofillError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub hotkey: HotkeyConfig,
    #[serde(default = "default_start_with_windows")]
    pub start_with_windows: bool,
}

fn default_start_with_windows() -> bool {
    true // Default to starting with Windows
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotkeyConfig {
    pub modifiers: Vec<String>, // "ctrl", "alt", "shift", "win"
    pub key: String,            // "P", "B", etc.
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            hotkey: HotkeyConfig {
                modifiers: vec!["ctrl".to_string(), "alt".to_string()],
                key: "P".to_string(),
            },
            start_with_windows: true,
        }
    }
}

impl Default for HotkeyConfig {
    fn default() -> Self {
        Self {
            modifiers: vec!["ctrl".to_string(), "alt".to_string()],
            key: "P".to_string(),
        }
    }
}

impl HotkeyConfig {
    pub fn display_string(&self) -> String {
        let mut parts = Vec::new();
        for m in &self.modifiers {
            match m.as_str() {
                "ctrl" => parts.push("Ctrl"),
                "alt" => parts.push("Alt"),
                "shift" => parts.push("Shift"),
                "win" => parts.push("Win"),
                _ => {}
            }
        }
        parts.push(&self.key);
        parts.join("+")
    }
}

fn config_path() -> Result<PathBuf> {
    let app_data = std::env::var("APPDATA")
        .map_err(|_| BitwardenAutofillError::KeyringError("APPDATA not found".to_string()))?;
    let config_dir = PathBuf::from(app_data).join("bitwarden-desktop-autofill");
    
    // Create directory if it doesn't exist
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir)
            .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))?;
    }
    
    Ok(config_dir.join("config.json"))
}

pub fn load_config() -> Result<AppConfig> {
    let path = config_path()?;
    
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    
    let content = fs::read_to_string(&path)
        .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))?;
    
    serde_json::from_str(&content)
        .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))
}

pub fn save_config(config: &AppConfig) -> Result<()> {
    let path = config_path()?;
    
    let content = serde_json::to_string_pretty(config)
        .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))?;
    
    fs::write(&path, content)
        .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))
}

/// Available keys for hotkey binding
pub const AVAILABLE_KEYS: &[&str] = &[
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
    "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
];

const STARTUP_REGISTRY_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const STARTUP_VALUE_NAME: &str = "BitwardenDesktopAutofill";

/// Check if the app is set to start with Windows
pub fn is_startup_enabled() -> bool {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER, KEY_READ, REG_SZ,
    };
    use windows::core::PCWSTR;
    
    let key_path: Vec<u16> = STARTUP_REGISTRY_KEY.encode_utf16().chain(std::iter::once(0)).collect();
    let value_name: Vec<u16> = STARTUP_VALUE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(key_path.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );
        
        if result.is_err() {
            return false;
        }
        
        let mut data_type = REG_SZ;
        let mut data_size: u32 = 0;
        
        let result = RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(value_name.as_ptr()),
            None,
            Some(&mut data_type),
            None,
            Some(&mut data_size),
        );
        
        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
        
        result.is_ok() && data_size > 0
    }
}

/// Enable or disable starting with Windows
pub fn set_startup_enabled(enabled: bool) -> Result<()> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegSetValueExW, RegDeleteValueW, HKEY_CURRENT_USER, KEY_WRITE, REG_SZ,
    };
    use windows::core::PCWSTR;
    
    let key_path: Vec<u16> = STARTUP_REGISTRY_KEY.encode_utf16().chain(std::iter::once(0)).collect();
    let value_name: Vec<u16> = STARTUP_VALUE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(key_path.as_ptr()),
            0,
            KEY_WRITE,
            &mut hkey,
        );
        
        if result.is_err() {
            return Err(BitwardenAutofillError::KeyringError(
                "Failed to open registry key".to_string(),
            ));
        }
        
        let final_result = if enabled {
            // Get the path to the current executable
            let exe_path = std::env::current_exe()
                .map_err(|e| BitwardenAutofillError::KeyringError(e.to_string()))?;
            let exe_path_str = exe_path.to_string_lossy();
            let exe_path_wide: Vec<u16> = exe_path_str.encode_utf16().chain(std::iter::once(0)).collect();
            
            RegSetValueExW(
                hkey,
                PCWSTR::from_raw(value_name.as_ptr()),
                0,
                REG_SZ,
                Some(&exe_path_wide.iter().flat_map(|&c| c.to_le_bytes()).collect::<Vec<u8>>()),
            )
        } else {
            RegDeleteValueW(hkey, PCWSTR::from_raw(value_name.as_ptr()))
        };
        
        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
        
        if final_result.is_err() {
            return Err(BitwardenAutofillError::KeyringError(
                format!("Failed to {} startup entry", if enabled { "set" } else { "delete" }),
            ));
        }
        
        Ok(())
    }
}

/// Sync the startup registry with the config setting
pub fn sync_startup_setting() -> Result<()> {
    let config = load_config()?;
    let is_enabled = is_startup_enabled();
    
    if config.start_with_windows != is_enabled {
        set_startup_enabled(config.start_with_windows)?;
    }
    
    Ok(())
}
