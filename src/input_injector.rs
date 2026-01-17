//! Input Injection Module
//!
//! This module provides secure keystroke injection using Windows SendInput API.
//! It avoids using the clipboard to prevent exposure to clipboard history loggers.

use crate::error::{BitwardenAutofillError, Result};
use secrecy::{ExposeSecret, SecretString};
use std::thread;
use std::time::Duration;
use tracing::{debug, error};

#[cfg(target_os = "windows")]
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    VIRTUAL_KEY, VK_CONTROL, VK_MENU, VK_SHIFT,
};

/// Delay between keystrokes in milliseconds
const KEYSTROKE_DELAY_MS: u64 = 5;

/// Input injector that uses SendInput for secure typing
pub struct InputInjector {
    /// Delay between keystrokes
    keystroke_delay: Duration,
}

impl InputInjector {
    /// Create a new input injector with default settings
    pub fn new() -> Self {
        Self {
            keystroke_delay: Duration::from_millis(KEYSTROKE_DELAY_MS),
        }
    }

    /// Create an input injector with a custom keystroke delay
    pub fn with_delay(delay_ms: u64) -> Self {
        Self {
            keystroke_delay: Duration::from_millis(delay_ms),
        }
    }

    /// Release all modifier keys (Ctrl, Alt, Shift)
    /// This is important to call before typing, especially after a hotkey was pressed
    #[cfg(target_os = "windows")]
    pub fn release_modifiers(&self) -> Result<()> {
        debug!("Releasing modifier keys (Ctrl, Alt, Shift)");

        let modifiers = [VK_CONTROL, VK_MENU, VK_SHIFT]; // Ctrl, Alt, Shift

        for vk in modifiers {
            let key_up = INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: vk,
                        wScan: 0,
                        dwFlags: KEYEVENTF_KEYUP,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };

            unsafe {
                SendInput(&[key_up], std::mem::size_of::<INPUT>() as i32);
            }
        }

        // Small delay to ensure keys are released
        thread::sleep(Duration::from_millis(30));
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn release_modifiers(&self) -> Result<()> {
        Ok(())
    }

    /// Type a secret string securely using SendInput
    ///
    /// This method:
    /// 1. Releases any held modifier keys first (important after hotkey)
    /// 2. Uses Unicode input to support all characters
    /// 3. Sends both key down and key up events
    /// 4. Does NOT use the clipboard (avoiding clipboard history)
    /// 5. The secret is automatically zeroized when dropped
    #[cfg(target_os = "windows")]
    pub fn type_secret(&self, text: &SecretString) -> Result<()> {
        // Release modifier keys first to avoid interference
        self.release_modifiers()?;

        let secret_text = text.expose_secret();
        debug!("Typing {} characters securely", secret_text.len());

        let mut success_count = 0;
        for ch in secret_text.chars() {
            match self.send_unicode_char(ch) {
                Ok(_) => success_count += 1,
                Err(e) => {
                    error!("Failed to send character: {}", e);
                    return Err(e);
                }
            }
            thread::sleep(self.keystroke_delay);
        }

        debug!(
            "Finished typing secret text ({} chars sent successfully)",
            success_count
        );
        Ok(())
    }

    /// Type a regular (non-secret) string
    #[cfg(target_os = "windows")]
    pub fn type_string(&self, text: &str) -> Result<()> {
        debug!("Typing {} characters", text.len());

        for ch in text.chars() {
            self.send_unicode_char(ch)?;
            thread::sleep(self.keystroke_delay);
        }

        Ok(())
    }

    /// Send a single Unicode character using SendInput
    #[cfg(target_os = "windows")]
    fn send_unicode_char(&self, ch: char) -> Result<()> {
        let scan_code = ch as u16;

        // Key down event
        let key_down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0), // 0 for Unicode input
                    wScan: scan_code,
                    dwFlags: KEYEVENTF_UNICODE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        // Key up event
        let key_up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: scan_code,
                    dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        let inputs = [key_down, key_up];

        // SendInput returns the number of events successfully inserted
        let result = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };

        if result != 2 {
            error!("SendInput failed for character '{}'", ch);
            return Err(BitwardenAutofillError::InputInjectionFailed(format!(
                "SendInput returned {} instead of 2",
                result
            )));
        }

        Ok(())
    }

    /// Press Tab key to move to next field
    #[cfg(target_os = "windows")]
    pub fn press_tab(&self) -> Result<()> {
        use windows::Win32::UI::Input::KeyboardAndMouse::VK_TAB;

        // Release modifiers first to avoid Alt+Tab
        self.release_modifiers()?;

        debug!("Pressing Tab key");

        let key_down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VK_TAB,
                    wScan: 0,
                    dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(0),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        let key_up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VK_TAB,
                    wScan: 0,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        let inputs = [key_down, key_up];
        let result = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };

        if result != 2 {
            return Err(BitwardenAutofillError::InputInjectionFailed(
                "Failed to send Tab key".to_string(),
            ));
        }

        thread::sleep(Duration::from_millis(50)); // Brief pause after Tab
        Ok(())
    }

    /// Press Enter key to submit form
    #[cfg(target_os = "windows")]
    pub fn press_enter(&self) -> Result<()> {
        use windows::Win32::UI::Input::KeyboardAndMouse::VK_RETURN;

        debug!("Pressing Enter key");

        let key_down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VK_RETURN,
                    wScan: 0,
                    dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(0),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        let key_up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VK_RETURN,
                    wScan: 0,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        let inputs = [key_down, key_up];
        let result = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };

        if result != 2 {
            return Err(BitwardenAutofillError::InputInjectionFailed(
                "Failed to send Enter key".to_string(),
            ));
        }

        Ok(())
    }

    // Non-Windows stub implementations
    #[cfg(not(target_os = "windows"))]
    pub fn type_secret(&self, _text: &SecretString) -> Result<()> {
        Err(BitwardenAutofillError::InputInjectionFailed(
            "Input injection is only supported on Windows".to_string(),
        ))
    }

    #[cfg(not(target_os = "windows"))]
    pub fn type_string(&self, _text: &str) -> Result<()> {
        Err(BitwardenAutofillError::InputInjectionFailed(
            "Input injection is only supported on Windows".to_string(),
        ))
    }

    #[cfg(not(target_os = "windows"))]
    pub fn press_tab(&self) -> Result<()> {
        Err(BitwardenAutofillError::InputInjectionFailed(
            "Input injection is only supported on Windows".to_string(),
        ))
    }

    #[cfg(not(target_os = "windows"))]
    pub fn press_enter(&self) -> Result<()> {
        Err(BitwardenAutofillError::InputInjectionFailed(
            "Input injection is only supported on Windows".to_string(),
        ))
    }
}

impl Default for InputInjector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injector_creation() {
        let injector = InputInjector::new();
        assert_eq!(injector.keystroke_delay, Duration::from_millis(5));

        let custom = InputInjector::with_delay(10);
        assert_eq!(custom.keystroke_delay, Duration::from_millis(10));
    }
}
