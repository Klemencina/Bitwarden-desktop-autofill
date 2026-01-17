//! Windows UI Automation Module
//!
//! This module uses Microsoft UI Automation to detect the currently focused
//! element and determine whether it's a password field or a regular text input.

use crate::error::{BitwardenAutofillError, Result};
use tracing::{debug, error, info, warn};
use uiautomation::controls::ControlType;
use uiautomation::types::{Handle, UIProperty};
use uiautomation::{UIAutomation, UIElement};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW};

/// Information about the currently focused UI element
#[derive(Debug, Clone)]
pub struct FocusedElement {
    /// The name/label of the element
    pub name: String,
    /// The control type (e.g., "Edit", "Text")
    pub control_type: String,
    /// Whether this is a password field
    pub is_password: bool,
    /// The window title of the parent window
    pub window_title: String,
    /// The process name of the application
    pub process_name: Option<String>,
}

/// Detected login fields in a window
#[derive(Debug)]
pub struct LoginFields {
    /// The username/email input field (if found)
    pub username_field: Option<UIElement>,
    /// The password input field (if found)
    pub password_field: Option<UIElement>,
    /// The window title where fields were found
    pub window_title: String,
}

/// UI Automation detector for Windows
pub struct UIDetector {
    automation: UIAutomation,
}

impl UIDetector {
    /// Create a new UI Automation detector
    pub fn new() -> Result<Self> {
        let automation = UIAutomation::new()
            .map_err(|e| BitwardenAutofillError::UIAutomationInitFailed(e.to_string()))?;

        info!("UI Automation initialized successfully");
        Ok(Self { automation })
    }

    /// Get information about the currently focused element
    pub fn get_focused_element(&self) -> Result<FocusedElement> {
        let focused = self.automation.get_focused_element().map_err(|e| {
            error!("Failed to get focused element: {}", e);
            BitwardenAutofillError::NoFocusedElement
        })?;

        // Get element name
        let name = focused
            .get_name()
            .unwrap_or_else(|_| String::from("Unknown"));

        // Get control type
        let control_type = focused
            .get_localized_control_type()
            .unwrap_or_else(|_| String::from("Unknown"));

        // Check if this is a password field
        let is_password = self.check_is_password(&focused);

        // Get the window title using multiple methods
        let window_title = self.get_window_title_with_fallbacks(&focused, &name)?;

        // Try to get process name
        let process_name = self.get_process_name(&focused);

        debug!(
            "Focused element - Name: '{}', Type: '{}', IsPassword: {}, Window: '{}'",
            name, control_type, is_password, window_title
        );

        Ok(FocusedElement {
            name,
            control_type,
            is_password,
            window_title,
            process_name,
        })
    }

    /// Get window title using multiple fallback methods
    fn get_window_title_with_fallbacks(
        &self,
        element: &uiautomation::UIElement,
        element_name: &str,
    ) -> Result<String> {
        // Method 1: Try tree walking first
        if let Ok(title) = self.get_top_window_title(element) {
            if !title.is_empty() && title != "Unknown Application" {
                return Ok(title);
            }
        }

        // Method 2: Try Win32 GetForegroundWindow
        if let Some(title) = self.get_foreground_window_title() {
            if !title.is_empty() {
                debug!("Got window title from GetForegroundWindow: '{}'", title);
                return Ok(title);
            }
        }

        // Method 3: Use the element's name if it looks like a window/page title
        if !element_name.is_empty() && element_name != "Unknown" {
            // Check if element name looks like a meaningful title
            // (contains separators often used in window titles, or is reasonably long)
            if element_name.contains(" - ")
                || element_name.contains(" | ")
                || element_name.contains(" — ")
                || element_name.len() > 10
            {
                debug!("Using element name as window title: '{}'", element_name);
                return Ok(element_name.to_string());
            }
        }

        // Method 4: If element name is short but non-empty, still use it
        if !element_name.is_empty() && element_name != "Unknown" {
            debug!(
                "Using short element name as window title: '{}'",
                element_name
            );
            return Ok(element_name.to_string());
        }

        warn!("Could not determine window title through any method");
        Ok(String::from("Unknown Application"))
    }

    /// Get the foreground window title using Win32 API
    fn get_foreground_window_title(&self) -> Option<String> {
        unsafe {
            let hwnd: HWND = GetForegroundWindow();
            if hwnd.0.is_null() {
                return None;
            }

            let mut buffer = [0u16; 512];
            let len = GetWindowTextW(hwnd, &mut buffer);
            if len > 0 {
                let title = String::from_utf16_lossy(&buffer[..len as usize]);
                return Some(title);
            }
        }
        None
    }

    /// Check if the given element is a password field
    fn check_is_password(&self, element: &uiautomation::UIElement) -> bool {
        use std::convert::TryInto;

        // Method 1: Check the IsPassword property directly
        if let Ok(is_password) = element.get_property_value(UIProperty::IsPassword) {
            // Use TryInto to convert Variant to bool
            if let Ok(val) = TryInto::<bool>::try_into(is_password) {
                if val {
                    return true;
                }
            }
        }

        // Method 2: Check if it's an Edit control with password characteristics
        if let Ok(control_type) = element.get_localized_control_type() {
            let control_lower = control_type.to_lowercase();
            if control_lower.contains("password") {
                return true;
            }
        }

        // Method 3: Check the element name for password hints
        if let Ok(name) = element.get_name() {
            let name_lower = name.to_lowercase();
            if name_lower.contains("password") || name_lower.contains("passwort") {
                return true;
            }
        }

        // Method 4: Check automation ID
        if let Ok(auto_id) = element.get_automation_id() {
            let id_lower = auto_id.to_lowercase();
            if id_lower.contains("password") || id_lower.contains("passwd") {
                return true;
            }
        }

        false
    }

    /// Walk up the UI tree to find the top-level window title
    fn get_top_window_title(&self, element: &uiautomation::UIElement) -> Result<String> {
        let mut current = element.clone();
        let mut window_title = String::new();

        // Walk up the tree looking for a window element
        loop {
            // Check if this is a window
            if let Ok(control_type) = current.get_localized_control_type() {
                let control_lower = control_type.to_lowercase();
                if control_lower.contains("window") || control_lower.contains("fenster") {
                    if let Ok(name) = current.get_name() {
                        if !name.is_empty() {
                            window_title = name;
                        }
                    }
                }
            }

            // Try to get parent
            match self
                .automation
                .create_tree_walker()
                .and_then(|walker| walker.get_parent(&current))
            {
                Ok(parent) => {
                    // Check if we've reached the root (desktop)
                    if let Ok(name) = parent.get_name() {
                        if name.is_empty() || name == "Desktop" {
                            break;
                        }
                    }
                    current = parent;
                }
                Err(_) => break,
            }
        }

        if window_title.is_empty() {
            // Fallback: just use the root element's name if we couldn't find a window
            warn!("Could not find window title through tree walking");
            window_title = String::from("Unknown Application");
        }

        Ok(window_title)
    }

    /// Try to get the process name for the element's window
    fn get_process_name(&self, element: &uiautomation::UIElement) -> Option<String> {
        // Get process ID from the element
        let process_id = element.get_process_id().ok()?;

        // Try to get process name from process ID
        // This is a simplified approach - in production, you'd use
        // Windows APIs to get the process name from the PID
        debug!("Element belongs to process ID: {}", process_id);

        // For now, return None - we'll rely on window title matching
        None
    }

    /// Check if the focused element is an input field (text or password)
    pub fn is_input_field(&self) -> Result<bool> {
        let focused = self.get_focused_element()?;
        let control_lower = focused.control_type.to_lowercase();

        Ok(control_lower.contains("edit")
            || control_lower.contains("text")
            || control_lower.contains("eingabe")
            || focused.is_password)
    }

    /// Find login fields (username + password) in the foreground window
    ///
    /// This attempts to automatically detect login form fields without requiring
    /// the user to click in a specific field first. Uses heuristics to identify
    /// username vs other text fields.
    ///
    /// Returns None for fields that couldn't be found (e.g., in web browsers
    /// where form content may not be accessible via UI Automation).
    pub fn find_login_fields(&self) -> Result<LoginFields> {
        info!("Attempting to auto-detect login fields in foreground window");

        // Get the foreground window title first
        let window_title = self
            .get_foreground_window_title()
            .unwrap_or_else(|| String::from("Unknown"));

        // Get the foreground window as UIElement
        let foreground_element = self.get_foreground_window_element()?;

        // Use UIMatcher to find all Edit controls in the window
        let matcher = self
            .automation
            .create_matcher()
            .from(foreground_element)
            .control_type(ControlType::Edit)
            .depth(20) // Search deep in the UI tree
            .timeout(500); // Quick timeout - don't block too long

        let all_edits = match matcher.find_all() {
            Ok(edits) => edits,
            Err(e) => {
                warn!("Failed to find edit controls in window: {}", e);
                return Ok(LoginFields {
                    username_field: None,
                    password_field: None,
                    window_title,
                });
            }
        };

        debug!("Found {} edit controls in window", all_edits.len());

        // Filter to only enabled, focusable fields
        let usable_edits: Vec<UIElement> = all_edits
            .into_iter()
            .filter(|el| {
                let enabled = el.is_enabled().unwrap_or(false);
                let focusable = el.is_keyboard_focusable().unwrap_or(false);
                let offscreen = el.is_offscreen().unwrap_or(true);
                enabled && focusable && !offscreen
            })
            .collect();

        debug!(
            "After filtering: {} usable edit controls",
            usable_edits.len()
        );

        // Classify fields
        let mut password_field: Option<UIElement> = None;
        let mut username_field: Option<UIElement> = None;
        let mut fallback_text_field: Option<UIElement> = None;

        for element in usable_edits {
            let is_password = element.is_password().unwrap_or(false);

            if is_password {
                if password_field.is_none() {
                    debug!("Found password field");
                    password_field = Some(element);
                }
            } else {
                // Check if this looks like a username field using heuristics
                if username_field.is_none() && self.is_likely_username_field(&element) {
                    debug!("Found username field via heuristics");
                    username_field = Some(element);
                } else if fallback_text_field.is_none() {
                    // Store first non-password field as fallback
                    fallback_text_field = Some(element);
                }
            }
        }

        // If no username field found via heuristics, use fallback
        if username_field.is_none() && fallback_text_field.is_some() {
            debug!("Using fallback text field as username field");
            username_field = fallback_text_field;
        }

        info!(
            "Login field detection complete - username: {}, password: {}",
            username_field.is_some(),
            password_field.is_some()
        );

        Ok(LoginFields {
            username_field,
            password_field,
            window_title,
        })
    }

    /// Get the foreground window as a UIElement
    fn get_foreground_window_element(&self) -> Result<UIElement> {
        unsafe {
            let hwnd: HWND = GetForegroundWindow();
            if hwnd.0.is_null() {
                return Err(BitwardenAutofillError::NoFocusedElement);
            }

            // Convert HWND to uiautomation Handle type via isize
            // (works around version mismatch between windows crates)
            let handle = Handle::from(hwnd.0 as isize);

            // Get the UIElement from the window handle
            self.automation.element_from_handle(handle).map_err(|e| {
                error!("Failed to get UIElement from window handle: {}", e);
                BitwardenAutofillError::UIAutomationInitFailed(e.to_string())
            })
        }
    }

    /// Check if an element is likely a username/email field using heuristics
    fn is_likely_username_field(&self, element: &UIElement) -> bool {
        // Patterns that suggest a username/email field
        let username_patterns = [
            "user",
            "email",
            "e-mail",
            "login",
            "account",
            "username",
            "userid",
            "benutzer",    // German
            "utilisateur", // French
            "usuario",     // Spanish
            "uporabnik",   // Slovenian
        ];

        // Check automation ID
        if let Ok(auto_id) = element.get_automation_id() {
            let auto_id_lower = auto_id.to_lowercase();
            for pattern in &username_patterns {
                if auto_id_lower.contains(pattern) {
                    debug!(
                        "Field matches username pattern in automation_id: '{}'",
                        auto_id
                    );
                    return true;
                }
            }
        }

        // Check element name
        if let Ok(name) = element.get_name() {
            let name_lower = name.to_lowercase();
            for pattern in &username_patterns {
                if name_lower.contains(pattern) {
                    debug!("Field matches username pattern in name: '{}'", name);
                    return true;
                }
            }
        }

        // Check help text
        if let Ok(help) = element.get_help_text() {
            let help_lower = help.to_lowercase();
            for pattern in &username_patterns {
                if help_lower.contains(pattern) {
                    debug!("Field matches username pattern in help_text: '{}'", help);
                    return true;
                }
            }
        }

        false
    }

    /// Focus on a specific UI element
    pub fn focus_element(&self, element: &UIElement) -> Result<()> {
        debug!("Setting focus to element");
        element.set_focus().map_err(|e| {
            error!("Failed to set focus: {}", e);
            BitwardenAutofillError::UIAutomationInitFailed(format!(
                "Failed to focus element: {}",
                e
            ))
        })
    }
}

impl Default for UIDetector {
    fn default() -> Self {
        Self::new().expect("Failed to initialize UI Automation")
    }
}

/// Extract a searchable app name from a window title
///
/// This cleans up window titles to get a simpler name for vault searching.
/// Examples:
/// - "Google - Google Chrome" -> "Google Chrome"
/// - "Inbox - user@gmail.com - Gmail" -> "Gmail"
/// - "Visual Studio Code" -> "Visual Studio Code"
pub fn extract_app_name(window_title: &str) -> String {
    // Common patterns to handle:
    // 1. "Page Title - Browser Name" -> extract browser name
    // 2. "Document - Application" -> extract application

    // Split by common separators and take the last meaningful part
    let separators = [" - ", " — ", " | ", " – "];

    for sep in separators {
        if let Some(last_part) = window_title.rsplit(sep).next() {
            let trimmed = last_part.trim();
            // Check if this looks like an application name (not a page title)
            if is_likely_app_name(trimmed) {
                return trimmed.to_string();
            }
        }
    }

    // No separator found or couldn't identify app name, return cleaned title
    window_title.trim().to_string()
}

/// Heuristic to determine if a string is likely an application name
fn is_likely_app_name(s: &str) -> bool {
    let common_app_names = [
        "chrome",
        "firefox",
        "edge",
        "safari",
        "opera",
        "brave",
        "outlook",
        "thunderbird",
        "mail",
        "slack",
        "teams",
        "discord",
        "zoom",
        "code",
        "visual studio",
        "notepad",
        "sublime",
    ];

    let lower = s.to_lowercase();
    common_app_names.iter().any(|app| lower.contains(app))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_app_name() {
        assert_eq!(extract_app_name("Google - Google Chrome"), "Google Chrome");
        assert_eq!(extract_app_name("Inbox - Gmail"), "Gmail");
        assert_eq!(extract_app_name("Visual Studio Code"), "Visual Studio Code");
    }

    #[test]
    fn test_is_likely_app_name() {
        assert!(is_likely_app_name("Google Chrome"));
        assert!(is_likely_app_name("Firefox"));
        assert!(is_likely_app_name("Microsoft Edge"));
        assert!(!is_likely_app_name("My Document"));
    }
}
