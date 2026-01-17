//! Bitwarden Desktop Autofill
//!
//! A Windows desktop autofill tool that integrates with Bitwarden to automatically
//! fill credentials in native Windows applications using Microsoft UI Automation.
//!
//! ## Usage
//! 1. Run the application (it will appear in the system tray)
//! 2. Click the tray icon and select "Login"
//! 3. Enter your Bitwarden email and master password
//! 4. Focus on a login form and press Ctrl+Alt+P to autofill
//!
//! ## How it works
//! - Connects directly to Bitwarden API (no CLI needed)
//! - Detects the focused UI element using Windows UI Automation
//! - Matches the window title to vault entries using fuzzy search
//! - If the focused field is a password box, fills the password
//! - If the focused field is a text box, fills the username

use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use global_hotkey::hotkey::{Code, HotKey, Modifiers};
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};
use muda::MenuEvent;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

// Use the new crate name
use bitwarden_desktop_autofill::bitwarden::BitwardenClient;
use bitwarden_desktop_autofill::config::{load_config, sync_startup_setting, HotkeyConfig};
use bitwarden_desktop_autofill::credentials_store::{
    clear_login, load_saved_login, save_login, SavedLogin,
};
use bitwarden_desktop_autofill::error::{BitwardenAutofillError, Result};
use bitwarden_desktop_autofill::input_injector::InputInjector;
use bitwarden_desktop_autofill::native_ui::{
    prompt_account_selection, prompt_generic_input, prompt_login, show_error, show_no_credentials_found, show_settings_dialog,
};
use bitwarden_desktop_autofill::tray::{TrayAction, TrayManager, VaultState};
use bitwarden_desktop_autofill::ui_automation::{extract_app_name, LoginFields, UIDetector};

use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
};

/// Application state shared across async tasks
struct AppState {
    bw_client: BitwardenClient,
    tray: TrayManager,
    ui_detector: UIDetector,
    input_injector: InputInjector,
    fuzzy_matcher: SkimMatcherV2,
}

impl AppState {
    fn new() -> Result<Self> {
        Ok(Self {
            bw_client: BitwardenClient::new(),
            tray: TrayManager::new()?,
            ui_detector: UIDetector::new()?,
            input_injector: InputInjector::new(),
            fuzzy_matcher: SkimMatcherV2::default(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file (optional)
    let _ = dotenvy::dotenv();

    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .init();

    info!("Bitwarden Desktop Autofill starting...");

    // Sync startup registry setting with config
    if let Err(e) = sync_startup_setting() {
        warn!("Failed to sync startup setting: {}", e);
    }

    // Initialize application state
    let state = Arc::new(RwLock::new(AppState::new()?));

    // Show system tray
    {
        let mut state_guard = state.write().await;
        state_guard.tray.show()?;
        info!("System tray initialized");
    }

    // Load hotkey configuration
    let hotkey_config = load_config()
        .map(|c| c.hotkey)
        .unwrap_or_default();
    
    // Register global hotkey from config
    let hotkey_manager = GlobalHotKeyManager::new()
        .map_err(|e| BitwardenAutofillError::InputInjectionFailed(e.to_string()))?;

    let hotkey = config_to_hotkey(&hotkey_config);
    if let Err(e) = hotkey_manager.register(hotkey) {
        let error_message = e.to_string();
        warn!("Failed to register hotkey: {}", error_message);
        show_error(
            "Hotkey Registration Failed",
            "The global hotkey is already in use. Another instance may be running, or the hotkey is registered by another app. You can quit the other app or change the hotkey in Settings.",
        );
    } else {
        info!("Registered hotkey: {}", hotkey_config.display_string());
    }

    // Event channels
    let hotkey_receiver = GlobalHotKeyEvent::receiver();
    let menu_receiver = MenuEvent::receiver();

    info!("Ready! Press Ctrl+Alt+P to autofill, or use the system tray menu.");
    info!("Click tray icon -> Login to connect to Bitwarden.");

    if let Err(e) = handle_login(Arc::clone(&state)).await {
        warn!("Startup login failed: {}", e);
    }

    loop {
        // Pump Windows messages (required for tray icon and menu)
        unsafe {
            let mut msg = MSG::default();
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                let _ = DispatchMessageW(&msg);
            }
        }
        // Check for hotkey events
        if let Ok(event) = hotkey_receiver.try_recv() {
            if event.state == HotKeyState::Pressed {
                debug!("Hotkey pressed");
                if let Err(e) = handle_autofill(Arc::clone(&state)).await {
                    // Show helpful dialog for "no credentials found" error
                    if let BitwardenAutofillError::NoCredentialsFound(ref app_name) = e {
                        let state_guard = state.read().await;
                        let server_region = state_guard.bw_client.get_server_region();
                        drop(state_guard);
                        let sync_requested = show_no_credentials_found(app_name, Some(&server_region));
                        if sync_requested {
                            info!("Syncing vault after no credentials dialog...");
                            if let Err(sync_err) = handle_sync(Arc::clone(&state)).await {
                                error!("Sync failed: {}", sync_err);
                                show_error("Sync Failed", &format!("Failed to sync vault: {}", sync_err));
                            } else {
                                info!("Vault synced successfully");
                            }
                        }
                    } else if !e.is_recoverable() {
                        error!("Autofill failed: {}", e);
                    }
                }
            }
        }

        // Check for menu events
        if let Ok(event) = menu_receiver.try_recv() {
            let action = TrayManager::handle_menu_event(&event);
            debug!("Menu action: {:?}", action);

            match action {
                TrayAction::Unlock => {
                    if let Err(e) = handle_login(Arc::clone(&state)).await {
                        error!("Login failed: {}", e);
                    }
                }
                TrayAction::Lock => {
                    handle_logout(Arc::clone(&state)).await;
                }
                TrayAction::Sync => {
                    if let Err(e) = handle_sync(Arc::clone(&state)).await {
                        error!("Sync failed: {}", e);
                    }
                }
                TrayAction::Quit => {
                    info!("Quit requested");
                    break;
                }
                TrayAction::OpenSettings => {
                    match show_settings_dialog() {
                        Ok(result) => {
                            if result.clear_credentials {
                                if let Err(e) = clear_login() {
                                    error!("Failed to clear credentials: {}", e);
                                } else {
                                    info!("Credentials cleared from settings");
                                }
                            }
                            if result.sync_vault {
                                info!("Syncing vault from settings...");
                                if let Err(e) = handle_sync(Arc::clone(&state)).await {
                                    error!("Vault sync failed: {}", e);
                                    show_error("Sync Failed", &format!("Failed to sync vault: {}", e));
                                } else {
                                    info!("Vault synced successfully");
                                }
                            }
                        }
                        Err(e) => {
                            error!("Settings dialog failed: {}", e);
                        }
                    }
                }
                TrayAction::Unknown(id) => {
                    warn!("Unknown menu action: {}", id);
                }
            }
        }

        // Small sleep to prevent busy-waiting
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    info!("Bitwarden Desktop Autofill shutting down");
    Ok(())
}

/// Handle the login action
async fn handle_login(state: Arc<RwLock<AppState>>) -> Result<()> {
    info!("Starting login...");

    let saved_login = match load_saved_login() {
        Ok(login) => login,
        Err(e) => {
            warn!("Failed to load saved login: {}", e);
            None
        }
    };
    if saved_login.is_some() {
        info!("Loaded saved login from credential manager");
    }

    let login_input = match prompt_login(saved_login.as_ref()) {
        Ok(input) => input,
        Err(e) => {
            warn!("Login cancelled: {}", e);
            return Err(e);
        }
    };

    {
        let mut state_guard = state.write().await;
        state_guard.bw_client.set_server(login_input.server.clone());
    }

    info!("Attempting login with API key");

    let client_secret_value = login_input.client_secret.expose_secret();

    // Login with API Key
    let login_result = {
        let mut state_guard = state.write().await;
        state_guard
            .bw_client
            .login_api_key(
                &login_input.email,
                login_input.password,
                &login_input.client_id,
                client_secret_value,
            )
            .await
    };

    if let Err(e) = login_result {
        show_error("Login Failed", &e.to_string());
        return Err(e);
    }

    // Check if 2FA is required
    let needs_2fa = {
        let state_guard = state.read().await;
        match state_guard.bw_client.state() {
            bitwarden_desktop_autofill::bitwarden::client::ClientState::AwaitingTwoFactor(
                p,
            ) => Some(p.clone()),
            _ => None,
        }
    };

    if let Some(providers) = needs_2fa {
        // Prompt for 2FA code (Native Dialog)
        // We generally default to the first provider
        let provider = providers.first().copied().unwrap_or(
            bitwarden_desktop_autofill::bitwarden::types::TwoFactorProvider::Authenticator,
        );

        // We use the generic prompt where "User name" label is implicitly used for input
        let (code_input, _) = match prompt_generic_input(
            "Two-Factor Authentication",
            "Enter your 2FA code (e.g. from Authenticator App) in the User name box.\nLeave Password blank.",
        ) {
            Ok(res) => res,
            Err(_) => return Ok(()),
        };

        let code = if code_input.is_empty() {
            // Maybe user put it in password field? no, let's assume username field usage
            // We can check the secret string too if we wanted.
            return Ok(());
        } else {
            code_input
        };

        let mut state_guard = state.write().await;
        if let Err(e) = state_guard.bw_client.submit_2fa(provider, &code).await {
            show_error("2FA Failed", &e.to_string());
            return Err(e);
        }
    }

    if login_input.remember {
        let saved = SavedLogin {
            server: login_input.server.clone(),
            email: login_input.email.clone(),
            client_id: login_input.client_id.clone(),
            client_secret: login_input.client_secret.clone(),
        };
        if let Err(e) = save_login(&saved) {
            warn!("Failed to save credentials: {}", e);
        }
    } else if let Err(e) = clear_login() {
        warn!("Failed to clear saved credentials: {}", e);
    }

    // Update tray state
    {
        let mut state_guard = state.write().await;
        state_guard.tray.set_vault_state(VaultState::Unlocked)?;
    }

    info!("Login successful, vault unlocked");
    Ok(())
}

/// Handle the logout action
async fn handle_logout(state: Arc<RwLock<AppState>>) {
    info!("Logging out...");

    {
        let mut state_guard = state.write().await;
        state_guard.bw_client.logout();
    }

    // Update tray state
    if let Ok(mut state_guard) = state.try_write() {
        let _ = state_guard.tray.set_vault_state(VaultState::Locked);
    }

    info!("Logged out");
}

/// Handle the sync vault action
async fn handle_sync(state: Arc<RwLock<AppState>>) -> Result<()> {
    info!("Syncing vault...");

    // Update tray to syncing state
    {
        let mut state_guard = state.write().await;
        state_guard.tray.set_vault_state(VaultState::Syncing)?;
    }

    // Perform sync
    let result = {
        let mut state_guard = state.write().await;
        state_guard.bw_client.sync().await
    };

    // Update tray state based on result
    {
        let mut state_guard = state.write().await;
        if result.is_ok() {
            state_guard.tray.set_vault_state(VaultState::Unlocked)?;
        } else {
            state_guard.tray.set_vault_state(VaultState::Locked)?;
        }
    }

    result?;
    info!("Vault synced successfully");
    Ok(())
}

/// Main autofill pipeline
async fn handle_autofill(state: Arc<RwLock<AppState>>) -> Result<()> {
    info!("Autofill triggered");

    // Small delay to let focus settle after hotkey press
    // This helps ensure the target window/field is properly focused
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Check if logged in, prompt if not
    loop {
        let state_guard = state.read().await;

        if !state_guard.bw_client.is_unlocked() {
            warn!("Not logged in, prompting for login");
            drop(state_guard);
            handle_login(Arc::clone(&state)).await?;
            continue;
        }

        break;
    }

    let state_guard = state.read().await;

    // First, try to auto-detect login fields in the foreground window
    let login_fields = state_guard.ui_detector.find_login_fields();

    match login_fields {
        Ok(LoginFields {
            username_field: Some(ref username_el),
            password_field,
            ref window_title,
        }) => {
            // Auto-detected username field! Use it
            debug!("Auto-detected login fields in window: '{}'", window_title);

            // Search for credentials using window title
            let search_query = extract_app_name(window_title);
            let selected = find_best_credential(&state_guard, &search_query, window_title).await?;
            debug!("Selected credential for autofill");

            // Focus username field
            state_guard.ui_detector.focus_element(username_el)?;
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            // Fill username
            if let Some(ref username) = selected.username {
                info!("Filling username field (auto-detected)");
                let username_str: String = username.clone();
                let username_secret = SecretString::from(username_str);
                state_guard.input_injector.type_secret(&username_secret)?;

                // Tab to password field (or use detected password field)
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                if let Some(ref password_el) = password_field {
                    // Focus password field directly
                    state_guard.ui_detector.focus_element(password_el)?;
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                } else {
                    // Tab to next field
                    state_guard.input_injector.press_tab()?;
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }

                // Fill password
                if let Some(ref password) = selected.password {
                    info!("Filling password field");
                    state_guard.input_injector.type_secret(password)?;
                } else {
                    warn!("No password available for this credential");
                }
            } else {
                warn!("No username available, trying password only");
                // Focus password field if we have it
                if let Some(ref password_el) = password_field {
                    state_guard.ui_detector.focus_element(password_el)?;
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
                if let Some(ref password) = selected.password {
                    state_guard.input_injector.type_secret(password)?;
                }
            }

            info!("Autofill complete (auto-detected fields)");
            Ok(())
        }
        Ok(LoginFields {
            username_field: None,
            password_field: Some(ref password_el),
            ref window_title,
        }) => {
            // Only password field found - focus and fill it
            debug!(
                "Auto-detected only password field in window: '{}'",
                window_title
            );

            let search_query = extract_app_name(window_title);
            let selected = find_best_credential(&state_guard, &search_query, window_title).await?;
            debug!("Selected credential for autofill");

            state_guard.ui_detector.focus_element(password_el)?;
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            if let Some(ref password) = selected.password {
                info!("Filling password field (auto-detected)");
                state_guard.input_injector.type_secret(password)?;
            } else {
                warn!("No password available for this credential");
            }

            info!("Autofill complete (password only)");
            Ok(())
        }
        _ => {
            // Auto-detection failed or no fields found
            // Fall back to using the currently focused element
            debug!("Auto-detection failed, falling back to focused element");
            handle_autofill_fallback(&state_guard).await
        }
    }
}

/// Fallback autofill using the currently focused element
/// This is the original behavior when auto-detection doesn't work (e.g., in browsers)
async fn handle_autofill_fallback(
    state_guard: &tokio::sync::RwLockReadGuard<'_, AppState>,
) -> Result<()> {
    // Get the focused element
    let focused = state_guard.ui_detector.get_focused_element()?;
    debug!(
        "Fallback mode - Window: '{}', IsPassword: {}, ControlType: '{}'",
        focused.window_title, focused.is_password, focused.control_type
    );

    // Extract searchable app name from window title
    let search_query = extract_app_name(&focused.window_title);
    let selected = find_best_credential(state_guard, &search_query, &focused.window_title).await?;
    debug!("Selected credential for autofill");

    // Fill both username and password in sequence
    // If we're in a password field, fill password first then we're done
    // If we're in a non-password field (likely username), fill username -> Tab -> password

    if focused.is_password {
        // Already in password field, just fill password
        if let Some(ref password) = selected.password {
            info!("Filling password field");
            state_guard.input_injector.type_secret(password)?;
        } else {
            warn!("No password available for this credential");
        }
    } else {
        // In username/other field - fill username, tab to password, fill password
        if let Some(ref username) = selected.username {
            info!("Filling username field");
            let username_str: String = username.clone();
            let username_secret = SecretString::from(username_str);
            state_guard.input_injector.type_secret(&username_secret)?;

            // Tab to next field (password)
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            state_guard.input_injector.press_tab()?;

            // Small delay to let focus shift
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            // Fill password
            if let Some(ref password) = selected.password {
                info!("Filling password field");
                state_guard.input_injector.type_secret(password)?;
            } else {
                warn!("No password available for this credential");
            }
        } else {
            warn!("No username available for this credential");
            // Try to fill password anyway
            if let Some(ref password) = selected.password {
                info!("No username, filling password only");
                state_guard.input_injector.type_secret(password)?;
            }
        }
    }

    info!("Autofill complete (fallback mode)");
    Ok(())
}

/// Find the best matching credential for a given search query
async fn find_best_credential(
    state_guard: &tokio::sync::RwLockReadGuard<'_, AppState>,
    search_query: &str,
    window_title: &str,
) -> Result<bitwarden_desktop_autofill::bitwarden::types::LoginItem> {
    debug!("Search query: '{}'", search_query);

    // Search for matching credentials
    let mut logins = state_guard.bw_client.search(search_query).await;

    if logins.is_empty() {
        // Try with full window title
        warn!("No results for '{}', trying full title", search_query);
        logins = state_guard.bw_client.search(window_title).await;

        if logins.is_empty() {
            return Err(BitwardenAutofillError::NoCredentialsFound(
                search_query.to_string(),
            ));
        }
    }

    // If multiple matches, show selection dialog
    let selected = if logins.len() > 1 {
        info!(
            "Found {} matching credentials, showing selection dialog",
            logins.len()
        );

        // Sort by fuzzy score first so best matches appear at top
        let mut scored: Vec<_> = logins
            .iter()
            .map(|item| {
                let score = state_guard
                    .fuzzy_matcher
                    .fuzzy_match(&item.name, window_title)
                    .unwrap_or(0);
                (score, item)
            })
            .collect();

        scored.sort_by(|a, b| b.0.cmp(&a.0));

        // Build accounts list for dialog (sorted by score)
        let accounts: Vec<(String, Option<String>)> = scored
            .iter()
            .map(|(_, item)| (item.name.clone(), item.username.clone()))
            .collect();

        // Extract app name for dialog title
        let app_name = extract_app_name(window_title);

        // Show selection dialog
        match prompt_account_selection(&app_name, &accounts) {
            Ok(Some(index)) => {
                let selected_item = scored
                    .get(index)
                    .map(|(_, item)| (*item).clone())
                    .ok_or_else(|| {
                        BitwardenAutofillError::PasswordDialogFailed(
                            "Selection index out of range".to_string(),
                        )
                    })?;
                debug!("User selected account from dialog");
                selected_item
            }
            Ok(None) => {
                info!("User cancelled account selection");
                return Err(BitwardenAutofillError::PasswordDialogCancelled);
            }
            Err(e) => {
                error!("Account selection dialog failed: {}", e);
                // Fall back to best fuzzy match
                warn!("Falling back to best fuzzy match");
                scored[0].1.clone()
            }
        }
    } else {
        logins
            .into_iter()
            .next()
            .ok_or_else(|| BitwardenAutofillError::NoCredentialsFound(search_query.to_string()))?
    };

    Ok(selected)
}

/// Convert HotkeyConfig to global_hotkey::HotKey
fn config_to_hotkey(config: &HotkeyConfig) -> HotKey {
    // Build modifiers
    let mut modifiers = Modifiers::empty();
    for m in &config.modifiers {
        match m.as_str() {
            "ctrl" => modifiers |= Modifiers::CONTROL,
            "alt" => modifiers |= Modifiers::ALT,
            "shift" => modifiers |= Modifiers::SHIFT,
            "win" => modifiers |= Modifiers::SUPER,
            _ => {}
        }
    }
    
    // Convert key string to Code
    let code = match config.key.as_str() {
        "A" => Code::KeyA,
        "B" => Code::KeyB,
        "C" => Code::KeyC,
        "D" => Code::KeyD,
        "E" => Code::KeyE,
        "F" => Code::KeyF,
        "G" => Code::KeyG,
        "H" => Code::KeyH,
        "I" => Code::KeyI,
        "J" => Code::KeyJ,
        "K" => Code::KeyK,
        "L" => Code::KeyL,
        "M" => Code::KeyM,
        "N" => Code::KeyN,
        "O" => Code::KeyO,
        "P" => Code::KeyP,
        "Q" => Code::KeyQ,
        "R" => Code::KeyR,
        "S" => Code::KeyS,
        "T" => Code::KeyT,
        "U" => Code::KeyU,
        "V" => Code::KeyV,
        "W" => Code::KeyW,
        "X" => Code::KeyX,
        "Y" => Code::KeyY,
        "Z" => Code::KeyZ,
        "F1" => Code::F1,
        "F2" => Code::F2,
        "F3" => Code::F3,
        "F4" => Code::F4,
        "F5" => Code::F5,
        "F6" => Code::F6,
        "F7" => Code::F7,
        "F8" => Code::F8,
        "F9" => Code::F9,
        "F10" => Code::F10,
        "F11" => Code::F11,
        "F12" => Code::F12,
        _ => Code::KeyP, // Default fallback
    };
    
    let mods = if modifiers.is_empty() { None } else { Some(modifiers) };
    HotKey::new(mods, code)
}
