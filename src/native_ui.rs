//! Native Windows UI Helper
//!
//! Wraps Win32 APIs for native dialogs.

use crate::bitwarden::client::ServerRegion;
use crate::credentials_store::SavedLogin;
use crate::error::{BitwardenAutofillError, Result};
use secrecy::{ExposeSecret, SecretString};
use std::cell::RefCell;
use std::ffi::c_void;
use std::rc::Rc;
use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{GetLastError, BOOL, ERROR_INSUFFICIENT_BUFFER, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{GetStockObject, DEFAULT_GUI_FONT};
use windows::Win32::Security::Credentials::{
    CredPackAuthenticationBufferW, CredUIPromptForWindowsCredentialsW,
    CredUnPackAuthenticationBufferW, CREDUIWIN_CHECKBOX, CREDUIWIN_GENERIC, CREDUI_INFOW,
    CRED_PACK_FLAGS,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOG_BUTTON, TDCBF_CANCEL_BUTTON,
    TDF_ALLOW_DIALOG_CANCELLATION, TDF_USE_COMMAND_LINKS, TD_INFORMATION_ICON,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{SetActiveWindow, SetFocus};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetDlgItem, GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW,
    IsDialogMessageW, MessageBoxW, PostQuitMessage, RegisterClassExW, SendMessageW,
    SetWindowTextW, ShowWindow, TranslateMessage,
    BM_GETCHECK, BM_SETCHECK, CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL,
    CW_USEDEFAULT, HMENU, IDCANCEL, IDC_ARROW,
    MB_ICONERROR, MB_OK, MB_SYSTEMMODAL, MSG, SW_HIDE, SW_SHOW, SW_SHOWNORMAL,
    WINDOW_EX_STYLE, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_SETFONT,
    WNDCLASSEXW, WS_BORDER, WS_CAPTION, WS_CHILD,
    WS_MINIMIZEBOX, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};

// Win32 style constants (these are i32/u32 values)
const ES_AUTOHSCROLL: u32 = 0x0080;
const ES_PASSWORD: u32 = 0x0020;
const CBS_DROPDOWNLIST: u32 = 0x0003;
const BS_AUTOCHECKBOX: u32 = 0x0003;
const BS_DEFPUSHBUTTON: u32 = 0x0001;
const BS_PUSHBUTTON: u32 = 0x0000;
const BST_CHECKED: u32 = 0x0001;

pub fn to_wstring(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wstring(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

// Control IDs for the unified login dialog
const IDC_SERVER_COMBO: i32 = 1001;
const IDC_IDENTITY_URL: i32 = 1002;
const IDC_API_URL: i32 = 1003;
const IDC_EMAIL: i32 = 1004;
const IDC_PASSWORD: i32 = 1005;
const IDC_CLIENT_ID: i32 = 1006;
const IDC_CLIENT_SECRET: i32 = 1007;
const IDC_REMEMBER: i32 = 1008;
const IDC_OK: i32 = 1;
const IDC_CANCEL: i32 = 2;
const IDC_IDENTITY_LABEL: i32 = 1010;
const IDC_API_LABEL: i32 = 1011;

// Dialog result stored in thread-local for the window procedure
thread_local! {
    static DIALOG_DATA: RefCell<Option<Rc<RefCell<DialogData>>>> = const { RefCell::new(None) };
    static LOGIN_DIALOG_HWND: RefCell<Option<HWND>> = const { RefCell::new(None) };
}

struct DialogData {
    result: Option<LoginInput>,
    cancelled: bool,
    saved: Option<SavedLogin>,
}

/// Unified login dialog - single page with all fields
pub fn prompt_login_unified(saved: Option<&SavedLogin>) -> Result<LoginInput> {
    // Check if a login dialog is already open
    let existing_hwnd = LOGIN_DIALOG_HWND.with(|h| *h.borrow());
    if let Some(hwnd) = existing_hwnd {
        // Check if the window still exists
        if unsafe { windows::Win32::UI::WindowsAndMessaging::IsWindow(hwnd).as_bool() } {
            // Bring existing window to foreground
            unsafe {
                let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
                let _ = windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(hwnd);
                let _ = SetActiveWindow(hwnd);
            }
            // Return cancelled since we're not creating a new dialog
            return Err(BitwardenAutofillError::PasswordDialogCancelled);
        } else {
            // Window no longer exists, clear the stored handle
            LOGIN_DIALOG_HWND.with(|h| {
                *h.borrow_mut() = None;
            });
        }
    }

    let data = Rc::new(RefCell::new(DialogData {
        result: None,
        cancelled: false,
        saved: saved.cloned(),
    }));

    DIALOG_DATA.with(|d| {
        *d.borrow_mut() = Some(Rc::clone(&data));
    });

    // Register window class
    let class_name = w!("BitwardenLoginDialog");
    let h_instance = unsafe { GetModuleHandleW(None).unwrap_or_default() };

    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(login_dialog_proc),
        hInstance: h_instance.into(),
        lpszClassName: class_name,
        hCursor: unsafe { windows::Win32::UI::WindowsAndMessaging::LoadCursorW(None, IDC_ARROW).unwrap_or_default() },
        hbrBackground: unsafe { windows::Win32::Graphics::Gdi::GetSysColorBrush(windows::Win32::Graphics::Gdi::COLOR_3DFACE) },
        ..Default::default()
    };

    unsafe { RegisterClassExW(&wc) };

    // Create dialog window
    let title = to_wstring("Bitwarden Login");
    let hwnd = unsafe {
        CreateWindowExW(
            windows::Win32::UI::WindowsAndMessaging::WS_EX_APPWINDOW,
            class_name,
            PCWSTR::from_raw(title.as_ptr()),
            WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_BORDER,
            CW_USEDEFAULT, CW_USEDEFAULT,
            420, 410,
            None,
            None,
            h_instance,
            None,
        )
    };

    let hwnd = match hwnd {
        Ok(h) if !h.is_invalid() => h,
        _ => {
            return Err(BitwardenAutofillError::PasswordDialogFailed(
                "Failed to create dialog window".to_string(),
            ));
        }
    };

    // Store the HWND so we can detect if dialog is already open
    LOGIN_DIALOG_HWND.with(|h| {
        *h.borrow_mut() = Some(hwnd);
    });

    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        let _ = SetActiveWindow(hwnd);
        // Try to bring to foreground
        let _ = windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(hwnd);
    }

    // Message loop
    let mut msg = MSG::default();
    unsafe {
        while windows::Win32::UI::WindowsAndMessaging::GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if !IsDialogMessageW(hwnd, &msg).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    // Get result
    let data_ref = data.borrow();
    if data_ref.cancelled {
        return Err(BitwardenAutofillError::PasswordDialogCancelled);
    }

    data_ref.result.clone().ok_or_else(|| {
        BitwardenAutofillError::PasswordDialogFailed("No result from dialog".to_string())
    })
}

unsafe extern "system" fn login_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            create_login_controls(hwnd);
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            let notification = ((wparam.0 >> 16) & 0xFFFF) as u16;
            
            match id {
                IDC_OK => {
                    if validate_and_save(hwnd) {
                        let _ = DestroyWindow(hwnd);
                    }
                }
                IDC_CANCEL => {
                    DIALOG_DATA.with(|d| {
                        if let Some(data) = d.borrow().as_ref() {
                            data.borrow_mut().cancelled = true;
                        }
                    });
                    let _ = DestroyWindow(hwnd);
                }
                IDC_SERVER_COMBO => {
                    // CBN_SELCHANGE = 1
                    if notification == 1 {
                        update_self_hosted_visibility(hwnd);
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            DIALOG_DATA.with(|d| {
                if let Some(data) = d.borrow().as_ref() {
                    data.borrow_mut().cancelled = true;
                }
            });
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            // Clear the stored HWND
            LOGIN_DIALOG_HWND.with(|h| {
                *h.borrow_mut() = None;
            });
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe fn create_login_controls(hwnd: HWND) {
    let h_instance: windows::Win32::Foundation::HINSTANCE = GetModuleHandleW(None).unwrap_or_default().into();
    let font = GetStockObject(DEFAULT_GUI_FONT);

    // Get saved data for prefilling
    let (saved_server, saved_email, saved_client_id, saved_client_secret, saved_identity, saved_api) = DIALOG_DATA.with(|d| {
        if let Some(data) = d.borrow().as_ref() {
            let data_ref = data.borrow();
            if let Some(saved) = &data_ref.saved {
                let (identity, api) = match &saved.server {
                    ServerRegion::SelfHosted { identity, api } => (identity.clone(), api.clone()),
                    _ => (String::new(), String::new()),
                };
                let server_idx = match &saved.server {
                    ServerRegion::US => 0,
                    ServerRegion::EU => 1,
                    ServerRegion::SelfHosted { .. } => 2,
                };
                return (
                    server_idx,
                    saved.email.clone(),
                    saved.client_id.clone(),
                    saved.client_secret.expose_secret().to_string(),
                    identity,
                    api,
                );
            }
        }
        (0i32, String::new(), String::new(), String::new(), String::new(), String::new())
    });

    let mut y = 15;
    let label_width = 90;
    let control_width = 280;
    let control_height = 24;
    let row_height = 32;
    let left_margin = 15;
    let control_left = left_margin + label_width + 5;

    // Server label and combo
    create_static(hwnd, h_instance, "Server:", left_margin, y + 2, label_width, 20, font);
    let combo = create_combobox(hwnd, h_instance, control_left, y, control_width, 100, IDC_SERVER_COMBO, font);
    
    // Add server options
    let us_text = to_wstring("Bitwarden US");
    let eu_text = to_wstring("Bitwarden EU");
    let self_text = to_wstring("Self-hosted");
    SendMessageW(combo, CB_ADDSTRING, WPARAM(0), LPARAM(us_text.as_ptr() as isize));
    SendMessageW(combo, CB_ADDSTRING, WPARAM(0), LPARAM(eu_text.as_ptr() as isize));
    SendMessageW(combo, CB_ADDSTRING, WPARAM(0), LPARAM(self_text.as_ptr() as isize));
    SendMessageW(combo, CB_SETCURSEL, WPARAM(saved_server as usize), LPARAM(0));

    y += row_height + 5;

    // Self-hosted fields (initially hidden unless self-hosted is selected)
    let identity_label = create_static_with_id(hwnd, h_instance, "Identity URL:", left_margin, y + 2, label_width, 20, IDC_IDENTITY_LABEL, font);
    let identity_edit = create_edit(hwnd, h_instance, control_left, y, control_width, control_height, IDC_IDENTITY_URL, false, font);
    if !saved_identity.is_empty() {
        let text = to_wstring(&saved_identity);
        let _ = SetWindowTextW(identity_edit, PCWSTR::from_raw(text.as_ptr()));
    }
    
    y += row_height;
    
    let api_label = create_static_with_id(hwnd, h_instance, "API URL:", left_margin, y + 2, label_width, 20, IDC_API_LABEL, font);
    let api_edit = create_edit(hwnd, h_instance, control_left, y, control_width, control_height, IDC_API_URL, false, font);
    if !saved_api.is_empty() {
        let text = to_wstring(&saved_api);
        let _ = SetWindowTextW(api_edit, PCWSTR::from_raw(text.as_ptr()));
    }

    // Hide self-hosted fields initially if not self-hosted
    if saved_server != 2 {
        let _ = ShowWindow(identity_label, SW_HIDE);
        let _ = ShowWindow(identity_edit, SW_HIDE);
        let _ = ShowWindow(api_label, SW_HIDE);
        let _ = ShowWindow(api_edit, SW_HIDE);
    }

    y += row_height + 10;

    // Email
    create_static(hwnd, h_instance, "Email:", left_margin, y + 2, label_width, 20, font);
    let email_edit = create_edit(hwnd, h_instance, control_left, y, control_width, control_height, IDC_EMAIL, false, font);
    if !saved_email.is_empty() {
        let text = to_wstring(&saved_email);
        let _ = SetWindowTextW(email_edit, PCWSTR::from_raw(text.as_ptr()));
    }

    y += row_height;

    // Password
    create_static(hwnd, h_instance, "Password:", left_margin, y + 2, label_width, 20, font);
    create_edit(hwnd, h_instance, control_left, y, control_width, control_height, IDC_PASSWORD, true, font);

    y += row_height + 10;

    // Client ID
    create_static(hwnd, h_instance, "Client ID:", left_margin, y + 2, label_width, 20, font);
    let client_id_edit = create_edit(hwnd, h_instance, control_left, y, control_width, control_height, IDC_CLIENT_ID, false, font);
    if !saved_client_id.is_empty() {
        let text = to_wstring(&saved_client_id);
        let _ = SetWindowTextW(client_id_edit, PCWSTR::from_raw(text.as_ptr()));
    }

    y += row_height;

    // Client Secret
    create_static(hwnd, h_instance, "Client Secret:", left_margin, y + 2, label_width, 20, font);
    let client_secret_edit = create_edit(hwnd, h_instance, control_left, y, control_width, control_height, IDC_CLIENT_SECRET, true, font);
    if !saved_client_secret.is_empty() {
        let text = to_wstring("(saved)");
        let _ = SetWindowTextW(client_secret_edit, PCWSTR::from_raw(text.as_ptr()));
    }

    y += row_height + 10;

    // Remember checkbox
    let remember_check = create_checkbox(hwnd, h_instance, "Remember credentials", left_margin, y, 200, 24, IDC_REMEMBER, font);
    if saved_email.is_empty() {
        // Default unchecked for new
    } else {
        SendMessageW(remember_check, BM_SETCHECK, WPARAM(BST_CHECKED as usize), LPARAM(0));
    }

    y += row_height + 15;

    // Buttons
    let button_width = 90;
    let button_height = 28;
    let button_spacing = 10;
    let total_button_width = button_width * 2 + button_spacing;
    let button_left = (420 - total_button_width) / 2 - 10;

    create_button(hwnd, h_instance, "OK", button_left, y, button_width, button_height, IDC_OK, true, font);
    create_button(hwnd, h_instance, "Cancel", button_left + button_width + button_spacing, y, button_width, button_height, IDC_CANCEL, false, font);

    // Set focus to first empty field
    if saved_email.is_empty() {
        let _ = SetFocus(email_edit);
    } else if let Ok(pwd_ctrl) = GetDlgItem(hwnd, IDC_PASSWORD) {
        let _ = SetFocus(pwd_ctrl);
    }
}

unsafe fn create_static(hwnd: HWND, h_instance: windows::Win32::Foundation::HINSTANCE, text: &str, x: i32, y: i32, w: i32, h: i32, font: windows::Win32::Graphics::Gdi::HGDIOBJ) -> HWND {
    let class = w!("STATIC");
    let text_wide = to_wstring(text);
    let ctrl = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        PCWSTR::from_raw(text_wide.as_ptr()),
        WS_CHILD | WS_VISIBLE,
        x, y, w, h,
        hwnd,
        None,
        h_instance,
        None,
    ).unwrap_or_default();
    SendMessageW(ctrl, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    ctrl
}

unsafe fn create_static_with_id(hwnd: HWND, h_instance: windows::Win32::Foundation::HINSTANCE, text: &str, x: i32, y: i32, w: i32, h: i32, id: i32, font: windows::Win32::Graphics::Gdi::HGDIOBJ) -> HWND {
    let class = w!("STATIC");
    let text_wide = to_wstring(text);
    let ctrl = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        PCWSTR::from_raw(text_wide.as_ptr()),
        WS_CHILD | WS_VISIBLE,
        x, y, w, h,
        hwnd,
        HMENU(id as *mut c_void),
        h_instance,
        None,
    ).unwrap_or_default();
    SendMessageW(ctrl, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    ctrl
}

unsafe fn create_edit(hwnd: HWND, h_instance: windows::Win32::Foundation::HINSTANCE, x: i32, y: i32, w: i32, h: i32, id: i32, password: bool, font: windows::Win32::Graphics::Gdi::HGDIOBJ) -> HWND {
    let class = w!("EDIT");
    let mut style_bits = (WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP).0 | ES_AUTOHSCROLL;
    if password {
        style_bits |= ES_PASSWORD;
    }
    let ctrl = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        PCWSTR::null(),
        windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(style_bits),
        x, y, w, h,
        hwnd,
        HMENU(id as *mut c_void),
        h_instance,
        None,
    ).unwrap_or_default();
    SendMessageW(ctrl, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    ctrl
}

unsafe fn create_combobox(hwnd: HWND, h_instance: windows::Win32::Foundation::HINSTANCE, x: i32, y: i32, w: i32, h: i32, id: i32, font: windows::Win32::Graphics::Gdi::HGDIOBJ) -> HWND {
    let class = w!("COMBOBOX");
    let style_bits = (WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL).0 | CBS_DROPDOWNLIST;
    let ctrl = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        PCWSTR::null(),
        windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(style_bits),
        x, y, w, h,
        hwnd,
        HMENU(id as *mut c_void),
        h_instance,
        None,
    ).unwrap_or_default();
    SendMessageW(ctrl, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    ctrl
}

unsafe fn create_checkbox(hwnd: HWND, h_instance: windows::Win32::Foundation::HINSTANCE, text: &str, x: i32, y: i32, w: i32, h: i32, id: i32, font: windows::Win32::Graphics::Gdi::HGDIOBJ) -> HWND {
    let class = w!("BUTTON");
    let text_wide = to_wstring(text);
    let style_bits = (WS_CHILD | WS_VISIBLE | WS_TABSTOP).0 | BS_AUTOCHECKBOX;
    let ctrl = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        PCWSTR::from_raw(text_wide.as_ptr()),
        windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(style_bits),
        x, y, w, h,
        hwnd,
        HMENU(id as *mut c_void),
        h_instance,
        None,
    ).unwrap_or_default();
    SendMessageW(ctrl, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    ctrl
}

unsafe fn create_button(hwnd: HWND, h_instance: windows::Win32::Foundation::HINSTANCE, text: &str, x: i32, y: i32, w: i32, h: i32, id: i32, default: bool, font: windows::Win32::Graphics::Gdi::HGDIOBJ) -> HWND {
    let class = w!("BUTTON");
    let text_wide = to_wstring(text);
    let bs = if default { BS_DEFPUSHBUTTON } else { BS_PUSHBUTTON };
    let style_bits = (WS_CHILD | WS_VISIBLE | WS_TABSTOP).0 | bs;
    let ctrl = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        PCWSTR::from_raw(text_wide.as_ptr()),
        windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(style_bits),
        x, y, w, h,
        hwnd,
        HMENU(id as *mut c_void),
        h_instance,
        None,
    ).unwrap_or_default();
    SendMessageW(ctrl, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    ctrl
}

unsafe fn get_dlg_item(hwnd: HWND, id: i32) -> HWND {
    GetDlgItem(hwnd, id).unwrap_or_default()
}

unsafe fn get_edit_text(hwnd: HWND, id: i32) -> String {
    let ctrl = get_dlg_item(hwnd, id);
    let len = GetWindowTextLengthW(ctrl) as usize;
    if len == 0 {
        return String::new();
    }
    let mut buffer = vec![0u16; len + 1];
    GetWindowTextW(ctrl, &mut buffer);
    from_wstring(&buffer)
}

unsafe fn update_self_hosted_visibility(hwnd: HWND) {
    let combo = get_dlg_item(hwnd, IDC_SERVER_COMBO);
    let selection = SendMessageW(combo, CB_GETCURSEL, WPARAM(0), LPARAM(0)).0 as i32;
    
    let show = if selection == 2 { SW_SHOW } else { SW_HIDE };
    
    let _ = ShowWindow(get_dlg_item(hwnd, IDC_IDENTITY_LABEL), show);
    let _ = ShowWindow(get_dlg_item(hwnd, IDC_IDENTITY_URL), show);
    let _ = ShowWindow(get_dlg_item(hwnd, IDC_API_LABEL), show);
    let _ = ShowWindow(get_dlg_item(hwnd, IDC_API_URL), show);
}

unsafe fn validate_and_save(hwnd: HWND) -> bool {
    let combo = get_dlg_item(hwnd, IDC_SERVER_COMBO);
    let server_idx = SendMessageW(combo, CB_GETCURSEL, WPARAM(0), LPARAM(0)).0 as i32;
    
    let email = get_edit_text(hwnd, IDC_EMAIL).trim().to_string();
    let password = get_edit_text(hwnd, IDC_PASSWORD);
    let client_id = get_edit_text(hwnd, IDC_CLIENT_ID).trim().to_string();
    let client_secret_input = get_edit_text(hwnd, IDC_CLIENT_SECRET);
    
    // Validation
    if email.is_empty() {
        show_error("Validation Error", "Email is required");
        let _ = SetFocus(get_dlg_item(hwnd, IDC_EMAIL));
        return false;
    }
    
    if password.is_empty() {
        show_error("Validation Error", "Password is required");
        let _ = SetFocus(get_dlg_item(hwnd, IDC_PASSWORD));
        return false;
    }
    
    if client_id.is_empty() {
        show_error("Validation Error", "Client ID is required");
        let _ = SetFocus(get_dlg_item(hwnd, IDC_CLIENT_ID));
        return false;
    }
    
    // Handle client secret - if "(saved)" is entered, use the saved value
    let client_secret_value = DIALOG_DATA.with(|d| {
        if client_secret_input.trim() == "(saved)" || client_secret_input.is_empty() {
            if let Some(data) = d.borrow().as_ref() {
                if let Some(saved) = &data.borrow().saved {
                    return saved.client_secret.expose_secret().to_string();
                }
            }
        }
        client_secret_input.trim().to_string()
    });
    
    if client_secret_value.is_empty() {
        show_error("Validation Error", "Client Secret is required");
        let _ = SetFocus(get_dlg_item(hwnd, IDC_CLIENT_SECRET));
        return false;
    }
    
    // Get server region
    let server = match server_idx {
        0 => ServerRegion::US,
        1 => ServerRegion::EU,
        2 => {
            let identity = get_edit_text(hwnd, IDC_IDENTITY_URL).trim().to_string();
            let api = get_edit_text(hwnd, IDC_API_URL).trim().to_string();
            
            if identity.is_empty() {
                show_error("Validation Error", "Identity URL is required for self-hosted");
                let _ = SetFocus(get_dlg_item(hwnd, IDC_IDENTITY_URL));
                return false;
            }
            if api.is_empty() {
                show_error("Validation Error", "API URL is required for self-hosted");
                let _ = SetFocus(get_dlg_item(hwnd, IDC_API_URL));
                return false;
            }
            
            ServerRegion::SelfHosted { identity, api }
        }
        _ => ServerRegion::US,
    };
    
    // Get remember checkbox state
    let remember_ctrl = get_dlg_item(hwnd, IDC_REMEMBER);
    let remember = SendMessageW(remember_ctrl, BM_GETCHECK, WPARAM(0), LPARAM(0)).0 == BST_CHECKED as isize;
    
    // Save result
    DIALOG_DATA.with(|d| {
        if let Some(data) = d.borrow().as_ref() {
            data.borrow_mut().result = Some(LoginInput {
                server,
                email,
                password: SecretString::new(password.into()),
                client_id,
                client_secret: SecretString::new(client_secret_value.into()),
                remember,
            });
        }
    });
    
    true
}

pub fn prompt_server_region(saved: Option<&ServerRegion>) -> Result<ServerRegion> {
    let button_texts = [
        to_wstring("Bitwarden US"),
        to_wstring("Bitwarden EU"),
        to_wstring("Self-hosted"),
    ];

    let buttons = [
        TASKDIALOG_BUTTON {
            nButtonID: 100,
            pszButtonText: PCWSTR::from_raw(button_texts[0].as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: 101,
            pszButtonText: PCWSTR::from_raw(button_texts[1].as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: 102,
            pszButtonText: PCWSTR::from_raw(button_texts[2].as_ptr()),
        },
    ];

    let title = to_wstring("Bitwarden Login");
    let instruction = to_wstring("Select your Bitwarden server");
    let content = to_wstring("Choose where your vault is hosted:");

    let mut config = TASKDIALOGCONFIG::default();
    config.cbSize = std::mem::size_of::<TASKDIALOGCONFIG>() as u32;
    config.hwndParent = unsafe { GetForegroundWindow() };
    config.dwFlags = TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION;
    config.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    config.pszWindowTitle = PCWSTR::from_raw(title.as_ptr());
    config.pszMainInstruction = PCWSTR::from_raw(instruction.as_ptr());
    config.pszContent = PCWSTR::from_raw(content.as_ptr());
    config.Anonymous1.pszMainIcon = TD_INFORMATION_ICON;
    config.cButtons = buttons.len() as u32;
    config.pButtons = buttons.as_ptr();
    config.nDefaultButton = match saved {
        Some(ServerRegion::EU) => 101,
        Some(ServerRegion::SelfHosted { .. }) => 102,
        _ => 100,
    };

    let mut selected_button = 0;

    let result = unsafe { TaskDialogIndirect(&config, Some(&mut selected_button), None, None) };

    if result.is_err() {
        return Err(BitwardenAutofillError::PasswordDialogFailed(
            "TaskDialog failed".to_string(),
        ));
    }

    match selected_button {
        100 => Ok(ServerRegion::US),
        101 => Ok(ServerRegion::EU),
        102 => prompt_self_hosted_server(saved),
        _ => Err(BitwardenAutofillError::PasswordDialogCancelled),
    }
}

#[derive(Clone)]
pub struct LoginInput {
    pub server: ServerRegion,
    pub email: String,
    pub password: SecretString,
    pub client_id: String,
    pub client_secret: SecretString,
    pub remember: bool,
}

pub fn prompt_login(saved: Option<&SavedLogin>) -> Result<LoginInput> {
    prompt_login_unified(saved)
}

// Settings dialog control IDs
const IDC_SETTINGS_CLEAR_CREDS: i32 = 2001;
const IDC_SETTINGS_CLOSE: i32 = 2002;
const IDC_SETTINGS_CTRL: i32 = 2003;
const IDC_SETTINGS_ALT: i32 = 2004;
const IDC_SETTINGS_SHIFT: i32 = 2005;
const IDC_SETTINGS_KEY_COMBO: i32 = 2006;
const IDC_SETTINGS_SAVE_HOTKEY: i32 = 2007;
const IDC_SETTINGS_SYNC: i32 = 2008;
const IDC_SETTINGS_STARTUP: i32 = 2009;

use crate::config::{load_config, save_config, set_startup_enabled, is_startup_enabled, HotkeyConfig, AVAILABLE_KEYS};

// Settings dialog result
#[derive(Clone, Default)]
pub struct SettingsResult {
    pub clear_credentials: bool,
    pub hotkey_changed: bool,
    pub new_hotkey: Option<HotkeyConfig>,
    pub sync_vault: bool,
}

thread_local! {
    static SETTINGS_DATA: RefCell<Option<Rc<RefCell<SettingsDialogData>>>> = const { RefCell::new(None) };
}

struct SettingsDialogData {
    result: SettingsResult,
    current_hotkey: HotkeyConfig,
}

/// Show settings dialog
pub fn show_settings_dialog() -> Result<SettingsResult> {
    let current_hotkey = load_config()
        .map(|c| c.hotkey)
        .unwrap_or_default();

    let data = Rc::new(RefCell::new(SettingsDialogData {
        result: SettingsResult::default(),
        current_hotkey,
    }));

    SETTINGS_DATA.with(|d| {
        *d.borrow_mut() = Some(Rc::clone(&data));
    });

    // Register window class
    let class_name = w!("BitwardenSettingsDialog");
    let h_instance = unsafe { GetModuleHandleW(None).unwrap_or_default() };

    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(settings_dialog_proc),
        hInstance: h_instance.into(),
        lpszClassName: class_name,
        hCursor: unsafe { windows::Win32::UI::WindowsAndMessaging::LoadCursorW(None, IDC_ARROW).unwrap_or_default() },
        hbrBackground: unsafe { windows::Win32::Graphics::Gdi::GetSysColorBrush(windows::Win32::Graphics::Gdi::COLOR_3DFACE) },
        ..Default::default()
    };

    unsafe { RegisterClassExW(&wc) };

    let title = to_wstring("Settings");
    let hwnd = unsafe {
        CreateWindowExW(
            windows::Win32::UI::WindowsAndMessaging::WS_EX_APPWINDOW,
            class_name,
            PCWSTR::from_raw(title.as_ptr()),
            WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_BORDER,
            CW_USEDEFAULT, CW_USEDEFAULT,
            380, 460,
            None,
            None,
            h_instance,
            None,
        )
    };

    let hwnd = match hwnd {
        Ok(h) if !h.is_invalid() => h,
        _ => {
            return Err(BitwardenAutofillError::PasswordDialogFailed(
                "Failed to create settings dialog".to_string(),
            ));
        }
    };

    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        let _ = SetActiveWindow(hwnd);
    }

    // Message loop
    let mut msg = MSG::default();
    unsafe {
        while windows::Win32::UI::WindowsAndMessaging::GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if !IsDialogMessageW(hwnd, &msg).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    let result = data.borrow().result.clone();
    Ok(result)
}

unsafe extern "system" fn settings_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            create_settings_controls(hwnd);
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            
            match id {
                IDC_SETTINGS_CLEAR_CREDS => {
                    // Set the clear credentials flag
                    SETTINGS_DATA.with(|d| {
                        if let Some(data) = d.borrow().as_ref() {
                            data.borrow_mut().result.clear_credentials = true;
                        }
                    });
                    // Show confirmation
                    show_info("Credentials Cleared", "Saved credentials have been cleared.\nYou will need to log in again next time.");
                }
                IDC_SETTINGS_SAVE_HOTKEY => {
                    save_hotkey_from_dialog(hwnd);
                }
                IDC_SETTINGS_SYNC => {
                    // Set the sync flag and close dialog
                    SETTINGS_DATA.with(|d| {
                        if let Some(data) = d.borrow().as_ref() {
                            data.borrow_mut().result.sync_vault = true;
                        }
                    });
                    let _ = DestroyWindow(hwnd);
                }
                IDC_SETTINGS_STARTUP => {
                    // Toggle startup setting
                    let startup_cb = get_dlg_item(hwnd, IDC_SETTINGS_STARTUP);
                    let is_checked = SendMessageW(startup_cb, BM_GETCHECK, WPARAM(0), LPARAM(0)).0 == BST_CHECKED as isize;
                    
                    // Save to config and registry
                    if let Ok(mut config) = load_config() {
                        config.start_with_windows = is_checked;
                        let _ = save_config(&config);
                        let _ = set_startup_enabled(is_checked);
                    }
                }
                IDC_SETTINGS_CLOSE => {
                    let _ = DestroyWindow(hwnd);
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe fn save_hotkey_from_dialog(hwnd: HWND) {
    // Get modifier states
    let ctrl_checked = SendMessageW(get_dlg_item(hwnd, IDC_SETTINGS_CTRL), BM_GETCHECK, WPARAM(0), LPARAM(0)).0 == BST_CHECKED as isize;
    let alt_checked = SendMessageW(get_dlg_item(hwnd, IDC_SETTINGS_ALT), BM_GETCHECK, WPARAM(0), LPARAM(0)).0 == BST_CHECKED as isize;
    let shift_checked = SendMessageW(get_dlg_item(hwnd, IDC_SETTINGS_SHIFT), BM_GETCHECK, WPARAM(0), LPARAM(0)).0 == BST_CHECKED as isize;
    
    // Get selected key
    let combo = get_dlg_item(hwnd, IDC_SETTINGS_KEY_COMBO);
    let selection = SendMessageW(combo, CB_GETCURSEL, WPARAM(0), LPARAM(0)).0 as usize;
    let key = if selection < AVAILABLE_KEYS.len() {
        AVAILABLE_KEYS[selection].to_string()
    } else {
        "P".to_string()
    };
    
    // Build modifiers list
    let mut modifiers = Vec::new();
    if ctrl_checked {
        modifiers.push("ctrl".to_string());
    }
    if alt_checked {
        modifiers.push("alt".to_string());
    }
    if shift_checked {
        modifiers.push("shift".to_string());
    }
    
    // Validate - need at least one modifier
    if modifiers.is_empty() {
        show_error("Invalid Hotkey", "Please select at least one modifier key (Ctrl, Alt, or Shift).");
        return;
    }
    
    let new_hotkey = HotkeyConfig { modifiers, key };
    
    // Save to config
    if let Ok(mut config) = load_config() {
        config.hotkey = new_hotkey.clone();
        if save_config(&config).is_ok() {
            SETTINGS_DATA.with(|d| {
                if let Some(data) = d.borrow().as_ref() {
                    let mut data = data.borrow_mut();
                    data.result.hotkey_changed = true;
                    data.result.new_hotkey = Some(new_hotkey.clone());
                }
            });
            show_info("Hotkey Saved", &format!("New hotkey: {}\n\nRestart the application for the change to take effect.", new_hotkey.display_string()));
        } else {
            show_error("Error", "Failed to save hotkey configuration.");
        }
    }
}

unsafe fn create_settings_controls(hwnd: HWND) {
    let h_instance: windows::Win32::Foundation::HINSTANCE = GetModuleHandleW(None).unwrap_or_default().into();
    let font = GetStockObject(DEFAULT_GUI_FONT);

    // Get current hotkey config
    let current_hotkey = SETTINGS_DATA.with(|d| {
        d.borrow().as_ref().map(|data| data.borrow().current_hotkey.clone())
    }).unwrap_or_default();

    let left_margin = 20;
    let mut y = 15;

    // Title/Version
    let version = env!("CARGO_PKG_VERSION");
    let version_text = format!("Bitwarden Desktop Autofill v{}", version);
    create_static(hwnd, h_instance, &version_text, left_margin, y, 300, 20, font);
    
    y += 35;

    // Credentials section
    create_static(hwnd, h_instance, "Credentials", left_margin, y, 300, 18, font);
    y += 25;
    create_button(hwnd, h_instance, "Clear Saved Credentials", left_margin, y, 180, 26, IDC_SETTINGS_CLEAR_CREDS, false, font);
    
    y += 45;
    
    // Hotkey section
    create_static(hwnd, h_instance, "Hotkey", left_margin, y, 300, 18, font);
    y += 25;
    
    // Current hotkey display
    let current_text = format!("Current: {}", current_hotkey.display_string());
    create_static(hwnd, h_instance, &current_text, left_margin, y, 200, 20, font);
    y += 28;
    
    // Modifiers label
    create_static(hwnd, h_instance, "Modifiers:", left_margin, y + 2, 60, 20, font);
    
    // Modifier checkboxes
    let ctrl_cb = create_checkbox(hwnd, h_instance, "Ctrl", left_margin + 65, y, 50, 22, IDC_SETTINGS_CTRL, font);
    let alt_cb = create_checkbox(hwnd, h_instance, "Alt", left_margin + 120, y, 45, 22, IDC_SETTINGS_ALT, font);
    let shift_cb = create_checkbox(hwnd, h_instance, "Shift", left_margin + 170, y, 55, 22, IDC_SETTINGS_SHIFT, font);
    
    // Set current modifier states
    if current_hotkey.modifiers.contains(&"ctrl".to_string()) {
        SendMessageW(ctrl_cb, BM_SETCHECK, WPARAM(BST_CHECKED as usize), LPARAM(0));
    }
    if current_hotkey.modifiers.contains(&"alt".to_string()) {
        SendMessageW(alt_cb, BM_SETCHECK, WPARAM(BST_CHECKED as usize), LPARAM(0));
    }
    if current_hotkey.modifiers.contains(&"shift".to_string()) {
        SendMessageW(shift_cb, BM_SETCHECK, WPARAM(BST_CHECKED as usize), LPARAM(0));
    }
    
    y += 30;
    
    // Key selection
    create_static(hwnd, h_instance, "Key:", left_margin, y + 2, 60, 20, font);
    let key_combo = create_combobox(hwnd, h_instance, left_margin + 65, y, 70, 200, IDC_SETTINGS_KEY_COMBO, font);
    
    // Add available keys
    let mut selected_idx = 15; // Default to 'P' (index 15)
    for (idx, key) in AVAILABLE_KEYS.iter().enumerate() {
        let key_w = to_wstring(key);
        SendMessageW(key_combo, CB_ADDSTRING, WPARAM(0), LPARAM(key_w.as_ptr() as isize));
        if *key == current_hotkey.key {
            selected_idx = idx;
        }
    }
    SendMessageW(key_combo, CB_SETCURSEL, WPARAM(selected_idx), LPARAM(0));
    
    // Save hotkey button
    create_button(hwnd, h_instance, "Save Hotkey", left_margin + 150, y - 2, 100, 26, IDC_SETTINGS_SAVE_HOTKEY, false, font);
    
    y += 45;
    
    // Vault section
    create_static(hwnd, h_instance, "Vault", left_margin, y, 300, 18, font);
    y += 25;
    create_button(hwnd, h_instance, "Sync Vault", left_margin, y, 100, 26, IDC_SETTINGS_SYNC, false, font);
    
    y += 45;
    
    // General section
    create_static(hwnd, h_instance, "General", left_margin, y, 300, 18, font);
    y += 25;
    let startup_cb = create_checkbox(hwnd, h_instance, "Start with Windows", left_margin, y, 160, 22, IDC_SETTINGS_STARTUP, font);
    
    // Set current startup state
    if is_startup_enabled() {
        SendMessageW(startup_cb, BM_SETCHECK, WPARAM(BST_CHECKED as usize), LPARAM(0));
    }
    
    y += 45;

    // Close button
    let button_width = 80;
    let button_left = (350 - button_width) / 2 - 10;
    create_button(hwnd, h_instance, "Close", button_left, y, button_width, 28, IDC_SETTINGS_CLOSE, true, font);
}

pub fn show_info(title: &str, message: &str) {
    unsafe {
        MessageBoxW(
            HWND::default(),
            PCWSTR::from_raw(to_wstring(message).as_ptr()),
            PCWSTR::from_raw(to_wstring(title).as_ptr()),
            MB_OK | MB_SYSTEMMODAL,
        );
    }
}

// No credentials dialog control IDs
const IDC_NOCREDS_COPY: i32 = 3001;
const IDC_NOCREDS_CLOSE: i32 = 3002;
const IDC_NOCREDS_OPEN_VAULT: i32 = 3003;
const IDC_NOCREDS_SYNC: i32 = 3004;

thread_local! {
    static NOCREDS_APP_NAME: RefCell<String> = const { RefCell::new(String::new()) };
    static NOCREDS_VAULT_URL: RefCell<String> = const { RefCell::new(String::new()) };
    static NOCREDS_SYNC_REQUESTED: RefCell<bool> = const { RefCell::new(false) };
}

/// Show a helpful dialog when no credentials are found for an app
/// Returns true if the user requested a sync
pub fn show_no_credentials_found(app_name: &str, server_region: Option<&ServerRegion>) -> bool {
    NOCREDS_APP_NAME.with(|n| {
        *n.borrow_mut() = app_name.to_string();
    });
    
    // Reset sync requested flag
    NOCREDS_SYNC_REQUESTED.with(|s| {
        *s.borrow_mut() = false;
    });
    
    // Determine vault URL based on server region
    let vault_url = match server_region {
        Some(ServerRegion::EU) => "https://vault.bitwarden.eu",
        Some(ServerRegion::SelfHosted { .. }) => "", // No web vault for self-hosted
        _ => "https://vault.bitwarden.com", // Default to US
    };
    NOCREDS_VAULT_URL.with(|u| {
        *u.borrow_mut() = vault_url.to_string();
    });

    // Register window class
    let class_name = w!("BitwardenNoCredsDialog");
    let h_instance = unsafe { GetModuleHandleW(None).unwrap_or_default() };

    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(nocreds_dialog_proc),
        hInstance: h_instance.into(),
        lpszClassName: class_name,
        hCursor: unsafe { windows::Win32::UI::WindowsAndMessaging::LoadCursorW(None, IDC_ARROW).unwrap_or_default() },
        hbrBackground: unsafe { windows::Win32::Graphics::Gdi::GetSysColorBrush(windows::Win32::Graphics::Gdi::COLOR_3DFACE) },
        ..Default::default()
    };

    unsafe { RegisterClassExW(&wc) };

    let title = to_wstring("No Credentials Found");
    let hwnd = unsafe {
        CreateWindowExW(
            windows::Win32::UI::WindowsAndMessaging::WS_EX_APPWINDOW,
            class_name,
            PCWSTR::from_raw(title.as_ptr()),
            WS_CAPTION | WS_SYSMENU | WS_BORDER,
            CW_USEDEFAULT, CW_USEDEFAULT,
            450, 470,
            None,
            None,
            h_instance,
            None,
        )
    };

    let hwnd = match hwnd {
        Ok(h) if !h.is_invalid() => h,
        _ => return false,
    };

    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        let _ = SetActiveWindow(hwnd);
    }

    // Message loop
    let mut msg = MSG::default();
    unsafe {
        while windows::Win32::UI::WindowsAndMessaging::GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if !IsDialogMessageW(hwnd, &msg).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    
    // Return whether sync was requested
    NOCREDS_SYNC_REQUESTED.with(|s| *s.borrow())
}

const WM_TIMER: u32 = 0x0113;
const TIMER_RESET_COPY_BTN: usize = 1;

unsafe extern "system" fn nocreds_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            create_nocreds_controls(hwnd);
            LRESULT(0)
        }
        WM_TIMER => {
            if wparam.0 == TIMER_RESET_COPY_BTN {
                // Kill the timer
                let _ = windows::Win32::UI::WindowsAndMessaging::KillTimer(
                    hwnd,
                    TIMER_RESET_COPY_BTN,
                );
                // Reset button text
                let copy_btn = get_dlg_item(hwnd, IDC_NOCREDS_COPY);
                let original_text = to_wstring("Copy App Name");
                let _ = SetWindowTextW(copy_btn, PCWSTR::from_raw(original_text.as_ptr()));
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            match id {
                IDC_NOCREDS_COPY => {
                    // Copy app name to clipboard
                    NOCREDS_APP_NAME.with(|n| {
                        let name = n.borrow().clone();
                        copy_to_clipboard(&name);
                    });
                    // Change button text to "Copied!" temporarily
                    let copy_btn = get_dlg_item(hwnd, IDC_NOCREDS_COPY);
                    let copied_text = to_wstring("Copied!");
                    let _ = SetWindowTextW(copy_btn, PCWSTR::from_raw(copied_text.as_ptr()));
                    // Set a timer to reset the button text after 1.5 seconds
                    windows::Win32::UI::WindowsAndMessaging::SetTimer(hwnd, TIMER_RESET_COPY_BTN, 1500, None);
                }
                IDC_NOCREDS_OPEN_VAULT => {
                    // Open web vault in browser
                    NOCREDS_VAULT_URL.with(|u| {
                        let url = u.borrow().clone();
                        if !url.is_empty() {
                            let _ = open_url(&url);
                        }
                    });
                }
                IDC_NOCREDS_SYNC => {
                    // Set sync requested flag and close
                    NOCREDS_SYNC_REQUESTED.with(|s| {
                        *s.borrow_mut() = true;
                    });
                    let _ = DestroyWindow(hwnd);
                }
                IDC_NOCREDS_CLOSE => {
                    let _ = DestroyWindow(hwnd);
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn open_url(url: &str) -> std::io::Result<()> {
    std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn()?;
    Ok(())
}

unsafe fn create_nocreds_controls(hwnd: HWND) {
    let h_instance: windows::Win32::Foundation::HINSTANCE = GetModuleHandleW(None).unwrap_or_default().into();
    let font = GetStockObject(DEFAULT_GUI_FONT);

    let app_name = NOCREDS_APP_NAME.with(|n| n.borrow().clone());
    let vault_url = NOCREDS_VAULT_URL.with(|u| u.borrow().clone());

    let left_margin = 20;
    let mut y = 15;

    // Title
    let title_text = format!("No credentials found for \"{}\"", app_name);
    create_static(hwnd, h_instance, &title_text, left_margin, y, 400, 20, font);
    
    y += 35;

    // Instructions
    let instructions = "If you have credentials for this app in your vault, you can \
help Bitwarden find them:";
    create_static(hwnd, h_instance, instructions, left_margin, y, 400, 35, font);
    
    y += 45;

    create_static(hwnd, h_instance, "1. Open Bitwarden app or browser extension", left_margin, y, 400, 18, font);
    y += 22;
    create_static(hwnd, h_instance, "2. Edit the credential you want to use", left_margin, y, 400, 18, font);
    y += 22;
    create_static(hwnd, h_instance, "3. Scroll to \"Autofill options\"", left_margin, y, 400, 18, font);
    y += 22;
    create_static(hwnd, h_instance, "4. Click \"Add website\"", left_margin, y, 400, 18, font);
    y += 22;
    let step5 = format!("5. Paste \"{}\" and save", app_name);
    create_static(hwnd, h_instance, &step5, left_margin, y, 400, 18, font);
    y += 22;
    create_static(hwnd, h_instance, "6. Sync your vault (button below)", left_margin, y, 400, 18, font);
    
    y += 35;

    // Copy button
    create_button(hwnd, h_instance, "Copy App Name", left_margin, y, 130, 28, IDC_NOCREDS_COPY, false, font);
    
    // Open Vault button (only if we have a vault URL)
    if !vault_url.is_empty() {
        create_button(hwnd, h_instance, "Open Web Vault", left_margin + 145, y, 130, 28, IDC_NOCREDS_OPEN_VAULT, false, font);
        
        y += 35;
        // Show vault URL
        create_static(hwnd, h_instance, &vault_url, left_margin, y, 400, 18, font);
    }
    
    y += 40;
    
    // Sync note and button
    create_static(hwnd, h_instance, "After updating, sync to get the changes:", left_margin, y, 300, 18, font);
    create_button(hwnd, h_instance, "Sync Vault", left_margin + 270, y - 3, 100, 26, IDC_NOCREDS_SYNC, false, font);
    
    y += 45;

    // Close button
    create_button(hwnd, h_instance, "Close", 175, y, 80, 28, IDC_NOCREDS_CLOSE, true, font);
}

fn copy_to_clipboard(text: &str) {
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    unsafe {
        if OpenClipboard(None).is_err() {
            return;
        }

        let _ = EmptyClipboard();

        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let size = wide.len() * 2;

        if let Ok(hmem) = GlobalAlloc(GMEM_MOVEABLE, size) {
            let ptr = GlobalLock(hmem);
            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr as *mut u16, wide.len());
                GlobalUnlock(hmem).ok();
                let _ = SetClipboardData(CF_UNICODETEXT.0 as u32, windows::Win32::Foundation::HANDLE(hmem.0));
            }
        }

        let _ = CloseClipboard();
    }
}

fn prompt_self_hosted_server(saved: Option<&ServerRegion>) -> Result<ServerRegion> {
    let (identity_hint, api_hint) = match saved {
        Some(ServerRegion::SelfHosted { identity, api }) => (identity.as_str(), api.as_str()),
        _ => ("", ""),
    };

    let identity = prompt_generic_input_prefill(
        "Self-hosted Identity URL",
        "Enter your Bitwarden Identity URL (e.g. https://bw.example.com/identity)",
        "Identity URL",
        identity_hint,
    )?;

    let identity_value = identity.trim().to_string();

    let api = prompt_generic_input_prefill(
        "Self-hosted API URL",
        "Enter your Bitwarden API URL (e.g. https://bw.example.com/api)",
        "API URL",
        api_hint,
    )?;

    let api_value = api.trim().to_string();

    Ok(ServerRegion::SelfHosted {
        identity: identity_value,
        api: api_value,
    })
}

fn prompt_credentials_with_prefill(
    title: &str,
    message: &str,
    username_prefill: &str,
) -> Result<(String, SecretString)> {
    let (username, password, _) =
        prompt_credentials_with_prefill_save(title, message, username_prefill, false, false)?;
    Ok((username, password))
}

fn prompt_credentials_with_prefill_save(
    title: &str,
    message: &str,
    username_prefill: &str,
    show_save_checkbox: bool,
    default_save: bool,
) -> Result<(String, SecretString, bool)> {
    let mut cred_info = CREDUI_INFOW::default();
    cred_info.cbSize = std::mem::size_of::<CREDUI_INFOW>() as u32;
    cred_info.pszCaptionText = PCWSTR::from_raw(to_wstring(title).as_ptr());
    cred_info.pszMessageText = PCWSTR::from_raw(to_wstring(message).as_ptr());

    let mut auth_package: u32 = 0;
    let mut out_cred_buffer: *mut c_void = std::ptr::null_mut();
    let mut out_cred_size: u32 = 0;
    let mut save: BOOL = if default_save { BOOL(1) } else { BOOL(0) };

    let mut flags = CREDUIWIN_GENERIC;
    if show_save_checkbox {
        flags |= CREDUIWIN_CHECKBOX;
    } else {
        save = BOOL(0);
    }

    let mut packed: Vec<u8> = Vec::new();
    let mut packed_size: u32 = 0;
    if !username_prefill.is_empty() {
        let username_wide = to_wstring(username_prefill);
        unsafe {
            let _ = CredPackAuthenticationBufferW(
                CRED_PACK_FLAGS(0),
                PCWSTR::from_raw(username_wide.as_ptr()),
                PCWSTR::null(),
                None,
                &mut packed_size,
            );
        }
        let last_error = unsafe { GetLastError() };
        if last_error == ERROR_INSUFFICIENT_BUFFER {
            packed = vec![0u8; packed_size as usize];
            let pack_ok = unsafe {
                CredPackAuthenticationBufferW(
                    CRED_PACK_FLAGS(0),
                    PCWSTR::from_raw(username_wide.as_ptr()),
                    PCWSTR::null(),
                    Some(packed.as_mut_ptr()),
                    &mut packed_size,
                )
            };
            if pack_ok.is_err() {
                packed.clear();
                packed_size = 0;
            }
        }
    }

    let co_error = unsafe {
        CredUIPromptForWindowsCredentialsW(
            Some(&cred_info),
            0,
            &mut auth_package,
            if packed.is_empty() {
                None
            } else {
                Some(packed.as_ptr() as *const _)
            },
            packed_size,
            &mut out_cred_buffer,
            &mut out_cred_size,
            Some(&mut save),
            flags,
        )
    };

    if co_error != 0 {
        if co_error == 1223 {
            return Err(BitwardenAutofillError::PasswordDialogCancelled);
        }
        return Err(BitwardenAutofillError::PasswordDialogFailed(format!(
            "Error code: {}",
            co_error
        )));
    }

    let mut username_out = [0u16; 512];
    let mut password_out = [0u16; 512];
    let mut domain_out = [0u16; 512];

    let mut username_len = username_out.len() as u32;
    let mut password_len = password_out.len() as u32;
    let mut domain_len = domain_out.len() as u32;

    let unpack_result = unsafe {
        CredUnPackAuthenticationBufferW(
            CRED_PACK_FLAGS(0),
            out_cred_buffer as *const _,
            out_cred_size,
            PWSTR(username_out.as_mut_ptr()),
            &mut username_len,
            PWSTR(domain_out.as_mut_ptr()),
            Some(&mut domain_len),
            PWSTR(password_out.as_mut_ptr()),
            &mut password_len,
        )
    };

    unsafe {
        CoTaskMemFree(Some(out_cred_buffer as *const _));
    }

    unpack_result.map_err(|_| {
        BitwardenAutofillError::PasswordDialogFailed("Failed to unpack credentials".to_string())
    })?;

    let username = String::from_utf16_lossy(&username_out[..username_len as usize]);
    let password = String::from_utf16_lossy(&password_out[..password_len as usize]);

    Ok((username, SecretString::new(password.into()), save.as_bool()))
}

pub fn prompt_credentials(title: &str, message: &str) -> Result<(String, SecretString)> {
    prompt_credentials_with_prefill(title, message, "")
}

pub fn prompt_generic_input(
    title: &str,
    message: &str,
) -> Result<(String, SecretString)> {
    prompt_credentials(title, message)
}

fn prompt_generic_input_prefill(
    title: &str,
    message: &str,
    field_label: &str,
    prefill: &str,
) -> Result<String> {
    let (value, _) = prompt_credentials_with_prefill(title, message, prefill)?;
    if value.trim().is_empty() {
        return Err(BitwardenAutofillError::PasswordDialogFailed(format!(
            "{} is required",
            field_label
        )));
    }
    Ok(value)
}

pub fn show_error(title: &str, message: &str) {
    unsafe {
        MessageBoxW(
            HWND::default(),
            PCWSTR::from_raw(to_wstring(message).as_ptr()),
            PCWSTR::from_raw(to_wstring(title).as_ptr()),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL,
        );
    }
}

/// Prompt user to select from multiple accounts
///
/// Shows a TaskDialog with command links for each account.
/// Returns the index of the selected account, or None if cancelled.
///
/// # Arguments
/// * `app_name` - The name of the application (shown in dialog title)
/// * `accounts` - List of (name, username) tuples to display
///
/// # Returns
/// * `Ok(Some(index))` - User selected the account at this index
/// * `Ok(None)` - User cancelled the dialog
/// * `Err(_)` - Dialog failed to show
pub fn prompt_account_selection(
    app_name: &str,
    accounts: &[(String, Option<String>)],
) -> Result<Option<usize>> {
    if accounts.is_empty() {
        return Ok(None);
    }

    if accounts.len() == 1 {
        return Ok(Some(0));
    }

    // Build the command link buttons
    // Each button has ID starting from 100
    let base_button_id: i32 = 100;

    // Create button text strings - need to keep them alive
    let button_texts: Vec<Vec<u16>> = accounts
        .iter()
        .map(|(name, username)| {
            let display = match username {
                Some(u) if !u.is_empty() => format!("{}\n{}", name, u),
                _ => name.clone(),
            };
            to_wstring(&display)
        })
        .collect();

    // Create button structs
    let buttons: Vec<TASKDIALOG_BUTTON> = button_texts
        .iter()
        .enumerate()
        .map(|(i, text)| TASKDIALOG_BUTTON {
            nButtonID: base_button_id + i as i32,
            pszButtonText: PCWSTR::from_raw(text.as_ptr()),
        })
        .collect();

    // Create title and content strings
    let title = to_wstring(&format!("Select Account for {}", app_name));
    let main_instruction = to_wstring("Multiple accounts found");
    let content = to_wstring("Choose which account to use:");

    // Get the foreground window to parent the dialog to it
    // This ensures the dialog appears on the same monitor as the target window
    let parent_hwnd = unsafe { GetForegroundWindow() };

    // Configure the task dialog
    let mut config = TASKDIALOGCONFIG::default();
    config.cbSize = std::mem::size_of::<TASKDIALOGCONFIG>() as u32;
    config.hwndParent = parent_hwnd;
    config.dwFlags = TDF_USE_COMMAND_LINKS;
    config.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    config.pszWindowTitle = PCWSTR::from_raw(title.as_ptr());
    config.pszMainInstruction = PCWSTR::from_raw(main_instruction.as_ptr());
    config.pszContent = PCWSTR::from_raw(content.as_ptr());
    config.Anonymous1.pszMainIcon = TD_INFORMATION_ICON;
    config.cButtons = buttons.len() as u32;
    config.pButtons = buttons.as_ptr();

    let mut selected_button: i32 = 0;

    let result = unsafe {
        TaskDialogIndirect(
            &config,
            Some(&mut selected_button),
            None, // No radio button result needed
            None, // No verification checkbox
        )
    };

    if result.is_err() {
        return Err(BitwardenAutofillError::PasswordDialogFailed(
            "TaskDialog failed".to_string(),
        ));
    }

    // Check if user cancelled
    if selected_button == IDCANCEL.0 {
        return Ok(None);
    }

    // Calculate which account was selected
    let selected_index = (selected_button - base_button_id) as usize;

    if selected_index < accounts.len() {
        Ok(Some(selected_index))
    } else {
        Ok(None)
    }
}
