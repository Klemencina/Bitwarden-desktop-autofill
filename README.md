# Bitwarden Desktop Autofill

A Windows autofill addon for Bitwarden that automatically fills credentials in native desktop applications using Microsoft UI Automation. This is not a password manager itself — it connects to your existing Bitwarden vault to provide autofill functionality.

## Features

- **Secure Autofill**: Press `Ctrl+Alt+P` (customizable) to autofill credentials into the focused field
- **Smart Field Detection**: Automatically detects login forms and fills both username and password
- **Native Integration**: Uses Windows UI Automation for reliable field detection
- **Memory Safety**: All passwords are wrapped in `SecretString` and zeroized after use
- **No Clipboard**: Uses `SendInput` keystroke injection to avoid clipboard history
- **System Tray**: Background operation with lock/unlock status indicator
- **Direct API Access**: Connects directly to Bitwarden servers (no CLI required)
- **Credential Storage**: Optionally save API credentials in Windows Credential Manager

## Prerequisites

1. **Windows 10/11** (required for UI Automation)
2. **Bitwarden Account** with a [Personal API Key](https://bitwarden.com/help/personal-api-key/)
   - Go to your Bitwarden Web Vault → Account Settings → Security → Keys → API Key
   - Note your `client_id` and `client_secret`

## Installation

### From Source

```powershell
# Clone the repository
git clone https://github.com/Klemencina/Bitwarden-desktop-autofill.git
cd Bitwarden-desktop-autofill

# Build release version
cargo build --release

# Run
.\target\release\bitwarden-desktop-autofill.exe
```

### Windows Installer (Inno Setup)

This project includes an Inno Setup script to build a full installer.

1. Install Inno Setup 6.x: https://jrsoftware.org/isinfo.php
2. Build the release binary:

```powershell
cargo build --release
```

3. Build the installer (run from the repo root):

```powershell
iscc .\installer\bitwarden-desktop-autofill.iss
```

The installer will be written to `installer\output\Bitwarden-Desktop-Autofill-Setup.exe`.

## Usage

1. **Start the app** - It will appear in your system tray
2. **Login** - Enter your email, master password, and API key credentials
3. **Autofill Credentials**:
   - Focus on a login form → Press `Ctrl+Alt+P`
   - The app auto-detects username/password fields and fills them
   - If multiple credentials match, a selection dialog appears

### Tray Menu Options

| Option | Description |
|--------|-------------|
| Unlock Vault | Login to Bitwarden |
| Lock Vault | Clear session from memory |
| Sync Vault | Sync with Bitwarden servers |
| Settings | Configure hotkey, startup options |
| Quit | Exit application |

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        AUTOFILL PIPELINE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. User presses Ctrl+Alt+P                                     │
│           ↓                                                     │
│  2. UI Automation detects focused element / login form          │
│           ↓                                                     │
│  3. Get parent window title ("Google - Chrome")                 │
│           ↓                                                     │
│  4. Fuzzy match title to vault entries                          │
│           ↓                                                     │
│  5. If multiple matches → show selection dialog                 │
│           ↓                                                     │
│  6. Fill username field → Tab → Fill password field             │
│           ↓                                                     │
│  7. Zeroize credentials in memory                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Security

- **Memory Safety**: Built in Rust with `secrecy` and `zeroize` crates
- **No Disk Storage**: Vault data and encryption keys exist only in RAM
- **No Clipboard**: Avoids clipboard history loggers
- **Secure Credential Storage**: API keys stored in Windows Credential Manager
- **Direct HTTPS**: All communication with Bitwarden uses TLS

## Architecture

```
src/
├── main.rs              # Entry point, event loop, hotkey registration
├── lib.rs               # Module exports
├── error.rs             # Custom error types (BitwardenAutofillError)
├── config.rs            # Configuration storage (hotkey, startup settings)
├── credentials_store.rs # Windows Credential Manager integration
├── bitwarden/
│   ├── mod.rs           # Module exports
│   ├── auth.rs          # Bitwarden API authentication
│   ├── client.rs        # High-level Bitwarden client
│   ├── crypto.rs        # Vault encryption/decryption (Argon2id, AES)
│   ├── types.rs         # API data structures
│   └── vault.rs         # Vault parsing and management
├── ui_automation.rs     # Windows UI Automation for field detection
├── input_injector.rs    # SendInput keystroke injection
├── native_ui.rs         # Native Windows dialogs (login, settings, selection)
└── tray.rs              # System tray icon and menu
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `reqwest` | HTTP client for Bitwarden API |
| `uiautomation` | Windows UI Automation bindings |
| `global-hotkey` | Global hotkey detection |
| `tray-icon` + `muda` | System tray support |
| `windows` | Windows API bindings (SendInput, CredUI, Registry) |
| `secrecy` + `zeroize` | Secure memory handling |
| `argon2` + `aes-gcm` | Vault encryption |
| `fuzzy-matcher` | Window title to vault entry matching |
| `keyring` | Windows Credential Manager |
| `tracing` | Structured logging |



## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or PR.

## Disclaimer

This is an unofficial third-party client. It is not affiliated with or endorsed by Bitwarden, Inc.