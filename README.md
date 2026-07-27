# kryptx 🔐

**A lightweight, zero-dependency, highly secure terminal-based password manager written in Pure Bash.**

---

## ✨ Features

- 🛡️ **AES-256-CBC Encryption**: Master-password-derived encryption via PBKDF2 with **600,000 iterations** of SHA-256.
- 🔏 **Encrypt-then-MAC Integrity**: HMAC-SHA256 validation prevents cipher tampering, corrupted vaults, and padding oracle attacks.
- 🧹 **Zero Disk Leakage**: Transient decrypted data stays in RAM/tmpfs storage with automatic multi-pass secure deletion (`shred`/`srm`/`urandom`) on exit or signal interruption (`SIGINT`, `SIGTERM`).
- 🔒 **Process Memory Protection**: Master keys are passed directly to OpenSSL via file descriptors (`fd:3`), eliminating process argument leakage (`/proc`, `ps`).
- ⏱️ **Auto-Clearing Clipboard**: Automatically clears copied credentials from system clipboards (`pbcopy`, `xclip`, `wl-copy`) after a configurable timeout (default 30s).
- 🚨 **Rate Limiting & Lockout**: Protects against brute-force attacks by enforcing a 5-minute lockout after 5 consecutive failed master password attempts.
- 🎲 **Cryptographic Password Generator**: Generates strong, entropy-rich passwords tailored to custom length and character set criteria.
- 📁 **XDG Base Directory Compliance**: Follows standard Unix paths (`$XDG_CONFIG_HOME/kryptx` and `$XDG_DATA_HOME/kryptx`).
- 📜 **Security Audit Logging**: Maintains an encrypted-state timestamped event log (`kryptx-audit.log`) tracking authorization, lockouts, exports, and vault modifications.
- 📦 **JSON Import & Export**: Easily backup, restore, or migrate vaults with built-in duplicate detection and validation.

---

## 🔒 Security Architecture

kryptx is engineered around defense-in-depth security practices:

| Component | Implementation Details |
| :--- | :--- |
| **Symmetric Encryption** | `AES-256-CBC` with unique per-encryption salts via `openssl enc`. |
| **Key Derivation (KDF)** | `PBKDF2-HMAC-SHA256` with `600,000` iterations (pinned for consistent cross-platform security). |
| **Authentication & Integrity** | Encrypt-then-MAC scheme using `HMAC-SHA256` over the ciphertext payload. |
| **Master Key Isolation** | Secrets reside strictly in process memory; password inputs bypass `sys_execve` process arguments. |
| **Secure Erasure** | Multi-tiered disk wiping: prefers Linux `shred`, macOS `srm`, or `dd` overwrite with `/dev/urandom` fallback. |
| **Anti-Timing** | Constant-time password hash comparison during vault initialization and validation steps. |

---

## 📋 Prerequisites

kryptx requires minimal standard Unix tools installed on your system:

- **Bash** (`>= 4.0`)
- **OpenSSL** (`openssl` CLI)
- **jq** (Command-line JSON processor)

### Optional Clipboard Helpers
For automatic clipboard copy-and-clear features:
- **macOS**: `pbcopy` (built-in)
- **Linux (X11)**: `xclip` or `xsel`
- **Linux (Wayland)**: `wl-copy`

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/salvatorecorvaglia/kryptx.git
cd kryptx
```

### 2. Make Executable & Launch
```bash
chmod +x kryptx.sh
./kryptx.sh
```

### 3. (Optional) Install Globally or Create Alias
Add an alias to your `~/.bashrc` or `~/.zshrc`:
```bash
alias kryptx="$HOME/kryptx/kryptx.sh"
```
Or symlink to a bin directory in your `$PATH`:
```bash
ln -s "$(pwd)/kryptx.sh" ~/.local/bin/kryptx
```

---

## 📖 Usage & Features

Upon launching `./kryptx.sh`, kryptx prompts for your **Master Password**. On first run, it initializes a new encrypted vault.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔐 Password Manager
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. Store a password
  2. Retrieve a password
  3. List stored services
  4. Search services
  5. Edit a password
  6. Delete a password
  7. Import passwords
  8. Export passwords
  9. Settings
  10. Exit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Operations Overview

- **Store a Password (1)**: Add a new service record including Service Name, Username, Password (manually typed or auto-generated), optional URL, and Notes.
- **Retrieve a Password (2)**: Interactive account picker with search filtering. Option to copy password directly to clipboard (with auto-clear) or display on screen.
- **List Stored Services (3)**: Summarizes all stored entries grouped by service and username.
- **Search Services (4)**: Instant query matching across service names, usernames, and notes.
- **Edit / Delete Passwords (5 & 6)**: Modify stored credentials or safely delete accounts with confirmation prompts.
- **Import & Export (7 & 8)**: Export your vault to an encrypted file or plain JSON for backup. Import merges new records while skipping existing duplicates.
- **Settings (9)**: Customize default password length, clipboard clear timeout (seconds), and custom vault file locations.

---

## 📂 Data & Configuration Storage

kryptx complies with the **XDG Base Directory Specification**:

| Resource | Default Location | Description |
| :--- | :--- | :--- |
| **Config File** | `~/.config/kryptx/kryptx-config.json` | Stores user configuration settings |
| **Encrypted Vault** | `~/.local/share/kryptx/passwords.enc` | HMAC-authenticated AES-256 encrypted payload |
| **Audit Log** | `~/.local/share/kryptx/kryptx-audit.log` | Security audit trail |
| **Lockout Marker** | `~/.local/share/kryptx/.kryptx-lock` | Temporary lock file created during security lockout |

*All directories are created with strict permissions (`0700` / `rwx------`), and files are locked down (`0600` / `rw-------`).*

---

## 🧪 Running Unit Tests

kryptx comes with a comprehensive test suite covering password strength algorithms, HMAC integrity checks, tempfile sanitization, and encryption roundtrips.

To execute the test suite:

```bash
bash test_kryptx.sh
```

Example output:
```text
🧪 Running kryptx unit tests...
Running test_password_strength_too_short... OK
Running test_password_strength_weak_classes... OK
Running test_password_strength_acceptable... OK
Running test_empty_entries_line_count... OK
Running test_make_tempfile... OK
Running test_crypto_roundtrip... OK
Running test_crypto_hmac_tamper... OK
Running test_entry_selection_by_index... OK
✅ All tests passed successfully!
```

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📜 Changelog

Detailed release history and version changes can be found in [CHANGELOG.md](CHANGELOG.md).

## 🔐 Security

If you discover a security vulnerability, please see our [Security Policy](SECURITY.md).

## 📝 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

**Author**: [Salvatore Corvaglia](https://github.com/salvatorecorvaglia)