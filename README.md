# kryptx 🔐

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-3.2%2B-blue.svg)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/Security-AES--256--CBC--HMAC-green.svg)](#-security-internals)

**kryptx** is a high-security, lightweight, and modern command-line password manager built entirely in **Bash**. It leverages **OpenSSL** for industry-standard encryption (AES-256-CBC + HMAC-SHA256) and **jq** for robust, structured data management. Designed for terminal-centric workflows, it provides a secure vault without the overhead of external dependencies beyond standard Unix tools.

---

## 🚀 Features

- **Authenticated Encryption**: Uses **AES-256-CBC** with an **Encrypt-then-MAC (EtM)** approach using **HMAC-SHA256** to ensure data integrity and authenticity.
- **Hardened Key Derivation**: Employs **PBKDF2** with **600,000 iterations** (pinned) to protect against modern brute-force hardware.
- **Zero-Exposure Architecture**: Master passwords are never passed via command-line arguments or environment variables; they are read via secure `stdin` and passed to OpenSSL via file descriptors.
- **Secure Memory Management**:
    - Prefers **RAM-backed storage** (`/dev/shm`) for temporary files to prevent sensitive data from hitting the physical disk.
    - Temporary files are **securely wiped** using `shred` (or random-data overwrite fallback) before deletion.
- **Flexible Export/Import**: Supports both raw JSON and **Encrypted Export** files (using a separate passphrase), facilitating secure migrations and backups.
- **Clipboard Integration**: Copy passwords directly with a configurable **auto-clear timeout** (default 30s).
- **Security Lockout**: Automatic 5-minute lockout after 5 failed authentication attempts to thwart automated attacks.
- **Audit Logging**: Comprehensive action logging to `kryptx-audit.log` (sensitive metadata like service names are never logged).
- **Search & Management**: Intuitive interactive menu for storing, retrieving, editing, and searching entries with case-insensitive matching.

---

## 🛠️ Prerequisites

Ensure you have the following tools installed:

- **Bash** (3.2+)
- **OpenSSL** (1.1.1+ recommended)
- **jq** (for JSON processing)

### Installation

#### macOS
```bash
brew install openssl jq
```

#### Ubuntu / Debian
```bash
sudo apt update && sudo apt install openssl jq xclip  # xclip for clipboard support
```

#### Arch Linux
```bash
sudo pacman -S openssl jq xclip
```

> [!TIP]
> On Linux, `kryptx` supports `xclip` (X11), `wl-clipboard` (Wayland), and `pbcopy` (macOS).

---

## 💻 Usage

### 1. Clone the repository
```bash
git clone https://github.com/salvatorecorvaglia/kryptx.git
cd kryptx
```

### 2. Make the script executable
```bash
chmod +x kryptx.sh
```

### 3. Start managing passwords
```bash
./kryptx.sh
```

> [!IMPORTANT]
> On the first run, you will set a **Master Password**. This is the only way to unlock your vault. **There is no recovery mechanism for a lost Master Password.**

---

## 📋 Available Commands

1.  **Store**: Add new entries with manual input or auto-generation. Includes password strength validation.
2.  **Retrieve**: View credentials and copy passwords to the clipboard.
3.  **List**: Overview of all stored services and usernames.
4.  **Search**: Fast substring search across all service names.
5.  **Edit**: Modify existing usernames, service names, or passwords.
6.  **Delete**: Securely remove an entry from the vault.
7.  **Import**: Load entries from JSON or encrypted export files.
8.  **Export**: Create unencrypted JSON backups or **passphrase-protected encrypted exports**.
9.  **Settings**: Configure password length, clipboard timeouts, and custom vault paths.
10. **Exit**: Securely wipe memory/temp files and terminate the session.

---

## 🔐 Security Internals

- **Cipher**: `AES-256-CBC` for confidentiality.
- **Integrity**: `HMAC-SHA256` for authenticity (protects against bit-flipping and padding oracle attacks).
- **KDF**: `PBKDF2` with `600,000` iterations and a unique salt.
- **I/O Safety**:
    - Vault files are restricted to `chmod 600`.
    - Temporary files are created with `mktemp` in `/dev/shm` (if available).
    - Trap handlers ensure `secure_cleanup` runs on exit, interrupts, or errors.
- **Sanitization**: All user inputs are handled via `jq` parameter binding (`--arg`) to prevent JSON or command injection.

---

## 📂 Storage Structure

| File | Purpose |
| :--- | :--- |
| `passwords.enc` | The encrypted vault (AES + HMAC). |
| `kryptx-config.json` | User-specific settings (length, timeouts). |
| `kryptx-audit.log` | Security audit trail (action types and timestamps). |
| `.kryptx-lock` | Temporary lockout marker. |

---

## ⚠️ Security Best Practices

- Use a **strong, unique** Master Password (12+ characters recommended).
- Use the **Encrypted Export** feature for backups rather than unencrypted JSON.
- Regularly check the `kryptx-audit.log` for unexpected activity.
- Keep your system's `OpenSSL` updated to the latest security patch.

---

## ⚖️ License

Distributed under the **MIT License**. See [LICENSE](LICENSE) and [SECURITY](SECURITY.md) for more information.

---

## 📝 Author

**Salvatore Corvaglia**
- GitHub: [@salvatorecorvaglia](https://github.com/salvatorecorvaglia)
