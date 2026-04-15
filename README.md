# kryptx 🔐

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-3.2%2B-blue.svg)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/Security-AES--256--CBC-green.svg)](#-security-internals)

**kryptx** is a secure, lightweight, and modern command-line password manager built entirely in **Bash**, utilizing **OpenSSL** for industry-standard encryption and **jq** for structured data management. It provides a robust, terminal-centric way to manage your credentials without external dependencies beyond standard Unix tools.

---

## 🚀 Features

- **End-to-End Encryption**: Robust storage using **AES-256-CBC** with **PBKDF2** key derivation.
- **Zero Exposure**: Master password is never passed as a command-line argument; it's read securely via `stdin`.
- **JSON-based Storage**: Leverages `jq` for structured data management, ensuring safety with special characters.
- **Secure Password Generation**: Generate strong, diverse passwords (uppercase, lowercase, digits, symbols) with guaranteed quality.
- **Clipboard Integration**: Copy passwords directly to your clipboard with an **auto-clear timeout** (configurable, default 30s).
- **Secure Cleanup**: Decrypted data exists only in temporary files that are **securely wiped** (overwritten with random data) before deletion.
- **Advanced Service Management**: Store, retrieve, edit, rename, delete, and search services through an intuitive interactive menu.
- **Backup & Migration**: Simple JSON import/export functionality with automatic duplicate detection.
- **Configurable Experience**: Customize password length, clipboard timeouts, and storage locations via the settings menu.
- **Security Audit & Logging**: All operations are logged to `kryptx-audit.log` for security tracking and accountability.
- **Brute-Force Protection**: Automatic 5-minute security lockout after 5 failed authentication attempts.

---

## 🛠️ Prerequisites

Ensure you have the following tools installed:

- **Bash** (3.2+)
- **OpenSSL** (for encryption and entropy)
- **jq** (for JSON processing)

### Installation

#### macOS
```bash
brew install openssl jq
```

#### Ubuntu / Debian
```bash
sudo apt update && sudo apt install openssl jq
```

#### Arch Linux
```bash
sudo pacman -S openssl jq
```

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

> [!NOTE]
> Upon the first run, you will be prompted to set and confirm a **Master Password**. This is the only key to your vault—if lost, your data **cannot** be recovered.

---

## 📋 Available Commands

1.  **Store a password**: Add a new service or update an existing one. Options include manual entry (with strength validation) or automatic generation.
2.  **Retrieve a password**: Search for a service and view credentials. Supports case-insensitive matching and clipboard copying.
3.  **List stored services**: View all services currently in your vault with a clean, formatted output.
4.  **Search services**: Perform fast substring searches across all service names.
5.  **Edit a password**: Modify the username, service name, or password of an existing entry.
6.  **Delete a password**: Securely remove an entry from the vault with a confirmation prompt.
7.  **Import passwords**: Bulk import entries from a JSON file. Duplicates are handled automatically.
8.  **Export passwords**: Create an unencrypted JSON backup of your vault (handle with care!).
9.  **Settings**: Interactively adjust default password length, clipboard timeout, and the vault file path.
10. **Exit**: Securely wipe temporary files, clear sensitive variables from memory, and close the session.

---

## 🔐 Security Internals

- **Encryption**: AES-256-CBC (Advanced Encryption Standard).
- **Key Derivation**: PBKDF2 (Password-Based Key Derivation Function 2) with salt.
- **File Security**: The vault file (`passwords.enc`) is restricted to owner-only access (`chmod 600`).
- **Memory Hygiene**: The Master Password variable is explicitly cleared on exit. No sensitive data persists in the terminal environment.
- **Safe I/O**: Temporary files are handled via `mktemp` and are **overwritten with random data** (`/dev/urandom`) before deletion using a `trap` signal handler.
- **Injection Protection**: All user inputs are sanitized using `jq` parameter binding to prevent command or JSON injection.
- **Lockout Mechanism**: Persistence of failed attempts via `.kryptx-lock` ensures protection against automated brute-force attacks.

---

## 📂 Storage Structure

| File | Purpose |
| :--- | :--- |
| `passwords.enc` | The encrypted vault containing your credentials. |
| `kryptx-config.json` | Stores your custom settings and preferences. |
| `kryptx-audit.log` | Records all session activities with timestamps. |
| `.kryptx-lock` | Temporary file used to manage security lockouts. |

---

## 🔄 Backup & Migration

### Creating a Backup
1. Use the **Export** feature (Option 8) to generate a JSON file.
2. Transfer the file to a secure, encrypted storage medium.
3. **Crucial**: Delete the unencrypted export file from your local disk immediately.

### Restoring from Backup
1. Ensure the backup file follows the standard JSON structure.
2. Use the **Import** feature (Option 7) to load the data into your vault.
3. Verify entries using the **List** feature (Option 3).

---

## ⚠️ Security Best Practices

- Use a **strong, unique** Master Password (passphrases of 12+ characters recommended).
- Regularly rotate your Master Password if you suspect exposure.
- Never leave exported unencrypted files on your system.
- Monitor the `kryptx-audit.log` for any suspicious activity.
- Keep your underlying system (especially OpenSSL) updated.

---

## 🐛 Troubleshooting

- **"Wrong password or corrupted file"**: Verify your Master Password. If the file is corrupted, restore from your latest backup.
- **"Security lock activated"**: You have exceeded the failed attempt limit. Wait 5 minutes for the lockout to expire.
- **"Clipboard not available"**:
    - **macOS**: `pbcopy` is standard.
    - **Linux (X11)**: Install `xclip`.
    - **Linux (Wayland)**: Install `wl-clipboard`.
- **"Invalid JSON structure"**: Ensure your import files are valid JSON arrays of objects.

---

## ⚖️ License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.

---

## 📝 Author

**Salvatore Corvaglia**
- GitHub: [@salvatorecorvaglia](https://github.com/salvatorecorvaglia)
