# kryptx 🔐

**kryptx** is a secure, lightweight, and modern command-line password manager built entirely with **Bash**, **OpenSSL**, and **jq**. It provides a robust way to manage your credentials directly from your terminal using industry-standard encryption.

---

## 🚀 Features

- **End-to-End Encryption**: Secure storage using **AES-256-CBC** with **PBKDF2** key derivation.
- **Zero Exposure**: Master password is never passed as an argument; it's read securely via `stdin`.
- **JSON-based Storage**: Uses `jq` for structured data management, ensuring compatibility with special characters.
- **Secure Random Generation**: Generate strong passwords with guaranteed character diversity (uppercase, lowercase, digits, symbols).
- **Clipboard Integration**: Copy passwords directly to your clipboard with **auto-clear timeout** (configurable, default 30s).
- **Safe Temp Handling**: Decrypted data is stored in a temporary file that is **securely wiped** (overwritten with random data) before deletion on exit.
- **Service Management**: Easily store, retrieve, edit (including service rename), delete, and search your services through an interactive menu.
- **Import/Export**: Backup and restore your password database with JSON import/export functionality. Duplicate detection works correctly.
- **Configurable Settings**: Customize default password length, clipboard timeout, and password file location.
- **Password Strength Checker**: Manual password inputs are evaluated for strength with helpful warnings.
- **Audit Logging**: All operations are logged to `kryptx-audit.log` for security tracking.
- **Rate Limiting & Lockout**: After 5 failed attempts, a 5-minute security lock is enforced.
- **Injection Protection**: All user inputs are properly sanitized to prevent injection attacks.
- **First-Run Confirmation**: Master password must be confirmed on first use to prevent typos.

---

## 🛠️ Prerequisites

Ensure you have the following installed:

- **Bash** (3.2+)
- **OpenSSL** (for encryption and password generation)
- **jq** (for JSON processing)

### Installation

#### macOS (Homebrew)

```bash
brew install openssl jq
```

#### Ubuntu/Debian

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
chmod +x password_manager.sh
```

### 3. Start managing passwords

```bash
./password_manager.sh
```

> [!NOTE]
> Upon first run, you will be prompted to set and confirm a **Master Password**. This password is the only key to your vault—if you lose it, your data cannot be recovered.

---

## 📋 Available Commands

1. **Store a password**: Add a new service or update an existing one. You can either enter a password manually (with strength check) or let the tool generate a secure one with customizable length and character options.

2. **Retrieve a password**: Search for a service (case-insensitive) and view credentials. Optionally copy the password to your clipboard (auto-clears after configurable timeout).

3. **List stored services**: See all services currently stored in your encrypted vault, with entry count and formatted output.

4. **Search services**: Perform safe substring searches across all service names to quickly find what you need.

5. **Edit a password**: Update username, service name, and/or password for an existing service entry.

6. **Delete a password**: Remove a service entry from the vault with confirmation prompt.

7. **Import passwords**: Import passwords from a JSON file. Duplicates (by service name) are automatically skipped.

8. **Export passwords**: Export your vault to a JSON file for backup purposes (⚠️ exported file is unencrypted).

9. **Settings**: Configure default password length, clipboard clear timeout, and password file location.

10. **Exit**: Securely close the application, wipe temporary data, and clear memory.

---

## 🔐 Security Internals

- **Encryption Algorithm**: AES-256-CBC
- **Key Derivation Function**: PBKDF2 with salt
- **File Permissions**: The encrypted file (`passwords.enc`) is restricted to owner-only access (`chmod 600`)
- **Secure Temp Cleanup**: Temporary files are **overwritten with random data** before deletion via a `trap EXIT INT TERM` signal handler
- **Memory Hygiene**: Master password variable is cleared on exit. No sensitive data persists in memory.
- **Input Sanitization**: All user inputs are properly escaped using `jq`'s string serialization to prevent injection attacks
- **JSON Validation**: Both encrypted and decrypted data structures are validated before processing
- **Rate Limiting**: After `$MAX_FAILED_ATTEMPTS` (default: 5) failed unlock attempts, a 5-minute security lock is enforced
- **Password Strength**: Manual password inputs are checked for minimum requirements (length, character diversity)
- **Clipboard Auto-Clear**: Passwords copied to clipboard are automatically cleared after a configurable timeout (default: 30s)

---

## 📂 Storage Structure

### Encrypted Vault

Data is stored in an encrypted file named `passwords.enc` (configurable).

### Configuration

User preferences are stored in `kryptx-config.json`.

### Audit Log

All operations are logged to `kryptx-audit.log` with timestamps for security tracking.

### Decrypted JSON Structure

Before encryption, the structure is a simple JSON array:

```json
[
  {
    "service": "github",
    "username": "user@example.com",
    "password": "s3cur3P@ssw0rd!"
  },
  {
    "service": "aws",
    "username": "admin",
    "password": "An0th3r$ecureP@ss"
  }
]
```

### Configuration File Format

```json
{
  "password_length": 20,
  "clipboard_timeout": 30,
  "password_file": "/path/to/passwords.enc"
}
```

---

## 🔄 Backup & Migration

### Creating a Backup

1. Use the **Export** feature (option 8) to create a JSON backup
2. Store the exported file in a secure location (encrypted USB, password-protected archive, etc.)
3. **Delete the unencrypted export** after securing it

### Restoring from Backup

1. Ensure your backup is in the correct JSON format (see structure above)
2. Use the **Import** feature (option 7) to load the backup
3. Verify the imported entries using the **List** feature (option 3)

---

## ⚠️ Security Best Practices

- **Never share** your master password
- **Regularly backup** your password vault
- **Delete exported files** immediately after securing them
- **Use strong master passwords** (consider using a passphrase of 12+ characters)
- **Keep your system updated** (OpenSSL, jq, Bash)
- **Verify file permissions** on `passwords.enc` (should be `600`)
- **Review audit logs** periodically (`kryptx-audit.log`) for unauthorized access
- **Don't ignore password strength warnings** when entering manual passwords
- **Be mindful of clipboard timeout** — avoid copying passwords on shared screens

---

## 🐛 Troubleshooting

### "Wrong password or corrupted file"

- You may have entered the wrong master password
- The `passwords.enc` file may be corrupted or tampered with
- Restore from a backup if available

### "Too many failed attempts. Security lock activated"

- You've exceeded the maximum number of failed unlock attempts (5)
- Wait 5 minutes before trying again
- The lock file is `.kryptx-lock` in the app directory

### "Clipboard not available"

- **macOS**: `pbcopy` should be available by default
- **Linux (X11)**: Install `xclip` (`sudo apt install xclip` or `sudo pacman -S xclip`)
- **Linux (Wayland)**: Install `wl-clipboard` (`sudo apt install wl-clipboard`)

### "Invalid JSON structure"

- The decrypted data may be corrupted
- Try restoring from a backup

### "Password is too weak"

- The password you entered doesn't meet minimum strength requirements
- Ensure it has at least 8 characters with a mix of uppercase, lowercase, digits, and special characters
- You can choose to bypass the warning if you understand the risk

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## ⚖️ License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

## 📝 Author

**Salvatore Corvaglia**

- GitHub: [@salvatorecorvaglia](https://github.com/salvatorecorvaglia)
