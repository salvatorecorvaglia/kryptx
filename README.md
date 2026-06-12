# kryptx 🔐

**kryptx** is a high-security, lightweight, and modern command-line password manager built entirely in **Bash**. It leverages **OpenSSL** for industry-standard encryption (AES-256-CBC + HMAC-SHA256) and **jq** for robust, structured data management. Designed for terminal-centric workflows, it provides a secure vault without the overhead of external dependencies beyond standard Unix tools.

---

## ✨ Features

*   **Robust Encryption**: AES-256-CBC paired with a high-entropy PBKDF2 key derivation function pinned at **600,000 iterations** for defense against GPU/CPU-based cracking attempts.
*   **Tamper Evidence (Encrypt-then-MAC)**: Employs HMAC-SHA256 to sign and verify the encrypted vault, preventing ciphertext tampering or manipulation attacks.
*   **Zero-Exposure Passwords**: The master password is input via secure prompts and piped internally using dedicated file descriptors, preventing it from appearing in processes (`ps` or `/proc/<pid>/cmdline`).
*   **Temporary Lockout Mechanism**: Enforces a strict lockout penalty (5 minutes) after 5 consecutive failed attempts to prevent automated brute-force attacks.
*   **Secure Temp Wiping**: Sensitive data is processed in RAM-backed temporary directories (`/dev/shm` on Linux) and cleaned up securely upon exit. Temporary files are destroyed using `shred` (or random-byte overwrite fallback) and variables are zeroed in memory.
*   **Anonymous Audit Log**: Maintains an audit history of actions (`STORE`, `RETRIEVE`, `DELETE`, etc.) without ever writing service names, usernames, or password metadata to disk.
*   **Entropic Password Generator**: Generates high-entropy passwords with custom length, ensuring strict character diversity (at least one lowercase, uppercase, number, and special character) without entropy-reducing shuffle techniques.
*   **Clipboard Auto-Clear**: Automatically copies retrieved passwords to the system clipboard and clears it after a configurable timer (default: 30 seconds).
*   **Import / Export**: Supports JSON-based import/export, with options for fully encrypted backup payloads using custom passphrases.

---

## 🛠️ Requirements

Ensure the following tools are installed and available in your environment:

1.  **Shell**: Bash (version 4.0 or newer recommended)
2.  **Core Utilities**: `openssl` (for cryptography), `jq` (for secure JSON querying/parsing)
3.  **Clipboard Managers** (Optional, for clipboard integration):
    *   **macOS**: `pbcopy` (built-in)
    *   **Linux (X11)**: `xclip`
    *   **Linux (Wayland)**: `wl-copy`

---

## 🚀 Getting Started

### Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/salvatorecorvaglia/kryptx.git
cd kryptx
chmod +x kryptx.sh
```

### Running the Password Manager

To launch the menu-driven password manager:

```bash
./kryptx.sh
```

On your first run, you will be prompted to create and confirm a Master Password to initialize your vault file (`~/.local/share/kryptx/passwords.enc`).

---

## 📂 Project Structure

*   [kryptx.sh](kryptx.sh) — Core password manager bash application.
*   [test_kryptx.sh](test_kryptx.sh) — Unit test suite for verifying cryptography, parsing, and strength checks.
*   [SECURITY.md](SECURITY.md) — Security policy and vulnerability reporting workflow.
*   [LICENSE](LICENSE) — MIT License.

---

## 🧪 Testing

The project includes an automated test suite. Run the tests using:

```bash
./test_kryptx.sh
```

---

## ⚠️ Security Best Practices

- Use a **strong, unique** Master Password (12+ characters recommended).
- Use the **Encrypted Export** feature for backups rather than unencrypted JSON.
- Regularly check the `kryptx-audit.log` for unexpected activity.
- Keep your system's `OpenSSL` updated to the latest security patch.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## ⚖️ License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

## 🛡️ Security

For information on security features and reporting vulnerabilities, please see our [Security Policy](SECURITY.md).

---

## 📝 Author

**Salvatore Corvaglia**

- GitHub: [@salvatorecorvaglia](https://github.com/salvatorecorvaglia)
