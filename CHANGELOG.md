# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-07-24

### Added
- **Core Architecture**: Pure Bash terminal-based password manager with zero third-party dependencies (requires only `openssl` and `jq`).
- **AES-256-CBC Encryption**: Master-password key derivation using PBKDF2-HMAC-SHA256 with **600,000 iterations**.
- **Encrypt-then-MAC Integrity**: HMAC-SHA256 tag verification on encrypted vault payload to detect file tampering and prevent corruption.
- **Process Memory Protection**: Secure master password passing via file descriptor (`fd:3`) to prevent credential leakage via `/proc` or process list (`ps`).
- **RAM-Backed Temp Files & Secure Erasure**: Automatic preference for `/dev/shm` (RAM-backed tmpfs) for transient data, backed by multi-pass deletion (`shred`, `srm`, or `dd` `/dev/urandom` overwrite) on process termination (`SIGINT`, `SIGTERM`, exit).
- **XDG Base Directory Compliance**: Storage and configuration following standard Unix paths (`$XDG_CONFIG_HOME/kryptx` and `$XDG_DATA_HOME/kryptx`).
- **Cryptographic Password Generator**: Built-in generator utilizing `openssl rand` to produce high-entropy passwords with custom length and symbol rules.
- **Account Selection & Search**: Support for interactive index selection and case-insensitive service query lookup.
- **Clipboard Management**: Integration with `pbcopy` (macOS), `xclip` (Linux X11), and `wl-copy` (Wayland) with configurable auto-clear timer (default 30 seconds).
- **Brute-Force Protection**: 5-minute security lockout triggered after 5 consecutive failed authentication attempts.
- **Import & Export Operations**: Backup and migration support with both unencrypted JSON and encrypted exports, built-in duplicate detection, and format validation.
- **Security Audit Logging**: Event logging to `kryptx-audit.log` tracking session activities, auth failures, and vault operations without storing plaintext credentials or query strings.
- **Automated CI/CD & Testing**: Unit test suite (`test_kryptx.sh`) and GitHub Actions workflows for continuous integration and automated releases.