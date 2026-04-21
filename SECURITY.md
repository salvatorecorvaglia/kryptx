# Security Policy

## Supported Versions

The following versions of **kryptx** are currently being supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < 1.0.0 | :x:                |

## Reporting a Vulnerability

We take the security of **kryptx** seriously. If you believe you have found a security vulnerability, please report it to us as soon as possible.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please use one of the following methods:

1.  **GitHub Private Vulnerability Reporting**: If available, please use the "Report a vulnerability" button under the "Security" tab of this repository.
2.  **Direct Contact**: You can contact the maintainer directly via GitHub [@salvatorecorvaglia](https://github.com/salvatorecorvaglia).

### What to Include in Your Report

To help us triage and resolve the issue quickly, please include as much information as possible:

*   A descriptive title.
*   A detailed description of the vulnerability.
*   Steps to reproduce the issue (proof-of-concept scripts or screenshots are very helpful).
*   Potential impact (e.g., what an attacker could achieve).
*   Any suggested mitigations.

### Our Commitment

If you report a vulnerability, we will:

*   Acknowledge receipt of your report within 48 hours.
*   Keep you informed of our progress as we work to resolve the issue.
*   Notify you once the vulnerability has been fixed.
*   Provide credit for your discovery (if you wish) in our release notes or CHANGELOG.

## Security Best Practices

As a password manager, the security of your data depends not only on the tool but also on how you use it. Please follow these best practices:

*   **Strong Master Password**: Use a unique, long, and complex master password.
*   **System Security**: Ensure your operating system and core utilities (OpenSSL, jq, Bash) are kept up to date.
*   **Secure Environment**: Only use **kryptx** on trusted machines. Avoid running it on public or shared computers.
*   **Audit Logs**: Regularly check `kryptx-audit.log` for any unauthorized access attempts.
*   **Vault Permissions**: Ensure your vault file (`passwords.enc`) remains restricted to your user (`chmod 600`). **kryptx** attempts to set these permissions automatically.

## Disclosure Policy

We follow a policy of coordinated disclosure. We ask that you do not share details of the vulnerability publicly until we have had a reasonable amount of time to fix it and notify users. Once a fix is released, we encourage you to document and share your findings to help the community.
