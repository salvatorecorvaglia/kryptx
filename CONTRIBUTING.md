# Contributing to Custode 🔐

Thank you for your interest in contributing to **Custode**! We welcome contributions, bug reports, feature requests, and security improvements from the community.

---

## 🛠️ How to Contribute

### 1. Reporting Bugs
- Search existing [Issues](https://github.com/salvatorecorvaglia/custode/issues) to ensure your bug hasn't already been reported.
- Open a new issue with a clear title, description, steps to reproduce, expected vs. actual behavior, and environment details (OS, Bash version, OpenSSL version, `jq` version).

### 2. Suggesting Features
- Open an issue describing the feature, why it would be beneficial, and any design proposals.
- Wait for feedback from maintainers before starting implementation to ensure alignment with project goals.

### 3. Submitting Code Changes

1. **Fork & Clone** the repository:
   ```bash
   git clone https://github.com/YOUR-USERNAME/custode.git
   cd custode
   ```

2. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**:
   - Ensure your code adheres to ShellCheck linting rules (`shellcheck -x custode.sh test_custode.sh`).
   - Keep scripts portable across macOS and Linux environment setups.
   - Maintain defense-in-depth security best practices (avoid logging secrets, avoid unquoted variables, ensure secure temp file creation and cleanup).

4. **Run Tests**:
   - Run the test suite to verify everything passes:
     ```bash
     ./test_custode.sh
     ```
   - Add new tests in `test_custode.sh` for any new functionality or bug fixes.

5. **Commit & Push**:
   - Write clear, concise commit messages.
   - Push your branch to GitHub:
     ```bash
     git push origin feature/your-feature-name
     ```

6. **Open a Pull Request**:
   - Submit a PR against the `main` branch.
   - Describe the changes made and link to any relevant issues.

---

## 📐 Coding & Style Guidelines

- **Pure Bash**: Custode is built strictly in Pure Bash (`bash >= 4.0`) using standard POSIX utilities (`openssl`, `jq`). Avoid introducing unnecessary external dependencies.
- **Linting**: All scripts must pass `shellcheck` cleanly.
- **Security-First**:
  - Pass sensitive data via file descriptors or streams—never via process arguments (`/proc`, `ps`).
  - Use cryptographically secure temporary file handling and clean up temporary files on exit or signal traps.
  - Quote all variables to prevent shell injection and word splitting.

---

## 🧪 Testing Guidelines

All unit tests are located in [test_custode.sh](test_custode.sh).

When adding a feature or bug fix:
1. Add test functions in `test_custode.sh`.
2. Follow the test pattern: mock temporary test directories, isolate credentials, and clean up test state.
3. Ensure running `./test_custode.sh` outputs `✅ All tests passed successfully!`.

---

Happy coding! 🔐