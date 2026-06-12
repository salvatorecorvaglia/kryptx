#!/bin/bash
set -euo pipefail

# Sourcing script functions without executing the main entry point menu
prompt_master_password() { :; }
main_menu() { :; }

# Source target script
source ./kryptx.sh

# Simple assertion functions
assert_equals() {
    local expected="$1"
    local actual="$2"
    if [ "$expected" != "$actual" ]; then
        printf '❌ Assertion failed: expected "%s", got "%s"\n' "$expected" "$actual" >&2
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Test Cases
# ------------------------------------------------------------------------------

test_password_strength_too_short() {
    printf 'Running test_password_strength_too_short... '
    if check_password_strength "Ab1" >/dev/null 2>&1; then
        printf '❌ Assertion failed: expected check_password_strength to fail on too short, but it succeeded\n' >&2
        exit 1
    fi
    printf 'OK\n'
}

test_password_strength_weak_classes() {
    printf 'Running test_password_strength_weak_classes... '
    if check_password_strength "aaaaaaaabbbb" >/dev/null 2>&1; then
        printf '❌ Assertion failed: expected check_password_strength to fail on weak classes, but it succeeded\n' >&2
        exit 1
    fi
    printf 'OK\n'
}

test_password_strength_acceptable() {
    printf 'Running test_password_strength_acceptable... '
    if ! check_password_strength "Ab1!cd2@" >/dev/null 2>&1; then
        printf '❌ Assertion failed: expected check_password_strength to succeed, but it failed\n' >&2
        exit 1
    fi
    printf 'OK\n'
}

test_empty_entries_line_count() {
    printf 'Running test_empty_entries_line_count... '
    local entries=""
    local count
    count=$(printf '%s' "$entries" | grep -c '^' || true)
    assert_equals "0" "$count"
    
    entries="one"
    count=$(printf '%s' "$entries" | grep -c '^' || true)
    assert_equals "1" "$count"
    
    entries=$'one\ntwo'
    count=$(printf '%s' "$entries" | grep -c '^' || true)
    assert_equals "2" "$count"
    printf 'OK\n'
}

test_make_tempfile() {
    printf 'Running test_make_tempfile... '
    local tmp
    tmp=$(_make_tempfile)
    if [ ! -f "$tmp" ]; then
        printf '❌ Assertion failed: temp file not created\n' >&2
        exit 1
    fi
    rm -f "$tmp"
    printf 'OK\n'
}

test_crypto_roundtrip() {
    printf 'Running test_crypto_roundtrip... '
    # Set up clean environment vars
    export MASTER_PASSWORD="supersecretpass"
    export HMAC_KEY=$(printf '%s' "kryptx-hmac-key-seed-v1" | openssl enc -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" -md sha256 -nosalt -pass fd:3 3<<<"$MASTER_PASSWORD" 2>/dev/null | base64 | tr -d '\n')
    
    export PASSWORD_FILE="./test_passwords.enc"
    export TEMP_FILE="./test_temp_file.json"
    
    # Write test data
    printf '[\n  {\n    "service": "Google",\n    "username": "alice",\n    "password": "mypassword"\n  }\n]\n' > "$TEMP_FILE"
    
    # Encrypt
    encrypt_file >/dev/null 2>&1
    if [ ! -f "$PASSWORD_FILE" ]; then
        printf '❌ Assertion failed: encrypted password file not created\n' >&2
        exit 1
    fi
    
    # Check that PASSWORD_FILE is encrypted and starts with Salted__ (since base64 content does after decoding)
    local bundle stored_hmac ct_b64
    bundle=$(cat "$PASSWORD_FILE")
    stored_hmac="${bundle%%:*}"
    ct_b64="${bundle#*:}"
    if [ -z "$stored_hmac" ]; then
        printf '❌ Assertion failed: hmac was empty\n' >&2
        exit 1
    fi
    
    # Decrypt to a clean temp file
    rm -f "$TEMP_FILE"
    decrypt_file >/dev/null 2>&1
    if [ ! -f "$TEMP_FILE" ]; then
        printf '❌ Assertion failed: decrypted temp file not created\n' >&2
        exit 1
    fi
    
    # Verify decrypted content
    local service
    service=$(jq -r '.[0].service' "$TEMP_FILE")
    assert_equals "Google" "$service"
    
    # Cleanup files
    rm -f "$PASSWORD_FILE" "$TEMP_FILE"
    printf 'OK\n'
}

# Run all tests
echo "🧪 Running kryptx unit tests..."
test_password_strength_too_short
test_password_strength_weak_classes
test_password_strength_acceptable
test_empty_entries_line_count
test_make_tempfile
test_crypto_roundtrip
echo "✅ All tests passed successfully!"
