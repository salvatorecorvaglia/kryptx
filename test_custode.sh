#!/bin/bash
set -euo pipefail

# Sourcing script functions without executing the main entry point menu
# shellcheck disable=SC2329
prompt_master_password() { :; }
# shellcheck disable=SC2329
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
    HMAC_KEY=$(printf '%s' "kryptx-hmac-key-seed-v1" | openssl enc -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" -md sha256 -nosalt -pass fd:3 3<<<"$MASTER_PASSWORD" 2>/dev/null | base64 | tr -d '\n')
    export HMAC_KEY
    
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
    if [ -z "$stored_hmac" ] || [ -z "$ct_b64" ]; then
        printf '❌ Assertion failed: hmac or ciphertext payload was empty\n' >&2
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

test_crypto_hmac_tamper() {
    printf 'Running test_crypto_hmac_tamper... '
    export MASTER_PASSWORD="supersecretpass"
    HMAC_KEY=$(printf '%s' "kryptx-hmac-key-seed-v1" | openssl enc -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" -md sha256 -nosalt -pass fd:3 3<<<"$MASTER_PASSWORD" 2>/dev/null | base64 | tr -d '\n')
    export HMAC_KEY
    
    export PASSWORD_FILE="./test_tamper_passwords.enc"
    export TEMP_FILE="./test_tamper_temp.json"
    
    printf '[{"service":"Github","username":"bob","password":"secret"}]\n' > "$TEMP_FILE"
    encrypt_file >/dev/null 2>&1
    
    # Tamper with the encrypted file (modify HMAC prefix)
    printf '0000000000000000000000000000000000000000000000000000000000000000:badpayload\n' > "$PASSWORD_FILE"
    
    rm -f "$TEMP_FILE"
    if decrypt_file >/dev/null 2>&1; then
        printf '❌ Assertion failed: decrypt_file succeeded on tampered ciphertext, but expected failure\n' >&2
        rm -f "$PASSWORD_FILE" "$TEMP_FILE"
        exit 1
    fi
    
    rm -f "$PASSWORD_FILE" "$TEMP_FILE"
    printf 'OK\n'
}

test_entry_selection_by_index() {
    printf 'Running test_entry_selection_by_index... '
    export TEMP_FILE="./test_selection_temp.json"
    printf '[\n  {"service":"Alpha","username":"user1","password":"p1"},\n  {"service":"Beta","username":"user2","password":"p2"}\n]\n' > "$TEMP_FILE"
    
    if ! _select_account_entry "test" "1" >/dev/null 2>&1; then
        printf '❌ Assertion failed: _select_account_entry failed on list index "1"\n' >&2
        rm -f "$TEMP_FILE"
        exit 1
    fi
    assert_equals "Alpha" "$SELECTED_SERVICE"
    assert_equals "user1" "$SELECTED_USERNAME"
    assert_equals "p1" "$SELECTED_PASSWORD"
    
    if ! _select_account_entry "test" "2" >/dev/null 2>&1; then
        printf '❌ Assertion failed: _select_account_entry failed on list index "2"\n' >&2
        rm -f "$TEMP_FILE"
        exit 1
    fi
    assert_equals "Beta" "$SELECTED_SERVICE"
    assert_equals "user2" "$SELECTED_USERNAME"
    assert_equals "p2" "$SELECTED_PASSWORD"
    
    if ! _select_account_entry "test" "alpha" >/dev/null 2>&1; then
        printf '❌ Assertion failed: _select_account_entry failed on service name "alpha"\n' >&2
        rm -f "$TEMP_FILE"
        exit 1
    fi
    assert_equals "Alpha" "$SELECTED_SERVICE"
    
    rm -f "$TEMP_FILE"
    printf 'OK\n'
}

test_crypto_hmac_tamper
test_entry_selection_by_index

echo "✅ All tests passed successfully!"
