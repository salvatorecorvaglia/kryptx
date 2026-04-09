#!/bin/bash

set -euo pipefail

# ==============================================================================
# Configuration and Global Variables
# ==============================================================================

# Application directory (resilient to working directory changes)
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Encrypted password storage file (configurable via config)
PASSWORD_FILE="$APP_DIR/passwords.enc"

# Audit log file
AUDIT_LOG="$APP_DIR/kryptx-audit.log"

# Temporary file for decrypted data (auto-deleted on exit)
TEMP_FILE=""
TEMP_FILES_TO_CLEAN=()

# Configuration file
CONFIG_FILE="$APP_DIR/kryptx-config.json"

# Default password length
DEFAULT_PASSWORD_LENGTH=16

# Clipboard clear timeout (seconds)
CLIPBOARD_TIMEOUT=30

# Max failed attempts before wipe attempt
MAX_FAILED_ATTEMPTS=5

# Master password variable (will be unset on exit)
MASTER_PASSWORD=""

# ==============================================================================
# Cleanup & Security Functions
# ==============================================================================

# Secure cleanup function
secure_cleanup() {
    # Overwrite temp files before deletion
    for f in "${TEMP_FILES_TO_CLEAN[@]}"; do
        if [ -f "$f" ]; then
            # Overwrite with random data before removing
            local size
            size=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null || echo "0")
            if [ "$size" -gt 0 ] 2>/dev/null; then
                dd if=/dev/urandom of="$f" bs=1 count="$size" 2>/dev/null || true
            fi
            rm -f "$f"
        fi
    done
    # Clear master password from memory
    MASTER_PASSWORD=""
}

# Setup trap for cleanup
TEMP_FILE=$(mktemp)
TEMP_FILES_TO_CLEAN+=("$TEMP_FILE" "$TEMP_FILE.tmp")
trap secure_cleanup EXIT INT TERM

# ==============================================================================
# Helper Functions
# ==============================================================================

# Load configuration from config file
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        DEFAULT_PASSWORD_LENGTH=$(jq -r '.password_length // 16' "$CONFIG_FILE")
        CLIPBOARD_TIMEOUT=$(jq -r '.clipboard_timeout // 30' "$CONFIG_FILE")
        local custom_password_file
        custom_password_file=$(jq -r '.password_file // ""' "$CONFIG_FILE")
        if [ -n "$custom_password_file" ]; then
            PASSWORD_FILE="$custom_password_file"
        fi
    fi
}

# Save configuration to config file
save_config() {
    local config_json
    if [ -f "$CONFIG_FILE" ]; then
        config_json=$(cat "$CONFIG_FILE")
    else
        config_json="{}"
    fi

    echo "$config_json" | jq \
        --argjson pl "${1:-$DEFAULT_PASSWORD_LENGTH}" \
        --argjson ct "${CLIPBOARD_TIMEOUT}" \
        --arg pf "$PASSWORD_FILE" \
        '.password_length = $pl | .clipboard_timeout = $ct | .password_file = $pf' \
        > "$CONFIG_FILE.tmp"
    mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
}

# Audit logging
audit_log() {
    local action="$1"
    local details="${2:-}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $action: $details" >> "$AUDIT_LOG"
    chmod 600 "$AUDIT_LOG" 2>/dev/null || true
}

# Check password strength
check_password_strength() {
    local password="$1"
    local length=${#password}
    local score=0
    local warn_short=""
    local warn_upper=""
    local warn_lower=""
    local warn_digit=""
    local warn_special=""

    if [ "$length" -lt 8 ]; then
        warn_short="YES"
    fi

    if echo "$password" | grep -q '[A-Z]'; then
        score=$((score + 1))
    else
        warn_upper="YES"
    fi

    if echo "$password" | grep -q '[a-z]'; then
        score=$((score + 1))
    else
        warn_lower="YES"
    fi

    if echo "$password" | grep -q '[0-9]'; then
        score=$((score + 1))
    else
        warn_digit="YES"
    fi

    if echo "$password" | grep -q '[^A-Za-z0-9]'; then
        score=$((score + 1))
    else
        warn_special="YES"
    fi

    if [ "$score" -lt 2 ]; then
        echo "Password is too weak:"
        if [ -n "$warn_short" ]; then printf '   Warning: Password is too short (min 8 chars)\n'; fi
        if [ -n "$warn_upper" ]; then printf '   Warning: No uppercase letters\n'; fi
        if [ -n "$warn_lower" ]; then printf '   Warning: No lowercase letters\n'; fi
        if [ -n "$warn_digit" ]; then printf '   Warning: No digits\n'; fi
        if [ -n "$warn_special" ]; then printf '   Warning: No special characters\n'; fi
        return 1
    fi

    if [ "$length" -lt 12 ] || [ -n "$warn_upper" ] || [ -n "$warn_lower" ] || [ -n "$warn_digit" ] || [ -n "$warn_special" ]; then
        echo "Password could be stronger:"
        if [ "$length" -lt 12 ]; then printf '   Tip: Consider using at least 12 characters\n'; fi
        if [ -n "$warn_upper" ]; then printf '   Tip: Add uppercase letters\n'; fi
        if [ -n "$warn_lower" ]; then printf '   Tip: Add lowercase letters\n'; fi
        if [ -n "$warn_digit" ]; then printf '   Tip: Add digits\n'; fi
        if [ -n "$warn_special" ]; then printf '   Tip: Add special characters\n'; fi
    fi

    return 0
}

# ==============================================================================
# Encryption/Decryption Functions
# ==============================================================================

# Prompt user for the master password with rate limiting
prompt_master_password() {
    local attempt=1
    local lock_file="$APP_DIR/.kryptx-lock"
    local lock_mtime=0
    local now_ts=0
    local lock_age=0
    local wait_secs=0

    # Check if lock file exists and is recent (within 5 minutes)
    if [ -f "$lock_file" ]; then
        now_ts=$(date +%s)
        lock_mtime=$(stat -f%m "$lock_file" 2>/dev/null || stat -c%Y "$lock_file" 2>/dev/null || echo "0")
        lock_age=$((now_ts - lock_mtime))
        if [ "$lock_age" -lt 300 ]; then
            wait_secs=$((300 - lock_age))
            echo "Security lock active. Too many failed attempts."
            echo "   Please wait $wait_secs seconds before retrying."
            exit 1
        else
            rm -f "$lock_file"
        fi
    fi

    while [ "$attempt" -le "$MAX_FAILED_ATTEMPTS" ]; do
        printf "%s\n" "Enter your master password (attempt $attempt/$MAX_FAILED_ATTEMPTS):"
        read -s MASTER_PASSWORD
        echo ""

        if [ -z "$MASTER_PASSWORD" ]; then
            echo "❌ Master password cannot be empty"
            attempt=$((attempt + 1))
            continue
        fi

        # Test password against existing file
        if [ -f "$PASSWORD_FILE" ]; then
            local test_decrypt
            test_decrypt=$(mktemp)
            TEMP_FILES_TO_CLEAN+=("$test_decrypt")

            if echo "$MASTER_PASSWORD" | openssl enc -aes-256-cbc -pbkdf2 -d \
                -in "$PASSWORD_FILE" -pass stdin -out "$test_decrypt" 2>/dev/null; then
                if jq empty "$test_decrypt" 2>/dev/null; then
                    audit_log "UNLOCK" "Master password accepted (attempt $attempt)"
                    rm -f "$test_decrypt"
                    return 0
                fi
            fi
            rm -f "$test_decrypt"
            echo "❌ Wrong password or corrupted file"
            audit_log "AUTH_FAIL" "Failed attempt $attempt/$MAX_FAILED_ATTEMPTS"
        else
            # First run - no existing file, validate password confirmation
            echo "Confirm your master password:"
            local confirm
            read -s confirm
            echo ""

            if [ "$MASTER_PASSWORD" != "$confirm" ]; then
                echo "❌ Passwords do not match"
                audit_log "MISMATCH" "Password confirmation failed"
                MASTER_PASSWORD=""
                attempt=$((attempt + 1))
                continue
            fi

            if [ ${#MASTER_PASSWORD} -lt 8 ]; then
                echo "❌ Master password must be at least 8 characters"
                MASTER_PASSWORD=""
                attempt=$((attempt + 1))
                continue
            fi

            audit_log "INIT" "New vault created"
            return 0
        fi

        attempt=$((attempt + 1))
    done

    # Create lock file after max attempts
    touch "$lock_file"
    chmod 600 "$lock_file"
    audit_log "LOCKOUT" "Security lock activated after $MAX_FAILED_ATTEMPTS failed attempts"
    echo "🔒 Too many failed attempts. Security lock activated for 5 minutes."
    exit 1
}

# Function to decrypt the encrypted password file into TEMP_FILE
decrypt_file() {
    if [ -f "$PASSWORD_FILE" ]; then
        echo "$MASTER_PASSWORD" | openssl enc -aes-256-cbc -pbkdf2 -d \
            -in "$PASSWORD_FILE" -pass stdin -out "$TEMP_FILE" 2>/dev/null || {
            echo "❌ Wrong password or corrupted file"
            audit_log "DECRYPT_FAIL" "Decryption failed"
            exit 1
        }

        # Validate JSON structure
        if ! jq empty "$TEMP_FILE" 2>/dev/null; then
            echo "❌ Corrupted password file"
            audit_log "DECRYPT_FAIL" "Invalid JSON after decryption"
            exit 1
        fi
    else
        echo "[]" > "$TEMP_FILE"
    fi
}

# Function to encrypt TEMP_FILE back into PASSWORD_FILE
encrypt_file() {
    # Validate JSON before encrypting
    if ! jq empty "$TEMP_FILE" 2>/dev/null; then
        echo "❌ Internal error: Invalid JSON structure"
        audit_log "ENCRYPT_FAIL" "Invalid JSON before encryption"
        exit 1
    fi

    echo "$MASTER_PASSWORD" | openssl enc -aes-256-cbc -pbkdf2 -salt \
        -in "$TEMP_FILE" -pass stdin -out "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"  # Restrict file permissions
}

# ==============================================================================
# Password Generation
# ==============================================================================

# Generate a random password with guaranteed quality
generate_password() {
    local length=${1:-$DEFAULT_PASSWORD_LENGTH}
    local include_symbols=${2:-true}

    if [ "$length" -lt 1 ]; then
        length=$DEFAULT_PASSWORD_LENGTH
    fi

    local charset='A-Za-z0-9'
    if [ "$include_symbols" = true ]; then
        charset+='!@#$%^&*()_+-='
    fi

    local password=""
    local max_attempts=10
    local attempt=0

    while [ ${#password} -lt "$length" ] && [ "$attempt" -lt "$max_attempts" ]; do
        local candidate
        candidate=$(openssl rand -base64 256 | tr -dc "$charset" | head -c "$length")
        if [ ${#candidate} -ge "$length" ]; then
            password="$candidate"
        fi
        attempt=$((attempt + 1))
    done

    # Fallback: if still not enough, use /dev/urandom directly
    if [ ${#password} -lt "$length" ]; then
        password=$(cat /dev/urandom | tr -dc "$charset" | head -c "$length")
    fi

    # Ensure minimum character diversity
    if [ "$length" -ge 8 ]; then
        local has_upper has_lower has_digit
        has_upper=$(echo "$password" | grep -c '[A-Z]' || true)
        has_lower=$(echo "$password" | grep -c '[a-z]' || true)
        has_digit=$(echo "$password" | grep -c '[0-9]' || true)

        # If missing character types, regenerate critical positions
        if [ "$has_upper" -eq 0 ] || [ "$has_lower" -eq 0 ] || [ "$has_digit" -eq 0 ]; then
            local forced=""
            [ "$has_upper" -eq 0 ] && forced+="A"
            [ "$has_lower" -eq 0 ] && forced+="a"
            [ "$has_digit" -eq 0 ] && forced+="1"
            if [ "$include_symbols" = true ]; then
                forced+="!"
            fi

            # Append forced chars and trim
            password="${password:0:$((length - ${#forced}))}${forced}"
            # Shuffle
            password=$(echo "$password" | fold -w1 | shuf | tr -d '\n' | head -c "$length")
        fi
    fi

    echo "$password"
}

# ==============================================================================
# Clipboard Operations
# ==============================================================================

# Clear clipboard
clear_clipboard() {
    if command -v pbcopy >/dev/null 2>&1; then
        echo -n "" | pbcopy
    elif command -v xclip >/dev/null 2>&1; then
        echo -n "" | xclip -selection clipboard
    elif command -v wl-copy >/dev/null 2>&1; then
        echo -n "" | wl-copy
    fi
}

# Copy text to clipboard with auto-clear timeout
copy_clipboard() {
    local text="$1"

    if command -v pbcopy >/dev/null 2>&1; then
        echo -n "$text" | pbcopy
        echo "📋 Copied to clipboard (auto-clear in ${CLIPBOARD_TIMEOUT}s)"
    elif command -v xclip >/dev/null 2>&1; then
        echo -n "$text" | xclip -selection clipboard
        echo "📋 Copied to clipboard (auto-clear in ${CLIPBOARD_TIMEOUT}s)"
    elif command -v wl-copy >/dev/null 2>&1; then
        echo -n "$text" | wl-copy
        echo "📋 Copied to clipboard (auto-clear in ${CLIPBOARD_TIMEOUT}s)"
    else
        echo "⚠️ Clipboard not available. Install xclip (Linux) or use pbcopy (macOS)"
        return 1
    fi

    # Schedule clipboard clear in background
    (
        sleep "$CLIPBOARD_TIMEOUT"
        clear_clipboard 2>/dev/null || true
    ) &
}

# ==============================================================================
# Core Operations
# ==============================================================================

# Store a new username/password entry
store_password() {
    decrypt_file

    read -p "Service: " service
    if [ -z "$service" ]; then
        echo "❌ Service name cannot be empty"
        return
    fi

    read -p "Username: " username
    if [ -z "$username" ]; then
        echo "❌ Username cannot be empty"
        return
    fi

    echo ""
    echo "1) Enter password"
    echo "2) Generate password ($DEFAULT_PASSWORD_LENGTH characters)"
    echo "3) Generate password (custom length)"
    read -p "Choice: " pchoice

    local password=""
    case "$pchoice" in
        1)
            read -s -p "Password: " password
            echo ""
            if [ -z "$password" ]; then
                echo "❌ Password cannot be empty"
                return
            fi
            # Check password strength
            if ! check_password_strength "$password"; then
                read -p "Use this password anyway? (y/n): " force
                if [ "$force" != "y" ]; then
                    return
                fi
            fi
            ;;
        2)
            password=$(generate_password "$DEFAULT_PASSWORD_LENGTH")
            echo "✅ Generated password: $password"
            ;;
        3)
            read -p "Password length (default: $DEFAULT_PASSWORD_LENGTH): " length
            length=${length:-$DEFAULT_PASSWORD_LENGTH}

            # Validate length is a number
            if ! [[ "$length" =~ ^[0-9]+$ ]]; then
                echo "❌ Invalid length"
                return
            fi

            if [ "$length" -lt 8 ]; then
                echo "⚠️ Password length should be at least 8 characters"
                read -p "Continue anyway? (y/n): " force
                if [ "$force" != "y" ]; then
                    return
                fi
            fi

            read -p "Include symbols? (y/n): " include_symbols
            if [ "$include_symbols" = "y" ]; then
                password=$(generate_password "$length" true)
            else
                password=$(generate_password "$length" false)
            fi
            echo "✅ Generated password: $password"
            ;;
        *)
            echo "❌ Invalid option"
            return
            ;;
    esac

    # Use jq with proper parameter binding to prevent injection
    local escaped_service
    local escaped_username
    local escaped_password

    escaped_service=$(echo -n "$service" | jq -Rs '.')
    escaped_username=$(echo -n "$username" | jq -Rs '.')
    escaped_password=$(echo -n "$password" | jq -Rs '.')

    # Remove existing entry if present and add new one
    jq "map(select(.service != $escaped_service)) + [{\"service\": $escaped_service, \"username\": $escaped_username, \"password\": $escaped_password}]" \
        "$TEMP_FILE" > "$TEMP_FILE.tmp"
    mv "$TEMP_FILE.tmp" "$TEMP_FILE"

    encrypt_file
    audit_log "STORE" "Password stored for service: $service"
    echo "✅ Password stored successfully for service: $service"
}

# Retrieve a password by service name
retrieve_password() {
    decrypt_file
    read -p "Service: " service

    if [ -z "$service" ]; then
        echo "❌ Service name cannot be empty"
        return
    fi

    # Use jq parameter binding for safe query
    local escaped_service
    escaped_service=$(echo -n "$service" | jq -Rs '.')

    local result
    result=$(jq -r ".[] | select(.service | ascii_downcase == ($escaped_service | ascii_downcase))" "$TEMP_FILE")

    if [ -z "$result" ]; then
        echo "❌ Not found"
        return
    fi

    local username password
    username=$(echo "$result" | jq -r ".username")
    password=$(echo "$result" | jq -r ".password")

    echo ""
    echo "📝 Service: $service"
    echo "👤 Username: $username"
    echo "🔑 Password: $password"
    echo ""

    read -p "Copy password to clipboard? (y/n): " c
    if [ "$c" = "y" ]; then
        copy_clipboard "$password"
    fi

    audit_log "RETRIEVE" "Password retrieved for service: $service"
}

# Delete a password entry
delete_password() {
    decrypt_file

    echo "Stored services:"
    jq -r ".[].service" "$TEMP_FILE" | sort | nl
    echo ""

    read -p "Service to delete: " service

    if [ -z "$service" ]; then
        echo "❌ Service name cannot be empty"
        return
    fi

    local escaped_service
    escaped_service=$(echo -n "$service" | jq -Rs '.')

    # Check if service exists
    local count
    count=$(jq "[.[] | select(.service == $escaped_service)] | length" "$TEMP_FILE")

    if [ "$count" -eq 0 ]; then
        echo "❌ Service not found"
        return
    fi

    read -p "Are you sure you want to delete '$service'? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        jq "map(select(.service != $escaped_service))" "$TEMP_FILE" > "$TEMP_FILE.tmp"
        mv "$TEMP_FILE.tmp" "$TEMP_FILE"
        encrypt_file
        audit_log "DELETE" "Service deleted: $service"
        echo "✅ Service '$service' deleted successfully"
    else
        echo "Operation cancelled"
    fi
}

# Edit an existing password entry
edit_password() {
    decrypt_file

    echo "Stored services:"
    jq -r ".[].service" "$TEMP_FILE" | sort | nl
    echo ""

    read -p "Service to edit: " service

    if [ -z "$service" ]; then
        echo "❌ Service name cannot be empty"
        return
    fi

    local escaped_service
    escaped_service=$(echo -n "$service" | jq -Rs '.')

    # Get current entry
    local current
    current=$(jq -r ".[] | select(.service == $escaped_service)" "$TEMP_FILE")

    if [ -z "$current" ]; then
        echo "❌ Service not found"
        return
    fi

    local current_username current_password
    current_username=$(echo "$current" | jq -r ".username")
    current_password=$(echo "$current" | jq -r ".password")

    echo "Current username: $current_username"
    read -p "New username (leave empty to keep current): " new_username
    new_username=${new_username:-$current_username}

    # Allow changing service name
    echo "Current service: $service"
    read -p "New service name (leave empty to keep current): " new_service
    new_service=${new_service:-$service}

    echo ""
    echo "1) Enter new password"
    echo "2) Generate new password"
    echo "3) Keep current password"
    read -p "Choice: " pchoice

    local new_password=""
    case "$pchoice" in
        1)
            read -s -p "New password: " new_password
            echo ""
            if [ -z "$new_password" ]; then
                echo "❌ Password cannot be empty"
                return
            fi
            # Check password strength
            if ! check_password_strength "$new_password"; then
                read -p "Use this password anyway? (y/n): " force
                if [ "$force" != "y" ]; then
                    return
                fi
            fi
            ;;
        2)
            new_password=$(generate_password "$DEFAULT_PASSWORD_LENGTH")
            echo "✅ Generated password: $new_password"
            ;;
        3)
            new_password="$current_password"
            ;;
        *)
            echo "❌ Invalid option"
            return
            ;;
    esac

    # Build the update - if service name changed, create new entry and delete old
    local escaped_new_service escaped_new_username escaped_new_password
    escaped_new_service=$(echo -n "$new_service" | jq -Rs '.')
    escaped_new_username=$(echo -n "$new_username" | jq -Rs '.')
    escaped_new_password=$(echo -n "$new_password" | jq -Rs '.')

    if [ "$service" != "$new_service" ]; then
        # Service name changed - delete old, add new
        jq "map(select(.service != $escaped_service)) + [{\"service\": $escaped_new_service, \"username\": $escaped_new_username, \"password\": $escaped_new_password}]" \
            "$TEMP_FILE" > "$TEMP_FILE.tmp"
        audit_log "EDIT" "Service renamed: $service -> $new_service"
    else
        # Service name unchanged - update in place
        jq "map(if .service == $escaped_service then .username = $escaped_new_username | .password = $escaped_new_password else . end)" \
            "$TEMP_FILE" > "$TEMP_FILE.tmp"
    fi
    mv "$TEMP_FILE.tmp" "$TEMP_FILE"

    encrypt_file
    audit_log "EDIT" "Service updated: $new_service"
    echo "✅ Service '$new_service' updated successfully"
}

# List all stored service names
list_passwords() {
    decrypt_file

    local count
    count=$(jq '. | length' "$TEMP_FILE")

    if [ "$count" -eq 0 ]; then
        echo "📭 No passwords stored yet"
        return
    fi

    echo "📊 Stored services ($count entries):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    jq -r '.[] | "  • \(.service) (\(.username))"' "$TEMP_FILE" | sort
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    audit_log "LIST" "Listed $count services"
}

# Search for services
search_passwords() {
    decrypt_file
    read -p "Search query: " query

    if [ -z "$query" ]; then
        echo "❌ Search query cannot be empty"
        return
    fi

    # Escape the query for safe regex use (literal string match)
    local escaped_query
    escaped_query=$(echo -n "$query" | jq -Rs '.')

    # Use index() for safe substring search instead of test() with regex
    local results
    results=$(jq -r "[.[] | select(.service | ascii_downcase | contains($escaped_query | ascii_downcase))] | .[] | \"  • \(.service) (\(.username))\"" "$TEMP_FILE" 2>/dev/null)

    if [ -z "$results" ]; then
        echo "❌ No services found matching '$query'"
        return
    fi

    echo "🔍 Search results for '$query':"
    echo "$results"

    audit_log "SEARCH" "Searched for: $query"
}

# ==============================================================================
# Import/Export Operations
# ==============================================================================

# Export passwords to a JSON file (unencrypted - for backup purposes)
export_passwords() {
    decrypt_file

    read -p "Export filename: " filename
    if [ -z "$filename" ]; then
        echo "❌ Filename cannot be empty"
        return
    fi

    # Ensure absolute path
    if [[ "$filename" != /* ]]; then
        filename="$APP_DIR/$filename"
    fi

    cp "$TEMP_FILE" "$filename"
    chmod 600 "$filename"

    local count
    count=$(jq '. | length' "$TEMP_FILE")

    echo "⚠️  WARNING: Exported file is UNENCRYPTED!"
    echo "✅ $count passwords exported to: $filename"
    echo "🔒 Delete this file after use or encrypt it manually"

    audit_log "EXPORT" "Exported $count passwords to: $filename"
}

# Import passwords from a JSON file
import_passwords() {
    decrypt_file

    read -p "Import filename: " filename
    if [ -z "$filename" ]; then
        echo "❌ Filename cannot be empty"
        return
    fi

    # Ensure absolute path
    if [[ "$filename" != /* ]]; then
        filename="$APP_DIR/$filename"
    fi

    if [ ! -f "$filename" ]; then
        echo "❌ File not found: $filename"
        return
    fi

    # Validate JSON
    if ! jq empty "$filename" 2>/dev/null; then
        echo "❌ Invalid JSON file"
        return
    fi

    # Validate structure
    local import_type
    import_type=$(jq -r 'type' "$filename")
    if [ "$import_type" != "array" ]; then
        echo "❌ Invalid format: expected a JSON array"
        return
    fi

    # Count existing services
    local existing_count
    existing_count=$(jq '. | length' "$TEMP_FILE")

    # Merge imported passwords with existing ones (skip duplicates by service name)
    jq --slurpfile imported "$filename" '
        . as $existing |
        reduce ($imported[0][] | select(type == "object" and has("service") and has("password"))) as $item (
            $existing;
            if any(.[]; .service == $item.service) then . else . + [$item] end
        )
    ' "$TEMP_FILE" > "$TEMP_FILE.tmp" 2>/dev/null

    if ! jq empty "$TEMP_FILE.tmp" 2>/dev/null; then
        echo "❌ Error merging data"
        rm -f "$TEMP_FILE.tmp"
        return
    fi

    mv "$TEMP_FILE.tmp" "$TEMP_FILE"

    local new_count
    new_count=$(jq '. | length' "$TEMP_FILE")
    local imported=$((new_count - existing_count))

    encrypt_file

    local total_imported
    total_imported=$(jq '. | length' "$filename")
    echo "✅ Imported $imported new entries ($((total_imported - imported)) duplicates skipped)"

    audit_log "IMPORT" "Imported $imported/$total_imported entries from: $filename"
}

# ==============================================================================
# Configuration Management
# ==============================================================================

# Configure password manager settings
configure_settings() {
    echo ""
    echo "⚙️  Configuration"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [ -f "$CONFIG_FILE" ]; then
        echo "Current settings:"
        echo "  • Default password length: $(jq -r '.password_length' "$CONFIG_FILE")"
        echo "  • Clipboard timeout: $(jq -r '.clipboard_timeout' "$CONFIG_FILE")s"
        echo "  • Password file: $(jq -r '.password_file' "$CONFIG_FILE")"
    else
        echo "No custom configuration found. Using defaults."
    fi
    echo ""

    echo "1. Change default password length"
    echo "2. Change clipboard clear timeout"
    echo "3. Change password file location"
    echo "4. Reset to defaults"
    echo "5. Back to menu"
    read -p "Choice: " setting_choice

    case "$setting_choice" in
        1)
            read -p "Set default password length (current: $DEFAULT_PASSWORD_LENGTH): " new_length
            if [ -n "$new_length" ]; then
                if ! [[ "$new_length" =~ ^[0-9]+$ ]] || [ "$new_length" -lt 8 ]; then
                    echo "❌ Invalid length. Must be at least 8 characters"
                    return
                fi
                DEFAULT_PASSWORD_LENGTH="$new_length"
                save_config "$DEFAULT_PASSWORD_LENGTH"
                audit_log "CONFIG" "Password length changed to $new_length"
                echo "✅ Configuration updated"
            fi
            ;;
        2)
            read -p "Set clipboard timeout in seconds (current: $CLIPBOARD_TIMEOUT): " new_timeout
            if [ -n "$new_timeout" ]; then
                if ! [[ "$new_timeout" =~ ^[0-9]+$ ]] || [ "$new_timeout" -lt 5 ]; then
                    echo "❌ Invalid timeout. Must be at least 5 seconds"
                    return
                fi
                CLIPBOARD_TIMEOUT="$new_timeout"
                save_config "$DEFAULT_PASSWORD_LENGTH"
                audit_log "CONFIG" "Clipboard timeout changed to $new_timeout"
                echo "✅ Configuration updated"
            fi
            ;;
        3)
            read -p "Set password file path (current: $PASSWORD_FILE): " new_path
            if [ -n "$new_path" ]; then
                if [[ "$new_path" != /* ]]; then
                    new_path="$APP_DIR/$new_path"
                fi
                PASSWORD_FILE="$new_path"
                save_config "$DEFAULT_PASSWORD_LENGTH"
                audit_log "CONFIG" "Password file changed to $new_path"
                echo "✅ Configuration updated"
            fi
            ;;
        4)
            rm -f "$CONFIG_FILE"
            DEFAULT_PASSWORD_LENGTH=16
            CLIPBOARD_TIMEOUT=30
            PASSWORD_FILE="$APP_DIR/passwords.enc"
            audit_log "CONFIG" "Settings reset to defaults"
            echo "✅ Settings reset to defaults"
            ;;
        5)
            return
            ;;
        *)
            echo "❌ Invalid option"
            ;;
    esac
}

# ==============================================================================
# Main Menu
# ==============================================================================

# Main menu loop
main_menu() {
    while true; do
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  🔐 Password Manager"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  1. Store a password"
        echo "  2. Retrieve a password"
        echo "  3. List stored services"
        echo "  4. Search services"
        echo "  5. Edit a password"
        echo "  6. Delete a password"
        echo "  7. Import passwords"
        echo "  8. Export passwords"
        echo "  9. Settings"
        echo "  10. Exit"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        read -p "  Choice: " choice

        case $choice in
            1) store_password ;;
            2) retrieve_password ;;
            3) list_passwords ;;
            4) search_passwords ;;
            5) edit_password ;;
            6) delete_password ;;
            7) import_passwords ;;
            8) export_passwords ;;
            9) configure_settings ;;
            10) audit_log "EXIT" "Application exited"; echo "👋 Goodbye!"; exit 0 ;;
            *) echo "❌ Invalid option" ;;
        esac
    done
}

# ==============================================================================
# Application Entry Point
# ==============================================================================

# Load configuration
load_config

# Prompt for master password
prompt_master_password

# Start main menu
main_menu
