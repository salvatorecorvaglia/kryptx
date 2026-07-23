#!/bin/bash

set -euo pipefail

# Verify dependencies are installed
for cmd in openssl jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf '❌ Error: "%s" is required but not installed.\n' "$cmd" >&2
        exit 1
    fi
done

# ==============================================================================
# Configuration and Global Variables
# ==============================================================================

# Application directory (resilient to working directory changes)
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# XDG Base Directory Specification paths
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kryptx"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/kryptx"

# Ensure directories exist with strict permissions
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chmod 700 "$CONFIG_DIR" "$DATA_DIR" 2>/dev/null || true

# Encrypted password storage file (configurable via config)
PASSWORD_FILE="$DATA_DIR/passwords.enc"

# Audit log file
AUDIT_LOG="$DATA_DIR/kryptx-audit.log"

# Temp file for decrypted data — prefer RAM-backed tmpfs to avoid disk writes
TEMP_FILE=""
TEMP_FILES_TO_CLEAN=()

# Configuration file
CONFIG_FILE="$CONFIG_DIR/kryptx-config.json"

# Default password length
DEFAULT_PASSWORD_LENGTH=16

# Clipboard clear timeout (seconds)
CLIPBOARD_TIMEOUT=30

# Max failed attempts before lockout
MAX_FAILED_ATTEMPTS=5

# Master password — cleared on exit
MASTER_PASSWORD=""

# HMAC key — derived via PBKDF2 and cached in memory, cleared on exit
HMAC_KEY=""

# Background PID for clipboard clear timer
_CLIP_PID=""

# PBKDF2 iteration count — pinned explicitly so strength doesn't depend on
# whichever OpenSSL version happens to be installed
PBKDF2_ITER=600000

# ==============================================================================
# Cleanup & Security Functions
# ==============================================================================

# Securely overwrite and delete a file
secure_remove_file() {
    local f="$1"
    if [ -f "$f" ]; then
        if command -v shred >/dev/null 2>&1; then
            shred -u -- "$f" 2>/dev/null || rm -f -- "$f"
        elif command -v srm >/dev/null 2>&1; then
            srm -z -- "$f" 2>/dev/null || rm -f -- "$f"
        else
            local size
            size=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null || echo "0")
            if [ "$size" -gt 0 ] 2>/dev/null; then
                local blocks=$(( (size + 4095) / 4096 ))
                dd if=/dev/urandom of="$f" bs=4096 count="$blocks" conv=notrunc 2>/dev/null || true
            fi
            rm -f -- "$f"
        fi
    fi
}

# Secure cleanup: zero temp files, clear clipboard, kill background timers
secure_cleanup() {
    # Kill clipboard-clear timer if still running
    if [ -n "$_CLIP_PID" ]; then
        kill "$_CLIP_PID" 2>/dev/null || true
        _CLIP_PID=""
    fi
    # Always clear clipboard on exit
    clear_clipboard 2>/dev/null || true

    # Securely overwrite and delete temp files
    for f in "${TEMP_FILES_TO_CLEAN[@]}"; do
        secure_remove_file "$f"
    done

    # Clear master password and HMAC key from shell memory
    MASTER_PASSWORD=""
    HMAC_KEY=""
}

# Create temp file — prefer /dev/shm (RAM-backed) to avoid any disk write
_make_tempfile() {
    local f
    if [ -d /dev/shm ] && [ -w /dev/shm ]; then
        f=$(mktemp /dev/shm/kryptx.XXXXXXXXXX)
    else
        f=$(mktemp)
    fi
    chmod 600 "$f"
    printf '%s\n' "$f"
}

# Bootstrap temp file and trap
TEMP_FILE=$(_make_tempfile)
TEMP_FILES_TO_CLEAN+=("$TEMP_FILE" "${TEMP_FILE}.tmp")
trap secure_cleanup EXIT INT TERM HUP QUIT

# ==============================================================================
# Helper Functions
# ==============================================================================

# Load configuration from config file
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        if jq empty "$CONFIG_FILE" 2>/dev/null; then
            DEFAULT_PASSWORD_LENGTH=$(jq -r '.password_length // 16' "$CONFIG_FILE" 2>/dev/null || echo "16")
            CLIPBOARD_TIMEOUT=$(jq -r '.clipboard_timeout // 30' "$CONFIG_FILE" 2>/dev/null || echo "30")
            local custom_password_file
            custom_password_file=$(jq -r '.password_file // ""' "$CONFIG_FILE" 2>/dev/null || echo "")
            if [ -n "$custom_password_file" ]; then
                PASSWORD_FILE="$custom_password_file"
            fi
        fi
    fi
}

# Save configuration to config file
save_config() {
    local config_json
    if [ -f "$CONFIG_FILE" ] && jq empty "$CONFIG_FILE" 2>/dev/null; then
        config_json=$(cat "$CONFIG_FILE")
    else
        config_json="{}"
    fi

    # Ensure parent directory exists
    local parent_dir
    parent_dir=$(dirname "$CONFIG_FILE")
    mkdir -p "$parent_dir"
    chmod 700 "$parent_dir" 2>/dev/null || true

    if ! printf '%s\n' "$config_json" | jq \
        --argjson pl "${1:-$DEFAULT_PASSWORD_LENGTH}" \
        --argjson ct "${CLIPBOARD_TIMEOUT}" \
        --arg pf "$PASSWORD_FILE" \
        '.password_length = $pl | .clipboard_timeout = $ct | .password_file = $pf' \
        > "$CONFIG_FILE.tmp" 2>/dev/null; then
        echo "❌ Failed to update configuration file" >&2
        rm -f -- "$CONFIG_FILE.tmp"
        return 1
    fi

    if [ -f "$CONFIG_FILE.tmp" ]; then
        mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
    fi
}

# Audit logging — records only action types, never service names or usernames,
# to avoid creating a plaintext map of the user's credentials.
audit_log() {
    local action="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $action" >> "$AUDIT_LOG"
    chmod 600 "$AUDIT_LOG" 2>/dev/null || true
}

# Check password strength
check_password_strength() {
    local password="$1"
    local length=${#password}
    local score=0
    local warn_upper="" warn_lower="" warn_digit="" warn_special=""

    if [ "$length" -lt 8 ]; then
        printf 'Password is too weak:\n'
        printf '   Warning: Password is too short (min 8 chars)\n'
        return 1
    fi

    [[ "$password" =~ [A-Z] ]] && score=$((score + 1)) || warn_upper="YES"
    [[ "$password" =~ [a-z] ]] && score=$((score + 1)) || warn_lower="YES"
    [[ "$password" =~ [0-9] ]] && score=$((score + 1)) || warn_digit="YES"
    [[ "$password" =~ [^A-Za-z0-9] ]] && score=$((score + 1)) || warn_special="YES"

    if [ "$score" -lt 2 ]; then
        printf 'Password is too weak:\n'
        [ -n "$warn_upper"   ] && printf '   Warning: No uppercase letters\n'
        [ -n "$warn_lower"   ] && printf '   Warning: No lowercase letters\n'
        [ -n "$warn_digit"   ] && printf '   Warning: No digits\n'
        [ -n "$warn_special" ] && printf '   Warning: No special characters\n'
        return 1
    fi

    if [ "$length" -lt 12 ] || [ -n "$warn_upper" ] || [ -n "$warn_lower" ] || \
       [ -n "$warn_digit" ] || [ -n "$warn_special" ]; then
        printf 'Password could be stronger:\n'
        [ "$length" -lt 12  ] && printf '   Tip: Consider using at least 12 characters\n'
        [ -n "$warn_upper"  ] && printf '   Tip: Add uppercase letters\n'
        [ -n "$warn_lower"  ] && printf '   Tip: Add lowercase letters\n'
        [ -n "$warn_digit"  ] && printf '   Tip: Add digits\n'
        [ -n "$warn_special" ] && printf '   Tip: Add special characters\n'
    fi

    return 0
}

# ==============================================================================
# Encryption / Decryption (AES-256-CBC + HMAC-SHA256 encrypt-then-MAC)
#
# File format:  <hmac_hex>:<base64(ciphertext)>
#
# The master password is passed via file descriptor 3 (never via argv or env)
# so it does not appear in /proc/<pid>/cmdline or ps output.
#
# PBKDF2 iterations are pinned at $PBKDF2_ITER (600,000) regardless of which
# OpenSSL version is installed.
# ==============================================================================

# Derive an HMAC key distinct from the encryption key
_hmac_key() {
    echo -n "$HMAC_KEY"
}

# Encrypt TEMP_FILE → PASSWORD_FILE with HMAC integrity tag
encrypt_file() {
    # Validate JSON before encrypting
    if ! jq empty "$TEMP_FILE" 2>/dev/null; then
        echo "❌ Internal error: invalid JSON structure"
        audit_log "ENCRYPT_FAIL: invalid JSON"
        exit 1
    fi

    local ct_file
    ct_file=$(_make_tempfile)
    TEMP_FILES_TO_CLEAN+=("$ct_file")

    # Encrypt — password via fd:3, never via argv
    openssl enc -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" -md sha256 -salt \
        -in "$TEMP_FILE" -pass fd:3 -out "$ct_file" 3<<<"$MASTER_PASSWORD" 2>/dev/null || {
        echo "❌ Encryption failed"
        audit_log "ENCRYPT_FAIL"
        exit 1
    }

    # Compute HMAC over the ciphertext (encrypt-then-MAC)
    local hmac
    hmac=$(openssl dgst -sha256 -hmac "$(_hmac_key)" "$ct_file" | awk '{print $NF}')

    # Bundle as  hmac_hex:base64(ciphertext)
    local ct_b64
    ct_b64=$(base64 < "$ct_file" | tr -d '\n')
    local p_dir
    p_dir=$(dirname "$PASSWORD_FILE")
    mkdir -p "$p_dir"
    chmod 700 "$p_dir" 2>/dev/null || true
    printf '%s:%s\n' "$hmac" "$ct_b64" > "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"

    # Securely remove intermediate ciphertext temp file
    secure_remove_file "$ct_file"
}

# Decrypt PASSWORD_FILE → TEMP_FILE, verifying the HMAC first
decrypt_file() {
    if [ ! -f "$PASSWORD_FILE" ]; then
        echo "[]" > "$TEMP_FILE"
        return
    fi

    local bundle
    bundle=$(cat "$PASSWORD_FILE")

    local stored_hmac ct_b64
    stored_hmac="${bundle%%:*}"
    ct_b64="${bundle#*:}"

    if [ -z "$stored_hmac" ] || [ -z "$ct_b64" ]; then
        echo "❌ Corrupted vault file (bad format)"
        audit_log "DECRYPT_FAIL: bad format"
        exit 1
    fi

    local ct_file
    ct_file=$(_make_tempfile)
    TEMP_FILES_TO_CLEAN+=("$ct_file")
    printf '%s' "$ct_b64" | base64 -d > "$ct_file"

    # Verify HMAC before decrypting to detect tampering
    local computed_hmac
    computed_hmac=$(openssl dgst -sha256 -hmac "$(_hmac_key)" "$ct_file" | awk '{print $NF}')

    if [ "$stored_hmac" != "$computed_hmac" ]; then
        echo "❌ Wrong password or vault has been tampered with"
        audit_log "DECRYPT_FAIL: HMAC mismatch"
        secure_remove_file "$ct_file"
        return 1
    fi

    # Decrypt — password via fd:3
    openssl enc -d -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" -md sha256 \
        -in "$ct_file" -pass fd:3 -out "$TEMP_FILE" 3<<<"$MASTER_PASSWORD" 2>/dev/null || {
        echo "❌ Decryption failed"
        audit_log "DECRYPT_FAIL"
        secure_remove_file "$ct_file"
        return 1
    }

    secure_remove_file "$ct_file"

    # Validate JSON structure
    if ! jq empty "$TEMP_FILE" 2>/dev/null; then
        echo "❌ Corrupted vault (invalid JSON after decryption)"
        audit_log "DECRYPT_FAIL: invalid JSON"
        exit 1
    fi
}

# ==============================================================================
# Master Password Prompt (with rate limiting)
# ==============================================================================

prompt_master_password() {
    local attempt=1
    local lock_file="$DATA_DIR/.kryptx-lock"

    # Enforce lockout based on lock file mtime
    if [ -f "$lock_file" ]; then
        local now_ts lock_mtime lock_age wait_secs
        now_ts=$(date +%s)
        lock_mtime=$(stat -f%m "$lock_file" 2>/dev/null || stat -c%Y "$lock_file" 2>/dev/null || echo "0")
        lock_age=$((now_ts - lock_mtime))
        if [ "$lock_age" -lt 300 ]; then
            wait_secs=$((300 - lock_age))
            echo "🔒 Security lock active. Too many failed attempts."
            echo "   Please wait $wait_secs seconds before retrying."
            exit 1
        else
            rm -f "$lock_file"
        fi
    fi

    while [ "$attempt" -le "$MAX_FAILED_ATTEMPTS" ]; do
        printf "Enter your master password (attempt %d/%d):\n" "$attempt" "$MAX_FAILED_ATTEMPTS"
        read -rs MASTER_PASSWORD || true
        echo ""

        if [ -z "$MASTER_PASSWORD" ]; then
            echo "❌ Master password cannot be empty"
            attempt=$((attempt + 1))
            continue
        fi

        # Derive HMAC key using PBKDF2 over a static seed
        HMAC_KEY=$(echo -n "kryptx-hmac-key-seed-v1" | openssl enc -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" -md sha256 -nosalt -pass fd:3 3<<<"$MASTER_PASSWORD" 2>/dev/null | base64 | tr -d '\n')

        if [ -f "$PASSWORD_FILE" ]; then
            # Try to decrypt; authenticate by HMAC match inside decrypt_file
            if decrypt_file 2>/dev/null; then
                audit_log "UNLOCK: accepted (attempt $attempt)"
                return 0
            fi
            echo "❌ Wrong password or corrupted vault"
            audit_log "AUTH_FAIL: attempt $attempt/$MAX_FAILED_ATTEMPTS"
            MASTER_PASSWORD=""
            HMAC_KEY=""
        else
            # First run — confirm password
            echo "Confirm your master password:"
            local confirm=""
            read -rs confirm || true
            echo ""

            # Constant-time-ish comparison via hashes to avoid trivial timing leaks
            local h1 h2
            h1=$(printf '%s' "$MASTER_PASSWORD" | openssl dgst -sha256 | awk '{print $NF}')
            h2=$(printf '%s' "$confirm"          | openssl dgst -sha256 | awk '{print $NF}')

            if [ "$h1" != "$h2" ]; then
                echo "❌ Passwords do not match"
                audit_log "MISMATCH: confirmation failed"
                MASTER_PASSWORD=""
                HMAC_KEY=""
                attempt=$((attempt + 1))
                continue
            fi

            if [ "${#MASTER_PASSWORD}" -lt 8 ]; then
                echo "❌ Master password must be at least 8 characters"
                MASTER_PASSWORD=""
                HMAC_KEY=""
                attempt=$((attempt + 1))
                continue
            fi

            audit_log "INIT: new vault created"
            echo "[]" > "$TEMP_FILE"
            encrypt_file
            return 0
        fi

        attempt=$((attempt + 1))
    done

    # Activate lockout
    touch "$lock_file"
    chmod 600 "$lock_file"
    audit_log "LOCKOUT: activated after $MAX_FAILED_ATTEMPTS failed attempts"
    echo "🔒 Too many failed attempts. Security lock activated for 5 minutes."
    exit 1
}

# ==============================================================================
# Password Generation
# ==============================================================================

generate_password() {
    local length=${1:-$DEFAULT_PASSWORD_LENGTH}
    local include_symbols=${2:-true}

    [ "$length" -lt 1 ] && length=$DEFAULT_PASSWORD_LENGTH

    local charset='A-Za-z0-9'
    [ "$include_symbols" = true ] && charset+='!@#$%^&*()_+-='

    local password=""
    local attempt=0
    local max_attempts=10

    while [ "${#password}" -lt "$length" ] && [ "$attempt" -lt "$max_attempts" ]; do
        local candidate
        candidate=$(LC_ALL=C tr -dc "$charset" < <(openssl rand 1000 2>/dev/null) | head -c "$length")
        [ "${#candidate}" -ge "$length" ] && password="$candidate"
        attempt=$((attempt + 1))
    done

    # Fallback
    if [ "${#password}" -lt "$length" ]; then
        password=$(LC_ALL=C tr -dc "$charset" < /dev/urandom | head -c "$length")
    fi

    # Ensure character-class diversity by replacing random positions using
    # openssl-derived offsets (avoids the entropy-reducing append-and-shuffle
    # approach that was used before)
    if [ "$length" -ge 8 ]; then
        local arr=()
        # Split password into character array
        local i
        for (( i=0; i<length; i++ )); do
            arr+=("${password:i:1}")
        done
        local arr_len=${#arr[@]}

        # Pick injection positions via raw openssl rand to keep entropy high (no base64 bias)
        local rand_positions
        rand_positions=$(openssl rand 16 | od -An -tu1 | tr ' ' '\n' | grep -v '^$' | head -4)
        local pos_arr=()
        while IFS= read -r v; do pos_arr+=("$v"); done <<< "$rand_positions"

        local used_indices=()
        local pi=0
        if ! [[ "$password" =~ [A-Z] ]]; then
            local raw_val=${pos_arr[$pi]:-0}
            local idx=$(( raw_val % arr_len ))
            while [ "${used_indices[$idx]:-0}" -eq 1 ]; do idx=$(( (idx + 1) % arr_len )); done
            used_indices[$idx]=1
            local ch_idx=$(( raw_val % 26 ))
            local uppers="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            arr[$idx]="${uppers:ch_idx:1}"
            pi=$((pi + 1))
        fi
        if ! [[ "$password" =~ [a-z] ]]; then
            local raw_val=${pos_arr[$pi]:-1}
            local idx=$(( raw_val % arr_len ))
            while [ "${used_indices[$idx]:-0}" -eq 1 ]; do idx=$(( (idx + 1) % arr_len )); done
            used_indices[$idx]=1
            local ch_idx=$(( raw_val % 26 ))
            local lowers="abcdefghijklmnopqrstuvwxyz"
            arr[$idx]="${lowers:ch_idx:1}"
            pi=$((pi + 1))
        fi
        if ! [[ "$password" =~ [0-9] ]]; then
            local raw_val=${pos_arr[$pi]:-2}
            local idx=$(( raw_val % arr_len ))
            while [ "${used_indices[$idx]:-0}" -eq 1 ]; do idx=$(( (idx + 1) % arr_len )); done
            used_indices[$idx]=1
            local ch_idx=$(( raw_val % 10 ))
            local digits="0123456789"
            arr[$idx]="${digits:ch_idx:1}"
            pi=$((pi + 1))
        fi
        if [ "$include_symbols" = true ] && ! [[ "$password" =~ [^A-Za-z0-9] ]]; then
            local raw_val=${pos_arr[$pi]:-3}
            local idx=$(( raw_val % arr_len ))
            while [ "${used_indices[$idx]:-0}" -eq 1 ]; do idx=$(( (idx + 1) % arr_len )); done
            used_indices[$idx]=1
            local syms='!@#$%^&*()_+-='
            local sym_idx=$(( raw_val % ${#syms} ))
            arr[$idx]="${syms:sym_idx:1}"
        fi

        password=$(printf '%s' "${arr[@]}")
        password="${password:0:$length}"
    fi

    printf '%s' "$password"
}

# ==============================================================================
# Clipboard Operations
# ==============================================================================

clear_clipboard() {
    if command -v pbcopy >/dev/null 2>&1; then
        printf '' | pbcopy
    elif command -v xclip >/dev/null 2>&1; then
        printf '' | xclip -selection clipboard
    elif command -v wl-copy >/dev/null 2>&1; then
        printf '' | wl-copy
    fi
}

# Copy to clipboard; schedule auto-clear; track background PID for cleanup
copy_clipboard() {
    local text="$1"

    if command -v pbcopy >/dev/null 2>&1; then
        printf '%s' "$text" | pbcopy
    elif command -v xclip >/dev/null 2>&1; then
        printf '%s' "$text" | xclip -selection clipboard
    elif command -v wl-copy >/dev/null 2>&1; then
        printf '%s' "$text" | wl-copy
    else
        echo "⚠️  Clipboard not available. Install xclip (Linux) or use pbcopy (macOS)"
        return 1
    fi

    echo "📋 Copied to clipboard (auto-clear in ${CLIPBOARD_TIMEOUT}s)"

    # Kill any previous timer before starting a new one
    if [ -n "$_CLIP_PID" ]; then
        kill "$_CLIP_PID" 2>/dev/null || true
    fi

    ( sleep "$CLIPBOARD_TIMEOUT"; clear_clipboard 2>/dev/null ) &
    _CLIP_PID=$!
}

# ==============================================================================
# Core Operations
# ==============================================================================

store_password() {
    decrypt_file

    read -rp "Service: " service
    [ -z "$service" ] && { echo "❌ Service name cannot be empty"; return; }

    read -rp "Username: " username
    [ -z "$username" ] && { echo "❌ Username cannot be empty"; return; }

    echo ""
    echo "1) Enter password"
    echo "2) Generate password ($DEFAULT_PASSWORD_LENGTH characters)"
    echo "3) Generate password (custom length)"
    read -rp "Choice: " pchoice

    local password=""
    case "$pchoice" in
        1)
            read -rs -p "Password: " password; echo ""
            [ -z "$password" ] && { echo "❌ Password cannot be empty"; return; }
            if ! check_password_strength "$password"; then
                read -rp "Use this password anyway? (y/n): " force
                [ "$force" != "y" ] && return
            fi
            ;;
        2)
            password=$(generate_password "$DEFAULT_PASSWORD_LENGTH")
            echo "✅ Password generated."
            read -rp "Copy to clipboard? (y/n): " c
            if [ "$c" = "y" ]; then
                copy_clipboard "$password" || true
            fi
            ;;
        3)
            read -rp "Password length (default: $DEFAULT_PASSWORD_LENGTH): " length
            length=${length:-$DEFAULT_PASSWORD_LENGTH}
            if ! [[ "$length" =~ ^[0-9]+$ ]]; then
                echo "❌ Invalid length"; return
            fi
            if [ "$length" -lt 8 ]; then
                echo "⚠️  Password length should be at least 8 characters"
                read -rp "Continue anyway? (y/n): " force
                [ "$force" != "y" ] && return
            fi
            read -rp "Include symbols? (y/n): " inc_sym
            if [ "$inc_sym" = "y" ]; then
                password=$(generate_password "$length" true)
            else
                password=$(generate_password "$length" false)
            fi
            echo "✅ Password generated."
            read -rp "Copy to clipboard? (y/n): " c
            if [ "$c" = "y" ]; then
                copy_clipboard "$password" || true
            fi
            ;;
        *)
            echo "❌ Invalid option"; return ;;
    esac

    jq --arg svc "$service" --arg usr "$username" --arg pw "$password" \
        'map(select((.service | ascii_downcase) != ($svc | ascii_downcase) or .username != $usr)) + [{"service": $svc, "username": $usr, "password": $pw}]' \
        "$TEMP_FILE" > "${TEMP_FILE}.tmp"
    mv "${TEMP_FILE}.tmp" "$TEMP_FILE"

    encrypt_file
    audit_log "STORE: new entry saved"
    echo "✅ Password stored successfully for $service ($username)"
}

# Helper: Displays stored accounts and prompts user to pick an entry by list number OR service query.
# Sets globals: SELECTED_SERVICE, SELECTED_USERNAME, SELECTED_PASSWORD
_select_account_entry() {
    local prompt_verb="${1:-select}"
    local initial_query="${2:-}"

    SELECTED_SERVICE=""
    SELECTED_USERNAME=""
    SELECTED_PASSWORD=""

    local all_entries
    all_entries=$(jq -c '. | sort_by([(.service | ascii_downcase), .username])' "$TEMP_FILE")

    local total_count
    total_count=$(jq '. | length' "$TEMP_FILE")

    if [ "$total_count" -eq 0 ]; then
        echo "📭 Vault is empty"
        return 1
    fi

    local target_input=""
    if [ -n "$initial_query" ]; then
        target_input="$initial_query"
    else
        echo "Stored accounts:"
        local i=1
        while IFS= read -r entry; do
            if [ -n "$entry" ]; then
                local svc usr
                svc=$(jq -r '.service' <<< "$entry")
                usr=$(jq -r '.username' <<< "$entry")
                printf "  %2d) %s (%s)\n" "$i" "$svc" "$usr"
                i=$((i + 1))
            fi
        done < <(jq -c '.[]' <<< "$all_entries")
        echo ""
        read -rp "Service to $prompt_verb (enter number 1-$total_count or service name): " target_input
    fi

    [ -z "$target_input" ] && { echo "❌ Input cannot be empty"; return 1; }

    # Option A: User entered a list number
    if [[ "$target_input" =~ ^[0-9]+$ ]] && [ "$target_input" -ge 1 ] && [ "$target_input" -le "$total_count" ]; then
        local chosen_entry
        chosen_entry=$(jq -c --argjson idx "$((target_input - 1))" '.[$idx]' <<< "$all_entries")
        SELECTED_SERVICE=$(jq -r '.service' <<< "$chosen_entry")
        SELECTED_USERNAME=$(jq -r '.username' <<< "$chosen_entry")
        SELECTED_PASSWORD=$(jq -r '.password' <<< "$chosen_entry")
        return 0
    fi

    # Option B: User entered a service name (or query)
    local matches
    matches=$(jq -c --arg q "$target_input" '.[] | select(.service | ascii_downcase == ($q | ascii_downcase))' <<< "$all_entries")
    local match_count
    match_count=$(printf '%s' "$matches" | grep -c '^' || true)

    if [ "$match_count" -eq 0 ] || [ -z "$matches" ]; then
        echo "❌ Service '$target_input' not found"
        return 1
    elif [ "$match_count" -eq 1 ]; then
        SELECTED_SERVICE=$(jq -r '.service' <<< "$matches")
        SELECTED_USERNAME=$(jq -r '.username' <<< "$matches")
        SELECTED_PASSWORD=$(jq -r '.password' <<< "$matches")
        return 0
    else
        echo "Multiple accounts found for service '$target_input':"
        local i=1
        local match_list=()
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                local usr
                usr=$(jq -r '.username' <<< "$line")
                match_list+=("$line")
                echo "  $i) $usr"
                i=$((i + 1))
            fi
        done <<< "$matches"

        read -rp "Select username to $prompt_verb (1-$((i-1))): " choice
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge "$i" ]; then
            echo "❌ Invalid choice"
            return 1
        fi
        local selected_json="${match_list[$((choice - 1))]}"
        SELECTED_SERVICE=$(jq -r '.service' <<< "$selected_json")
        SELECTED_USERNAME=$(jq -r '.username' <<< "$selected_json")
        SELECTED_PASSWORD=$(jq -r '.password' <<< "$selected_json")
        return 0
    fi
}

retrieve_password() {
    decrypt_file
    read -rp "Service (enter number or name): " query
    [ -z "$query" ] && { echo "❌ Input cannot be empty"; return; }
    if ! _select_account_entry "retrieve" "$query"; then
        return
    fi

    echo ""
    echo "📝 Service:  $SELECTED_SERVICE"
    echo "👤 Username: $SELECTED_USERNAME"
    echo "🔑 Password: (use clipboard option below)"
    echo ""

    read -rp "Copy password to clipboard? (y/n): " c
    if [ "$c" = "y" ]; then
        copy_clipboard "$SELECTED_PASSWORD" || true
    fi

    audit_log "RETRIEVE: entry accessed"
}

delete_password() {
    decrypt_file
    if ! _select_account_entry "delete"; then
        return
    fi

    read -rp "Are you sure you want to delete '$SELECTED_SERVICE' for user '$SELECTED_USERNAME'? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        jq --arg svc "$SELECTED_SERVICE" --arg usr "$SELECTED_USERNAME" \
            'map(select((.service | ascii_downcase) != ($svc | ascii_downcase) or .username != $usr))' \
            "$TEMP_FILE" > "${TEMP_FILE}.tmp"
        mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
        encrypt_file
        audit_log "DELETE: entry removed"
        echo "✅ Account '$SELECTED_SERVICE ($SELECTED_USERNAME)' deleted successfully"
    else
        echo "Operation cancelled"
    fi
}

edit_password() {
    decrypt_file
    if ! _select_account_entry "edit"; then
        return
    fi

    local orig_service="$SELECTED_SERVICE"
    local orig_username="$SELECTED_USERNAME"
    local orig_password="$SELECTED_PASSWORD"

    echo "Current username: $orig_username"
    read -rp "New username (leave empty to keep current): " new_username
    new_username=${new_username:-$orig_username}

    echo "Current service: $orig_service"
    read -rp "New service name (leave empty to keep current): " new_service
    new_service=${new_service:-$orig_service}

    echo ""
    echo "1) Enter new password"
    echo "2) Generate new password"
    echo "3) Keep current password"
    read -rp "Choice: " pchoice

    local new_password=""
    case "$pchoice" in
        1)
            read -rs -p "New password: " new_password; echo ""
            [ -z "$new_password" ] && { echo "❌ Password cannot be empty"; return; }
            if ! check_password_strength "$new_password"; then
                read -rp "Use this password anyway? (y/n): " force
                [ "$force" != "y" ] && return
            fi
            ;;
        2)
            new_password=$(generate_password "$DEFAULT_PASSWORD_LENGTH")
            echo "✅ Password generated."
            read -rp "Copy to clipboard? (y/n): " c
            if [ "$c" = "y" ]; then
                copy_clipboard "$new_password" || true
            fi
            ;;
        3)
            new_password="$orig_password" ;;
        *)
            echo "❌ Invalid option"; return ;;
    esac

    jq --arg svc "$orig_service" --arg usr "$orig_username" \
       --arg new_svc "$new_service" --arg new_usr "$new_username" --arg new_pw "$new_password" \
       'map(select((.service | ascii_downcase) != ($svc | ascii_downcase) or .username != $usr) | select((.service | ascii_downcase) != ($new_svc | ascii_downcase) or .username != $new_usr)) + [{"service": $new_svc, "username": $new_usr, "password": $new_pw}]' \
       "$TEMP_FILE" > "${TEMP_FILE}.tmp"

    mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
    encrypt_file
    audit_log "EDIT: entry updated"
    echo "✅ Account '$new_service ($new_username)' updated successfully"
}

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

    audit_log "LIST: vault listed"
}

search_passwords() {
    decrypt_file
    read -rp "Search query: " query
    [ -z "$query" ] && { echo "❌ Search query cannot be empty"; return; }

    local results
    results=$(jq -r --arg q "$query" \
        '[.[] | select(.service | ascii_downcase | contains($q | ascii_downcase))] | .[] | "  • \(.service) (\(.username))"' \
        "$TEMP_FILE" 2>/dev/null)

    if [ -z "$results" ]; then
        echo "❌ No services found matching '$query'"
        return
    fi

    echo "🔍 Search results for '$query':"
    echo "$results"
    audit_log "SEARCH: query executed"
}

# ==============================================================================
# Import / Export
# ==============================================================================

export_passwords() {
    decrypt_file

    echo "⚠️  WARNING: Export creates an UNENCRYPTED file."
    echo "   Consider using the encrypted export option (option 2) instead."
    echo ""
    echo "1) Unencrypted JSON export"
    echo "2) Encrypted export (requires a separate export passphrase)"
    echo "3) Cancel"
    read -rp "Choice: " export_choice

    read -rp "Export filename: " filename
    [ -z "$filename" ] && { echo "❌ Filename cannot be empty"; return; }
    
    if [[ "$filename" == ~/* ]]; then
        filename="$HOME/${filename#~/}"
    fi
    [[ "$filename" != /* ]] && filename="$PWD/$filename"

    # Ensure parent directory exists
    local parent_dir
    parent_dir=$(dirname "$filename")
    if [ ! -d "$parent_dir" ]; then
        mkdir -p "$parent_dir"
        chmod 700 "$parent_dir"
    fi

    # Check for overwrites
    if [ -f "$filename" ]; then
        read -rp "⚠️  File already exists. Overwrite? (y/n): " ov_choice
        if [ "$ov_choice" != "y" ]; then
            echo "Operation cancelled."
            return
        fi
    fi

    case "$export_choice" in
        1)
            cp "$TEMP_FILE" "$filename"
            chmod 600 "$filename"
            local count
            count=$(jq '. | length' "$TEMP_FILE")
            echo ""
            echo "⚠️  WARNING: Exported file is UNENCRYPTED — delete it after use!"
            echo "✅ $count passwords exported to: $filename"
            audit_log "EXPORT: unencrypted export performed"
            ;;
        2)
            echo "Enter an export passphrase (used only for this file):"
            local exp_pass=""
            read -rs exp_pass; echo ""
            [ -z "$exp_pass" ] && { echo "❌ Passphrase cannot be empty"; return; }

            openssl enc -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" -md sha256 -salt \
                -in "$TEMP_FILE" -pass fd:3 -out "$filename" 3<<<"$exp_pass" 2>/dev/null
            chmod 600 "$filename"
            local count
            count=$(jq '. | length' "$TEMP_FILE")
            echo "✅ $count passwords exported (encrypted) to: $filename"
            echo "   Decrypt with: openssl enc -d -aes-256-cbc -pbkdf2 -iter $PBKDF2_ITER -md sha256 -in \"$filename\" -pass stdin"
            audit_log "EXPORT: encrypted export performed"
            ;;
        3)
            echo "Export cancelled"; return ;;
        *)
            echo "❌ Invalid option"; return ;;
    esac
}

import_passwords() {
    decrypt_file

    read -rp "Import filename: " filename
    [ -z "$filename" ] && { echo "❌ Filename cannot be empty"; return; }
    if [[ "$filename" == ~/* ]]; then
        filename="$HOME/${filename#~/}"
    fi
    [[ "$filename" != /* ]] && filename="$PWD/$filename"
    [ ! -f "$filename" ] && { echo "❌ File not found: $filename"; return; }

    local import_file
    import_file=$(_make_tempfile)
    TEMP_FILES_TO_CLEAN+=("$import_file")

    # Check if it looks like an encrypted export using the Salted__ magic header
    if [ "$(head -c 8 "$filename" 2>/dev/null)" = "Salted__" ]; then
        echo "File appears to be encrypted. Enter the export passphrase:"
        local exp_pass=""
        read -rs exp_pass; echo ""
        openssl enc -d -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" -md sha256 \
            -in "$filename" -pass fd:3 -out "$import_file" 3<<<"$exp_pass" 2>/dev/null || {
            echo "❌ Failed to decrypt: wrong passphrase or not an encrypted export"
            return
        }
    else
        cp "$filename" "$import_file"
    fi

    if ! jq empty "$import_file" 2>/dev/null; then
        echo "❌ Invalid JSON file"; return
    fi

    local import_type
    import_type=$(jq -r 'type' "$import_file")
    [ "$import_type" != "array" ] && { echo "❌ Invalid format: expected a JSON array"; return; }

    local existing_count
    existing_count=$(jq '. | length' "$TEMP_FILE")

    jq --slurpfile imported "$import_file" '
        . as $existing |
        reduce ($imported[0][] | select(
            type == "object" and
            (.service | type == "string" and . != "") and
            (.username | type == "string" and . != "") and
            (.password | type == "string" and . != "")
        )) as $item (
            $existing;
            if any(.[]; (.service | ascii_downcase) == ($item.service | ascii_downcase) and .username == $item.username) then . else . + [$item] end
        )
    ' "$TEMP_FILE" > "${TEMP_FILE}.tmp" 2>/dev/null

    if ! jq empty "${TEMP_FILE}.tmp" 2>/dev/null; then
        echo "❌ Error merging data"; secure_remove_file "${TEMP_FILE}.tmp"; return
    fi

    mv "${TEMP_FILE}.tmp" "$TEMP_FILE"

    local new_count
    new_count=$(jq '. | length' "$TEMP_FILE")
    local imported_count=$((new_count - existing_count))
    local total_in_file
    total_in_file=$(jq '. | length' "$import_file")

    encrypt_file
    echo "✅ Imported $imported_count new entries ($((total_in_file - imported_count)) duplicates skipped)"
    audit_log "IMPORT: entries imported"
}

# ==============================================================================
# Configuration Management
# ==============================================================================

configure_settings() {
    echo ""
    echo "⚙️  Configuration"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [ -f "$CONFIG_FILE" ]; then
        echo "Current settings:"
        echo "  • Default password length: $(jq -r '.password_length' "$CONFIG_FILE")"
        echo "  • Clipboard timeout:       $(jq -r '.clipboard_timeout' "$CONFIG_FILE")s"
        echo "  • Password file:           $(jq -r '.password_file' "$CONFIG_FILE")"
    else
        echo "No custom configuration found. Using defaults."
    fi
    echo ""

    echo "1. Change default password length"
    echo "2. Change clipboard clear timeout"
    echo "3. Change password file location"
    echo "4. Reset to defaults"
    echo "5. Back to menu"
    read -rp "Choice: " setting_choice

    case "$setting_choice" in
        1)
            read -rp "Set default password length (current: $DEFAULT_PASSWORD_LENGTH): " new_length
            if [ -n "$new_length" ]; then
                if ! [[ "$new_length" =~ ^[0-9]+$ ]] || [ "$new_length" -lt 8 ]; then
                    echo "❌ Invalid length. Must be at least 8 characters"; return
                fi
                DEFAULT_PASSWORD_LENGTH="$new_length"
                save_config "$DEFAULT_PASSWORD_LENGTH"
                audit_log "CONFIG: password length updated"
                echo "✅ Configuration updated"
            fi
            ;;
        2)
            read -rp "Set clipboard timeout in seconds (current: $CLIPBOARD_TIMEOUT): " new_timeout
            if [ -n "$new_timeout" ]; then
                if ! [[ "$new_timeout" =~ ^[0-9]+$ ]] || [ "$new_timeout" -lt 5 ]; then
                    echo "❌ Invalid timeout. Must be at least 5 seconds"; return
                fi
                CLIPBOARD_TIMEOUT="$new_timeout"
                save_config "$DEFAULT_PASSWORD_LENGTH"
                audit_log "CONFIG: clipboard timeout updated"
                echo "✅ Configuration updated"
            fi
            ;;
        3)
            read -rp "Set password file path (current: $PASSWORD_FILE): " new_path
            if [ -n "$new_path" ]; then
                if [[ "$new_path" == ~/* ]]; then
                    new_path="$HOME/${new_path#~/}"
                fi
                [[ "$new_path" != /* ]] && new_path="$PWD/$new_path"
                
                local parent_dir
                parent_dir=$(dirname "$new_path")
                mkdir -p "$parent_dir"
                chmod 700 "$parent_dir" 2>/dev/null || true
                
                PASSWORD_FILE="$new_path"
                save_config "$DEFAULT_PASSWORD_LENGTH"
                audit_log "CONFIG: password file path updated"
                echo "✅ Configuration updated"
            fi
            ;;
        4)
            rm -f "$CONFIG_FILE"
            DEFAULT_PASSWORD_LENGTH=16
            CLIPBOARD_TIMEOUT=30
            PASSWORD_FILE="$DATA_DIR/passwords.enc"
            audit_log "CONFIG: reset to defaults"
            echo "✅ Settings reset to defaults"
            ;;
        5) return ;;
        *) echo "❌ Invalid option" ;;
    esac
}

# ==============================================================================
# Main Menu
# ==============================================================================

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
        read -rp "  Choice: " choice

        case $choice in
            1)  store_password ;;
            2)  retrieve_password ;;
            3)  list_passwords ;;
            4)  search_passwords ;;
            5)  edit_password ;;
            6)  delete_password ;;
            7)  import_passwords ;;
            8)  export_passwords ;;
            9)  configure_settings ;;
            10) audit_log "EXIT: session ended"; echo "👋 Goodbye!"; exit 0 ;;
            *)  echo "❌ Invalid option" ;;
        esac
    done
}

# ==============================================================================
# Entry Point
# ==============================================================================

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    load_config
    prompt_master_password
    main_menu
fi
