#!/usr/bin/env bash
# diagnose.sh - Cross-Platform Diagnostics Runner for Antigravity Zero-Privilege Bypass
# Operates completely in unprivileged user space. Zero elevated privileges required.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required for the full diagnostic self-test suite." >&2
    exit 1
fi

exec python3 "$SCRIPT_DIR/diagnose.py" "$@"
