#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
CONFIG_DIR="$HOME/.config/longline"
RULES_DST="$CONFIG_DIR/rules.yaml"
RULES_SRC="$(cd "$(dirname "$0")" && pwd)/rules/default-rules.yaml"

usage() {
    echo "Usage: install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --install-rules   Copy default rules to $RULES_DST"
    echo "                    Overwrites existing rules if present."
    echo "  --delete-rules    Delete existing rules at $RULES_DST"
    echo "  -h, --help        Show this help message"
}

INSTALL_RULES=false
DELETE_RULES=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-rules) INSTALL_RULES=true; shift ;;
        --delete-rules)  DELETE_RULES=true; shift ;;
        -h|--help)       usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if $INSTALL_RULES && $DELETE_RULES; then
    echo "ERROR: --install-rules and --delete-rules are mutually exclusive."
    exit 1
fi

# Build release binary
echo "Building release binary..."
cargo build --release --manifest-path "$(cd "$(dirname "$0")" && pwd)/Cargo.toml"

# Install binary
mkdir -p "$INSTALL_DIR"
cp "$(cd "$(dirname "$0")" && pwd)/target/release/longline" "$INSTALL_DIR/longline"
echo "Installed binary to $INSTALL_DIR/longline"

# Handle rules
if $DELETE_RULES; then
    if [ -f "$RULES_DST" ]; then
        rm "$RULES_DST"
        echo "Deleted rules at $RULES_DST"
    else
        echo "No rules file to delete at $RULES_DST"
    fi
elif $INSTALL_RULES; then
    mkdir -p "$CONFIG_DIR"
    if [ -f "$RULES_DST" ]; then
        cp "$RULES_SRC" "$RULES_DST"
        echo "Overwrote existing rules at $RULES_DST"
    else
        cp "$RULES_SRC" "$RULES_DST"
        echo "Installed default rules to $RULES_DST"
    fi
else
    echo "Skipping rules install (pass --install-rules to install or update rules)"
fi

# Check PATH
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    echo ""
    echo "WARNING: $INSTALL_DIR is not in your PATH."
    echo "Add this to your shell profile:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo ""
echo "Done. Test with:"
echo "  longline rules"
echo "  echo 'ls -la' | longline check"
