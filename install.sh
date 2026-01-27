#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
CONFIG_DIR="$HOME/.config/longline"
RULES_SRC="$(cd "$(dirname "$0")" && pwd)/rules/default-rules.yaml"

# Build release binary
echo "Building release binary..."
cargo build --release --manifest-path "$(cd "$(dirname "$0")" && pwd)/Cargo.toml"

# Install binary
mkdir -p "$INSTALL_DIR"
cp "$(cd "$(dirname "$0")" && pwd)/target/release/longline" "$INSTALL_DIR/longline"
echo "Installed binary to $INSTALL_DIR/longline"

# Install default rules (don't overwrite existing)
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/rules.yaml" ]; then
    cp "$RULES_SRC" "$CONFIG_DIR/rules.yaml"
    echo "Installed default rules to $CONFIG_DIR/rules.yaml"
else
    echo "Rules already exist at $CONFIG_DIR/rules.yaml (not overwritten)"
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
