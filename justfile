# Default recipe - show available commands
default:
    @just --list

# Release and install a new version (patch/minor/major)
release level:
    cargo release {{level}} --execute --no-confirm
    git push && git push --tags
    cargo install --path . --force

# Install rules to ~/.config/longline/rules.yaml
install-rules:
    mkdir -p ~/.config/longline
    cp rules/rules.yaml ~/.config/longline/rules.yaml
    @echo "Installed rules to ~/.config/longline/rules.yaml"

# Delete user rules file
delete-rules:
    rm -f ~/.config/longline/rules.yaml
    @echo "Deleted ~/.config/longline/rules.yaml"

# Run tests
test:
    cargo test

# Run clippy
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Install binary to ~/.cargo/bin (cargo default)
install:
    cargo install --path . --force

# Install binary to ~/.local/bin
install-local:
    cargo install --path . --root ~/.local --force
