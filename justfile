# Default recipe - show available commands
default:
    @just --list

# Step 1: Prepare a release (bump version, generate changelog draft, do NOT commit)
release-prep level:
    #!/usr/bin/env bash
    set -euo pipefail

    # Bump version in Cargo.toml (dry-run to get new version, then sed)
    OLD_VERSION=$(cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['version'])")
    echo "Current version: $OLD_VERSION"

    # Calculate new version
    IFS='.' read -r MAJOR MINOR PATCH <<< "$OLD_VERSION"
    case "{{level}}" in
        patch) PATCH=$((PATCH + 1)) ;;
        minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
        major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
        *) echo "Usage: just release-prep [patch|minor|major]"; exit 1 ;;
    esac
    NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
    echo "New version: $NEW_VERSION"

    # Bump version in Cargo.toml (compatible with both macOS and Linux sed)
    if [[ "$OSTYPE" == darwin* ]]; then
        sed -i '' "s/^version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
    else
        sed -i "s/^version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
    fi
    cargo check --quiet 2>/dev/null  # update Cargo.lock

    # Generate changelog draft to stdout for reference
    echo ""
    echo "=== git-cliff draft for v${NEW_VERSION} (unreleased commits) ==="
    echo ""
    git-cliff --unreleased --tag "$NEW_VERSION" 2>/dev/null || echo "(git-cliff not available, write changelog manually)"
    echo ""
    echo "=== end draft ==="
    echo ""
    echo "Next steps:"
    echo "  1. Edit CHANGELOG.md with release notes for v${NEW_VERSION}"
    echo "  2. Review all changes: git diff"
    echo "  3. Run: just release-finish"

# Step 2: Commit (if needed), tag, push, install. Supports uncommitted + pre-committed flows.
release-finish:
    #!/usr/bin/env bash
    set -euo pipefail

    VERSION=$(cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['version'])")
    TAG="v${VERSION}"
    echo "Releasing ${TAG}"

    # If the tag already exists, refuse — releasing the same version twice
    # is almost certainly a mistake.
    if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
        echo "Error: tag ${TAG} already exists. Bump the version via 'just release-prep' first."
        exit 1
    fi

    HEAD_SUBJECT=$(git log -1 --pretty=%s)
    EXPECTED_RELEASE_SUBJECT="chore: release ${TAG}"

    if ! git diff --quiet || ! git diff --cached --quiet; then
        # Flow A: uncommitted changes present. Ensure it's the Cargo.toml bump
        # + CHANGELOG edits we expect, then commit them.
        echo "Flow A: committing pending Cargo.toml / Cargo.lock / CHANGELOG.md"
        git add Cargo.toml Cargo.lock CHANGELOG.md
        git commit -m "${EXPECTED_RELEASE_SUBJECT}"
    elif [ "${HEAD_SUBJECT}" = "${EXPECTED_RELEASE_SUBJECT}" ]; then
        # Flow B: the release commit is already HEAD. Nothing to commit.
        echo "Flow B: release commit already at HEAD (${HEAD_SUBJECT}); skipping commit step"
    else
        # Nothing to commit, and HEAD isn't the expected release commit.
        echo "Error: no changes to commit and HEAD subject is not \"${EXPECTED_RELEASE_SUBJECT}\"."
        echo "       Either run 'just release-prep' and edit CHANGELOG.md, or"
        echo "       ensure HEAD is the release commit produced by your automation."
        echo "       HEAD subject: ${HEAD_SUBJECT}"
        exit 1
    fi

    # Tag + push + install. These are safe to re-run; the tag-exists check
    # above is the primary idempotency guard.
    git tag -a "${TAG}" -m "${TAG}"
    git push && git push --tags
    cargo install --path . --force
    echo ""
    echo "Released ${TAG}"

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
