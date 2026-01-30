# Versioning Design

Add version tracking to longline with industry-standard Rust tooling.

## Goals

1. Version number in logs for debugging old entries
2. Enforce version bump before every install (no installing unchanged code at same version)
3. Auto-generated changelog in Keep a Changelog format

## Implementation

### 1. Version in Logs

Add `version` field to `LogEntry` in `src/logger.rs`:

```rust
#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub version: &'static str,  // First field for visibility
    pub ts: String,
    // ... rest unchanged
}
```

In `make_entry()`:
```rust
version: env!("CARGO_PKG_VERSION"),
```

Log output:
```json
{"version":"0.2.0","ts":"2026-01-30T...","tool":"Bash","command":"ls",...}
```

### 2. CLI --version Flag

Add to clap derive in `src/cli.rs`:
```rust
#[command(version)]
```

### 3. cargo-release Configuration

Create `release.toml`:

```toml
allow-branch = ["master"]
sign-commit = false
sign-tag = false
push = false
tag-name = "v{{version}}"
pre-release-commit-message = "chore: release v{{version}}"
pre-release-hook = ["git-cliff", "-o", "CHANGELOG.md", "--tag", "{{version}}"]
```

Note: cargo-release only supports `pre-release-hook`, not `post-release-hook`. The install step is handled by the justfile `release` recipe instead (see below).

### 4. git-cliff Configuration

Create `cliff.toml`:

```toml
[changelog]
header = "# Changelog\n\nAll notable changes to this project will be documented in this file.\n"
body = """
## [{{ version }}] - {{ timestamp | date(format="%Y-%m-%d") }}
{% for group, commits in commits | group_by(attribute="group") %}
### {{ group | title }}
{% for commit in commits %}
- {{ commit.message | split(pat="\n") | first }}
{% endfor %}
{% endfor %}
"""

[git]
conventional_commits = true
commit_parsers = [
    { message = "^feat", group = "Added" },
    { message = "^fix", group = "Fixed" },
    { message = "^refactor", group = "Changed" },
    { message = "^perf", group = "Changed" },
    { message = "^test", group = "Changed" },
    { message = "^docs", group = "Changed" },
]
filter_commits = true
```

### 5. Justfile

Create `justfile` (replaces `install.sh`):

```just
# Default recipe - show available commands
default:
    @just --list

# Release and install a new version (patch/minor/major)
release level:
    cargo release {{level}} --execute
    cargo install --path . --root ~/.local

# Install binary to ~/.local/bin (for manual installs)
install:
    cargo install --path . --root ~/.local

# Install rules to ~/.config/longline/rules.yaml
install-rules:
    mkdir -p ~/.config/longline
    cp rules/default-rules.yaml ~/.config/longline/rules.yaml
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
```

Note: The install is inlined in the `release` recipe because cargo-release doesn't support `post-release-hook`. A separate `install` recipe is provided for manual installs when needed.

## File Changes Summary

**Create:**
- `justfile`
- `release.toml`
- `cliff.toml`
- `CHANGELOG.md` (auto-generated on first release)

**Modify:**
- `src/cli.rs` — Add `#[command(version)]`
- `src/logger.rs` — Add `version` field to `LogEntry`

**Delete:**
- `install.sh`

## Dependencies

One-time install:
```bash
cargo install cargo-release git-cliff just
```

## Workflow

```bash
just release patch  # 0.1.0 → 0.1.1
just release minor  # 0.1.0 → 0.2.0
just release major  # 0.1.0 → 1.0.0
```

Each release:
1. Runs git-cliff to update CHANGELOG.md (pre-release-hook)
2. Bumps version in Cargo.toml
3. Commits "chore: release v0.2.0"
4. Creates git tag `v0.2.0`
5. Installs binary to `~/.local/bin` (justfile inline, after cargo-release completes)
