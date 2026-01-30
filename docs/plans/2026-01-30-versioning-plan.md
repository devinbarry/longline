# Versioning Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add version tracking to logs and implement industry-standard release workflow with cargo-release, git-cliff, and justfile.

**Architecture:** Version embedded at compile time via `env!("CARGO_PKG_VERSION")`. Releases managed by cargo-release which bumps Cargo.toml, generates changelog via git-cliff (pre-release-hook), commits, and tags. Install is handled by the justfile `release` recipe after cargo-release completes (cargo-release doesn't support post-release hooks).

**Tech Stack:** cargo-release, git-cliff, just

---

### Task 1: Add version field to LogEntry

**Files:**
- Modify: `src/logger.rs:9-24` (LogEntry struct)
- Modify: `src/logger.rs:73-103` (make_entry function)
- Test: `src/logger.rs` (existing tests)

**Step 1: Update LogEntry struct to include version field**

In `src/logger.rs`, add `version` as the first field in `LogEntry`:

```rust
#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub version: &'static str,
    pub ts: String,
    pub tool: String,
    pub cwd: String,
    pub command: String,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_decision: Option<Decision>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub overridden: bool,
    pub matched_rules: Vec<String>,
    pub reason: Option<String>,
    pub parse_ok: bool,
    pub session_id: Option<String>,
}
```

**Step 2: Update make_entry to populate version**

Update `make_entry()` to include version in the returned LogEntry:

```rust
LogEntry {
    version: env!("CARGO_PKG_VERSION"),
    ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    tool: tool.to_string(),
    // ... rest unchanged
}
```

**Step 3: Run tests to verify compilation and existing tests pass**

Run: `cargo test --lib`
Expected: All tests pass. Existing tests may need `version` field added to expected outputs.

**Step 4: Update test assertions if needed**

If `test_log_entry_serialization` fails, update it to check for version:

```rust
assert!(json.contains("\"version\":\"0.1.0\""));
```

**Step 5: Run tests again**

Run: `cargo test --lib`
Expected: PASS

**Step 6: Commit**

```bash
git add src/logger.rs
git commit -m "feat: add version field to log entries"
```

---

### Task 2: Create justfile

**Files:**
- Create: `justfile`

**Step 1: Create justfile**

Create `justfile` in project root:

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

Note: The install is inlined in the `release` recipe because cargo-release doesn't support `post-release-hook`.

**Step 2: Verify justfile syntax**

Run: `just --list`
Expected: Shows available commands (release, install-rules, delete-rules, test, lint, fmt)

**Step 3: Test a simple command**

Run: `just test`
Expected: Runs `cargo test` successfully

**Step 4: Commit**

```bash
git add justfile
git commit -m "feat: add justfile for dev commands and release workflow"
```

---

### Task 3: Create cargo-release configuration

**Files:**
- Create: `release.toml`

**Step 1: Create release.toml**

Create `release.toml` in project root:

```toml
allow-branch = ["master"]
sign-commit = false
sign-tag = false
push = false
tag-name = "v{{version}}"
pre-release-commit-message = "chore: release v{{version}}"
pre-release-hook = ["git-cliff", "-o", "CHANGELOG.md", "--tag", "{{version}}"]
```

Note: cargo-release only supports `pre-release-hook`, not `post-release-hook`. The install step is handled by the justfile `release` recipe instead.

**Step 2: Verify cargo-release recognizes config**

Run: `cargo release --version`
Expected: Shows cargo-release version (confirms it's installed)

Run: `cargo release patch --dry-run`
Expected: Shows what would happen (bump to 0.1.1, etc.) without executing

**Step 3: Commit**

```bash
git add release.toml
git commit -m "feat: add cargo-release configuration"
```

---

### Task 4: Create git-cliff configuration

**Files:**
- Create: `cliff.toml`

**Step 1: Create cliff.toml**

Create `cliff.toml` in project root:

```toml
[changelog]
header = """
# Changelog

All notable changes to this project will be documented in this file.

"""
body = """
## [{{ version }}] - {{ timestamp | date(format="%Y-%m-%d") }}
{% for group, commits in commits | group_by(attribute="group") %}

### {{ group | title }}
{% for commit in commits %}
- {{ commit.message | split(pat="\n") | first }}
{%- endfor %}
{% endfor %}
"""
trim = true

[git]
conventional_commits = true
filter_unconventional = true
commit_parsers = [
    { message = "^feat", group = "Added" },
    { message = "^fix", group = "Fixed" },
    { message = "^refactor", group = "Changed" },
    { message = "^perf", group = "Changed" },
    { message = "^test", group = "Changed" },
    { message = "^docs", group = "Changed" },
    { message = "^chore", group = "Changed" },
]
filter_commits = true
```

**Step 2: Test git-cliff generates changelog**

Run: `git-cliff --unreleased`
Expected: Shows changelog entries for commits since last tag (or all commits if no tags)

**Step 3: Commit**

```bash
git add cliff.toml
git commit -m "feat: add git-cliff configuration for changelog generation"
```

---

### Task 5: Delete install.sh

**Files:**
- Delete: `install.sh`

**Step 1: Delete install.sh**

Run: `rm install.sh`

**Step 2: Commit**

```bash
git add -A
git commit -m "chore: remove install.sh (replaced by justfile)"
```

---

### Task 6: Install dependencies and test full release workflow

**Step 1: Ensure dependencies are installed**

Run: `cargo install cargo-release git-cliff just`
Expected: All three tools installed (or already up to date)

**Step 2: Dry-run a release**

Run: `cargo release patch --dry-run`
Expected: Shows:
- Would bump version 0.1.0 -> 0.1.1
- Would run git-cliff pre-release hook
- Would commit "chore: release v0.1.1"
- Would tag v0.1.1

Note: The install step happens after cargo-release completes, via the justfile.

**Step 3: Execute actual release**

Run: `just release patch`
Expected:
- CHANGELOG.md created with all changes since start
- Cargo.toml version bumped to 0.1.1
- Git commit and tag created
- Binary installed to ~/.local/bin/longline

**Step 4: Verify installation**

Run: `~/.local/bin/longline --version`
Expected: `longline 0.1.1`

**Step 5: Verify version in logs**

Run: `echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | ~/.local/bin/longline --config rules/default-rules.yaml`

Then check log:
Run: `tail -1 ~/.claude/hooks-logs/longline.jsonl | jq .version`
Expected: `"0.1.1"`
