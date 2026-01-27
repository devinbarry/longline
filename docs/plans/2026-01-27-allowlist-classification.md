# Allowlist Command Classification Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split the flat allowlist into always-safe (bare) and conditionally-safe (multi-word) entries so that commands with destructive variants require explicit safe-invocation matching.

**Architecture:** No schema change. Replace bare entries for git/cargo/npm/pip/gem/go with specific multi-word entries. Add `git-commit-amend` rule. Update golden tests to match.

**Tech Stack:** YAML rules config, YAML golden tests, Rust (one new rule only)

---

### Task 1: Update allowlist in default-rules.yaml

**Files:**
- Modify: `rules/default-rules.yaml:1-88`

**Step 1: Replace the allowlists section**

Replace the entire `allowlists:` block (lines 5-87) with:

```yaml
allowlists:
  commands:
    # ── Always safe: read-only / output-only ──────────────────────
    - ls
    - echo
    - pwd
    - whoami
    - date
    - cat
    - head
    - tail
    - wc
    - file
    - which
    - type
    - basename
    - dirname
    - realpath
    - readlink
    - stat
    - du
    - printf
    - md5sum
    - sha256sum
    - sha1sum
    - cksum
    - "true"
    - "false"
    - grep
    - rg
    - fd
    - sort
    - uniq
    - tr
    - cut
    - diff
    - jq
    - yq
    - test
    # ── Always safe: dev tools (no publish risk) ──────────────────
    - make
    - cmake
    - rustc
    - java
    - javac
    - node
    - python
    - python3
    - ruby
    - npx
    # ── Always safe: filesystem ops (secrets caught by rules) ─────
    - mkdir
    - touch
    - ln
    - cp
    - mv
    - tee
    - tar
    - gzip
    - gunzip
    - zip
    - unzip
    # ── Always safe: text processing ──────────────────────────────
    - sed
    - awk
    - xargs
    - patch
    - find
    # ── Git: read operations ──────────────────────────────────────
    - "git status"
    - "git diff"
    - "git log"
    - "git show"
    - "git branch"
    - "git stash list"
    - "git remote"
    - "git tag"
    - "git rev-parse"
    - "git config"
    # ── Git: safe write operations ────────────────────────────────
    - "git add"
    - "git commit"
    - "git fetch"
    - "git pull"
    - "git push"
    - "git stash"
    - "git checkout"
    - "git switch"
    - "git restore"
    - "git merge"
    - "git rebase"
    - "git cherry-pick"
    - "git worktree"
    - "git clone"
    - "git init"
    # ── Git: read-only extras ─────────────────────────────────────
    - "git blame"
    - "git bisect"
    - "git describe"
    - "git shortlog"
    - "git reflog"
    - "git ls-files"
    - "git ls-tree"
    - "git cat-file"
    # ── Cargo: safe invocations ───────────────────────────────────
    - "cargo build"
    - "cargo test"
    - "cargo check"
    - "cargo clippy"
    - "cargo fmt"
    - "cargo run"
    - "cargo bench"
    - "cargo doc"
    - "cargo clean"
    - "cargo update"
    - "cargo add"
    - "cargo remove"
    - "cargo init"
    - "cargo new"
    - "cargo tree"
    - "cargo metadata"
    - "cargo vendor"
    # ── npm: safe invocations ─────────────────────────────────────
    - "npm install"
    - "npm ci"
    - "npm test"
    - "npm run"
    - "npm start"
    - "npm ls"
    - "npm outdated"
    - "npm audit"
    - "npm init"
    - "npm exec"
    - "npm info"
    - "npm pack"
    # ── pip/pip3: safe invocations ────────────────────────────────
    - "pip install"
    - "pip list"
    - "pip show"
    - "pip freeze"
    - "pip check"
    - "pip3 install"
    - "pip3 list"
    - "pip3 show"
    - "pip3 freeze"
    - "pip3 check"
    # ── gem: safe invocations ─────────────────────────────────────
    - "gem install"
    - "gem list"
    - "gem info"
    - "gem search"
    # ── go: safe invocations ──────────────────────────────────────
    - "go build"
    - "go test"
    - "go run"
    - "go vet"
    - "go fmt"
    - "go mod"
    - "go generate"
    - "go doc"
    - "go get"
    - "go clean"
    - "go env"
    - "go version"
    - "go work"
```

**Step 2: Run tests to see what breaks**

Run: `cargo test 2>&1 | head -80`
Expected: Some golden tests fail (git.yaml tests that expected `ask` for now-allowlisted commands, safe-commands.yaml tests for now-restricted build tools like `cargo build`)

**Step 3: Commit**

```
git add rules/default-rules.yaml
git commit -m "refactor: split allowlist into always-safe and conditionally-safe groups"
```

---

### Task 2: Add git-commit-amend rule

**Files:**
- Modify: `rules/default-rules.yaml` (insert after `git-branch-delete-force` rule, around line 325)

**Step 1: Add the rule**

Insert after the `git-branch-delete-force` rule block:

```yaml
  - id: git-commit-amend
    level: high
    match:
      command: git
      args:
        any_of: ["commit"]
      flags:
        any_of: ["--amend"]
    decision: ask
    reason: "git commit --amend rewrites the previous commit"
```

**Step 2: Run tests**

Run: `cargo test 2>&1 | head -80`
Expected: Same failures as before (no new failures from this rule, no tests reference it yet)

**Step 3: Commit**

```
git add rules/default-rules.yaml
git commit -m "feat: add git-commit-amend rule to catch history rewriting"
```

---

### Task 3: Update git golden tests

**Files:**
- Modify: `tests/golden/git.yaml`

**Step 1: Update expected decisions for now-allowlisted git commands**

Change these test cases from `decision: ask` to `decision: allow`:

- `git-add` (line 53-55): `git add .` -> `allow`
- `git-commit` (line 56-59): `git commit -m 'fix: some bug'` -> `allow`
- `git-push` (line 60-63): `git push origin feature-branch` -> `allow`
- `git-stash-push-not-allowlisted` (line 120-123): `git stash push` -> `allow`
- `git-merge-not-allowlisted` (line 124-127): `git merge feature-branch` -> `allow`
- `git-rebase-not-allowlisted` (line 128-131): `git rebase main` -> `allow`
- `git-cherry-pick` (line 132-135): `git cherry-pick abc1234` -> `allow`
- `git-fetch` (line 136-139): `git fetch origin` -> `allow`
- `git-pull` (line 140-143): `git pull origin main` -> `allow`

Also rename test IDs to remove `-not-allowlisted` suffixes since they're now allowlisted:
- `git-stash-push-not-allowlisted` -> `git-stash-push`
- `git-merge-not-allowlisted` -> `git-merge`
- `git-rebase-not-allowlisted` -> `git-rebase`

**Step 2: Add git-commit-amend test case**

Add after the `git-commit` test:

```yaml
  - id: git-commit-amend
    command: "git commit --amend"
    expected:
      decision: ask
      rule_id: git-commit-amend
  - id: git-commit-amend-message
    command: "git commit --amend -m 'updated message'"
    expected:
      decision: ask
      rule_id: git-commit-amend
```

**Step 3: Add tests for newly-allowlisted git extras**

Append to the file:

```yaml
  - id: git-switch-safe
    command: "git switch feature-branch"
    expected:
      decision: allow
  - id: git-restore-safe
    command: "git restore file.txt"
    expected:
      decision: allow
  - id: git-worktree-safe
    command: "git worktree add ../feature feature-branch"
    expected:
      decision: allow
  - id: git-clone-safe
    command: "git clone https://github.com/user/repo.git"
    expected:
      decision: allow
  - id: git-init-safe
    command: "git init"
    expected:
      decision: allow
  - id: git-blame-safe
    command: "git blame src/main.rs"
    expected:
      decision: allow
  - id: git-bisect-safe
    command: "git bisect start"
    expected:
      decision: allow
  - id: git-describe-safe
    command: "git describe --tags"
    expected:
      decision: allow
  - id: git-shortlog-safe
    command: "git shortlog -sn"
    expected:
      decision: allow
  - id: git-reflog-safe
    command: "git reflog"
    expected:
      decision: allow
  - id: git-ls-files-safe
    command: "git ls-files"
    expected:
      decision: allow
  - id: git-ls-tree-safe
    command: "git ls-tree HEAD"
    expected:
      decision: allow
  - id: git-cat-file-safe
    command: "git cat-file -p HEAD"
    expected:
      decision: allow
```

**Step 4: Run git golden tests**

Run: `cargo test golden_git -- --nocapture`
Expected: PASS (all git tests green)

**Step 5: Commit**

```
git add tests/golden/git.yaml
git commit -m "test: update git golden tests for allowlist classification"
```

---

### Task 4: Update safe-commands golden tests

**Files:**
- Modify: `tests/golden/safe-commands.yaml`

**Step 1: Replace build tool tests that now need specific subcommands**

The following tests use bare commands that are no longer bare-allowlisted. Update them to use specific safe invocations that are allowlisted:

Change `cargo-build-safe` (line 31-33) command from `"cargo build"` -- already fine, `"cargo build"` is multi-word allowlisted.

Check each test -- actually all existing safe-commands.yaml tests use specific invocations like `"cargo build"`, `"cargo test"`, `"npm install"`, `"npm test"`, `"python3 script.py"`, `"pip install requests"` etc. Most will still pass because:
- `cargo build`, `cargo test`, `cargo clippy` are explicitly allowlisted
- `npm install`, `npm test`, `npm run build` are explicitly allowlisted
- `python3 script.py` -- `python3` stays bare, so still passes
- `pip install requests` -- `pip install` is allowlisted, so passes
- `pip3 install flask` -- `pip3 install` is allowlisted, so passes
- `ruby script.rb` -- `ruby` stays bare
- `gem install bundler` -- `gem install` is allowlisted
- `go build ./...` -- `go build` is allowlisted
- `java -jar app.jar` -- `java` stays bare
- `javac Main.java` -- `javac` stays bare
- `cmake ..` -- `cmake` stays bare
- `make build`, `make clean` -- `make` stays bare
- `node -e 'console.log(1)'` -- `node` stays bare
- `npx create-react-app myapp` -- `npx` stays bare

The only test that might break: `rustc --version` -- `rustc` stays bare, passes.

Run all safe-commands tests first to check.

**Step 2: Run safe-commands golden tests**

Run: `cargo test golden_safe_commands -- --nocapture`
Expected: PASS (all existing safe-commands tests should still pass)

**Step 3: Add build tool edge case tests**

Append to `tests/golden/safe-commands.yaml`:

```yaml
  # ── Cargo safe invocations ──────────────────────────────────────
  - id: cargo-check-safe
    command: "cargo check"
    expected:
      decision: allow
  - id: cargo-fmt-safe
    command: "cargo fmt"
    expected:
      decision: allow
  - id: cargo-run-safe
    command: "cargo run -- --arg"
    expected:
      decision: allow
  - id: cargo-doc-safe
    command: "cargo doc --open"
    expected:
      decision: allow
  - id: cargo-clean-safe
    command: "cargo clean"
    expected:
      decision: allow
  - id: cargo-add-safe
    command: "cargo add serde"
    expected:
      decision: allow
  - id: cargo-tree-safe
    command: "cargo tree"
    expected:
      decision: allow
  # ── npm safe invocations ────────────────────────────────────────
  - id: npm-ci-safe
    command: "npm ci"
    expected:
      decision: allow
  - id: npm-start-safe
    command: "npm start"
    expected:
      decision: allow
  - id: npm-audit-safe
    command: "npm audit"
    expected:
      decision: allow
  - id: npm-ls-safe
    command: "npm ls"
    expected:
      decision: allow
  # ── pip safe invocations ────────────────────────────────────────
  - id: pip-list-safe
    command: "pip list"
    expected:
      decision: allow
  - id: pip-freeze-safe
    command: "pip freeze"
    expected:
      decision: allow
  # ── go safe invocations ─────────────────────────────────────────
  - id: go-test-safe
    command: "go test ./..."
    expected:
      decision: allow
  - id: go-run-safe
    command: "go run main.go"
    expected:
      decision: allow
  - id: go-vet-safe
    command: "go vet ./..."
    expected:
      decision: allow
  - id: go-fmt-safe
    command: "go fmt ./..."
    expected:
      decision: allow
  - id: go-mod-safe
    command: "go mod tidy"
    expected:
      decision: allow
  - id: go-env-safe
    command: "go env"
    expected:
      decision: allow
  - id: go-version-safe
    command: "go version"
    expected:
      decision: allow
  # ── gem safe invocations ────────────────────────────────────────
  - id: gem-list-safe
    command: "gem list"
    expected:
      decision: allow
```

**Step 4: Run safe-commands golden tests again**

Run: `cargo test golden_safe_commands -- --nocapture`
Expected: PASS

**Step 5: Commit**

```
git add tests/golden/safe-commands.yaml
git commit -m "test: add golden tests for expanded build tool safe invocations"
```

---

### Task 5: Add golden tests for non-allowlisted build tool commands

**Files:**
- Create: `tests/golden/build-tools.yaml`
- Modify: `tests/golden_tests.rs` (add new test function)

**Step 1: Create the golden test file**

Create `tests/golden/build-tools.yaml`:

```yaml
tests:
  # ── Cargo: non-allowlisted (should ask) ─────────────────────────
  - id: cargo-publish-ask
    command: "cargo publish"
    expected:
      decision: ask
  - id: cargo-login-ask
    command: "cargo login"
    expected:
      decision: ask
  - id: cargo-yank-ask
    command: "cargo yank --version 1.0.0"
    expected:
      decision: ask
  - id: cargo-owner-ask
    command: "cargo owner --add user"
    expected:
      decision: ask
  # ── npm: non-allowlisted (should ask) ───────────────────────────
  - id: npm-publish-ask
    command: "npm publish"
    expected:
      decision: ask
  - id: npm-unpublish-ask
    command: "npm unpublish package@1.0.0"
    expected:
      decision: ask
  - id: npm-deprecate-ask
    command: "npm deprecate package@1.0.0 'message'"
    expected:
      decision: ask
  - id: npm-access-ask
    command: "npm access public"
    expected:
      decision: ask
  # ── pip: non-allowlisted (should ask) ───────────────────────────
  - id: pip-uninstall-ask
    command: "pip uninstall requests"
    expected:
      decision: ask
  # ── gem: non-allowlisted (should ask) ───────────────────────────
  - id: gem-push-ask
    command: "gem push package.gem"
    expected:
      decision: ask
  - id: gem-uninstall-ask
    command: "gem uninstall bundler"
    expected:
      decision: ask
  # ── go: non-allowlisted (should ask) ────────────────────────────
  - id: go-install-ask
    command: "go install github.com/user/tool@latest"
    expected:
      decision: ask
```

**Step 2: Register the new golden test suite**

Add to `tests/golden_tests.rs` at the end of the file:

```rust
#[test]
fn golden_build_tools() {
    run_golden_suite("build-tools.yaml");
}
```

**Step 3: Run the new test**

Run: `cargo test golden_build_tools -- --nocapture`
Expected: PASS (all non-allowlisted commands fall through to default `ask`)

**Step 4: Commit**

```
git add tests/golden/build-tools.yaml tests/golden_tests.rs
git commit -m "test: add golden tests for non-allowlisted build tool commands"
```

---

### Task 6: Run full test suite and verify

**Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass (unit + golden + integration)

**Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings

**Step 3: Final commit (if any fixups needed)**

If tests pass clean, no commit needed. Otherwise fix and commit.

---

### Task 7: Clean up design doc

**Files:**
- Delete: `docs/plans/2026-01-27-allowlist-classification-design.md` (superseded by this plan)

**Step 1: Remove the design doc**

```
git rm docs/plans/2026-01-27-allowlist-classification-design.md
git commit -m "chore: remove superseded design doc"
```
