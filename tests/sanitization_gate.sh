#!/usr/bin/env bash
# Test that scripts/verify-sanitization.sh fires on every check it claims
# AND passes when there is genuinely no sensitive content. Each case is
# isolated so a broken individual check cannot be masked by another check
# firing on the same fixture.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
GATE="$ROOT/scripts/verify-sanitization.sh"

# Build trigger strings at runtime via substring concatenation so this
# file's static content does not itself match the sensitive pattern.
# This split is LOAD-BEARING — anyone editing this test must preserve it.
# Never inline the literal trigger strings. The gate has no exclusion list;
# if any trigger literal lands in this file the next tag pipeline will fail.
T_DOMAIN="un""obtain"
T_HOST="git""fox"
T_USER_PATH="/Users""/axion"
T_LINUX_PATH="/home""/axion"
PATTERN="$T_DOMAIN|$T_HOST|$T_USER_PATH|$T_LINUX_PATH"

export SANITIZATION_PATTERN="$PATTERN"

# Synthetic minimal repo — NOT a clone of $ROOT. Cloning the real repo
# would inherit legitimately-tracked literals (the SANITIZATION_PATTERN
# declaration in .gitlab-ci.yml). That file is stripped by `git filter-repo`
# before the gate runs in CI. A synthetic repo lets us test the gate's
# behavior in isolation from the strip pipeline.
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
mkdir -p "$WORKDIR/repo" && cd "$WORKDIR/repo"
git init --quiet
git config user.email test@example.com
git config user.name test
echo "hello" > README.md
git add README.md && git commit --quiet -m "init"

assert_fails() {
  local case_name="$1"
  if SANITIZATION_PATTERN="$PATTERN" "$GATE" >/dev/null 2>&1; then
    echo "FAIL: $case_name — gate passed but should have failed" >&2; exit 1
  fi
  echo "ok: $case_name"
}

assert_passes() {
  local case_name="$1"
  if ! SANITIZATION_PATTERN="$PATTERN" "$GATE" >/dev/null 2>&1; then
    echo "FAIL: $case_name — gate failed but should have passed" >&2; exit 1
  fi
  echo "ok: $case_name"
}

# Case 1 — clean baseline. Gate must pass on a repo with no sensitive
# content anywhere.
assert_passes "clean baseline"

# Case 2 — staged-but-uncommitted working-tree content. Only check 1
# catches this (git grep searches the working tree of tracked files;
# truly untracked files are out of scope, but in CI filter-repo has
# already operated, so untracked files cannot exist there). Proves
# check 1 is independently functional. The filename "leak.txt" is clean
# so check 2 does not fire; the content is not committed so check 3
# does not fire.
echo "leaked: $T_DOMAIN" > leak.txt
git add leak.txt
assert_fails "uncommitted content (check 1 only)"
git rm --cached --quiet leak.txt && rm -f leak.txt

# Case 3 — staged-but-uncommitted sensitive filename. Only check 2 catches;
# the file is empty so check 1 sees nothing, the leak isn't committed so
# check 3 sees nothing.
mkdir -p "${T_HOST}-fixtures" && touch "${T_HOST}-fixtures/x"
git add "${T_HOST}-fixtures"
assert_fails "uncommitted filename (check 2 only)"
git rm --cached --quiet -r "${T_HOST}-fixtures" && rm -rf "${T_HOST}-fixtures"

# Case 4 — sensitive content in commit history of a file that no longer
# exists in the working tree. Only check 3 catches.
echo "old: $T_USER_PATH" > old.txt
git add old.txt && git commit --quiet -m "history leak setup"
git rm --quiet old.txt && git commit --quiet -m "remove old.txt"
assert_fails "history-only leak (check 3 only)"
git reset --quiet --hard HEAD~2

# Case 5 — sensitive content in an annotated tag's message. Only the
# tag-message scan (check 4) catches this; `git log -p --all` does not
# surface tag annotations.
git tag -a leaky-tag -m "release with $T_LINUX_PATH"
assert_fails "annotated tag message (check 4 only)"
git tag -d leaky-tag >/dev/null

echo "All sanitization gate cases passed."
