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

# Case 6 — sensitive content in commit author/committer metadata. Check 3
# catches this because `git log -p` includes Author/Committer headers.
# This case asserts the production pipeline's metadata-rewrite step
# (`git filter-repo --email-callback` / `--name-callback` in
# .gitlab-ci.yml) is necessary — without it, an upstream commit whose
# author email contains the sensitive pattern would survive the path-
# strip + replace-text passes (which do NOT touch identity headers) and
# trip the gate, blocking the public push.
git -c user.email="user@${T_DOMAIN}.example" \
    -c user.name="contributor" \
    commit --quiet --allow-empty -m "commit by sensitive author"
assert_fails "author email leak (check 3 covers metadata)"
git reset --quiet --hard HEAD~1

# Case 7 — invalid regex pattern. Gate must exit 2 (config error) and
# refuse to scan, NOT exit 0 with "PASSED" (which would happen if
# malformed regex caused every check to return "no match" via grep
# rc=2 being treated as "no match" by an `if cmd; then` form).
rc=0
SANITIZATION_PATTERN='(' "$GATE" >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 2 ]; then
  echo "FAIL: invalid regex case — gate exited $rc, expected 2 (config error)" >&2
  exit 1
fi
echo "ok: invalid regex (gate exits 2, not 0)"

# Case 8 — sensitive content in COMMITTER metadata only (author clean).
# Default `git log -p` format shows only Author, not Committer; the gate
# must use --format=fuller (or explicit format) to surface committer.
# Without that, a committer-only leak would slip past the gate.
GIT_AUTHOR_NAME="author" GIT_AUTHOR_EMAIL="author@example.com" \
  GIT_COMMITTER_NAME="committer" \
  GIT_COMMITTER_EMAIL="committer@${T_DOMAIN}.example" \
  git commit --quiet --allow-empty -m "commit with sensitive committer"
assert_fails "committer email leak (check 3 covers committer)"
git reset --quiet --hard HEAD~1

# Case 9 — sensitive content in TAGGER metadata only (tag message clean,
# tagger identity sensitive). `git for-each-ref` `%(contents)` does NOT
# include tagger atoms; the gate must include `%(taggername)
# %(taggeremail)` in the format. Without that, a tagger-only leak would
# slip past the gate.
GIT_COMMITTER_NAME="tagger" \
  GIT_COMMITTER_EMAIL="tagger@${T_HOST}.example" \
  git tag -a leaky-tagger -m "clean message body"
assert_fails "tagger email leak (check 4 covers tagger metadata)"
git tag -d leaky-tagger >/dev/null

echo "All sanitization gate cases passed."
