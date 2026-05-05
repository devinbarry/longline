#!/usr/bin/env bash
set -euo pipefail

if [ -z "${SANITIZATION_PATTERN:-}" ]; then
  echo "ERROR: SANITIZATION_PATTERN env var not set" >&2
  exit 2
fi

# Validate regex syntax up front. grep -E returns 1 (no match) on valid regex
# against empty input, and 2+ on regex syntax errors. Fail-closed if invalid
# — a malformed pattern would otherwise make every check return "no match"
# and silently disable the gate.
rc=0
printf '' | grep -E "$SANITIZATION_PATTERN" >/dev/null 2>&1 || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "ERROR: SANITIZATION_PATTERN is not a valid extended regex (grep rc=$rc)" >&2
  exit 2
fi

# Defensive: `git filter-repo` removes refs/original/* by default after a
# rewrite, but if a previous run was interrupted those backup refs may
# remain and would silently expand `git log --all` to include unrewritten
# history. Refusing to run is safer than scanning an ambiguous ref space.
if [ -n "$(git for-each-ref --format='%(refname)' refs/original 2>/dev/null)" ]; then
  echo "ERROR: refs/original/* present — sanitization context is unclear" >&2
  echo "Run: git for-each-ref refs/original --format='%(refname)' | xargs -r -n1 git update-ref -d" >&2
  exit 2
fi

failed=0

# Each check below uses `cmd || rc=$?` to capture grep's exit code
# explicitly and route it through a `case` block. The naïve form
# `if cmd; then ...; fi` would treat ANY non-zero exit (including regex
# errors and internal failures, exit codes >= 2) as "no match" and
# silently disable the gate. Fail-closed semantics require treating
# unexpected exit codes as failures.

# 1. Working-tree contents. There is NO exclusion list. Anyone editing
# scripts/verify-sanitization.sh or tests/sanitization_gate.sh must keep
# them pattern-free (use runtime substring construction).
rc=0
git grep -nE "$SANITIZATION_PATTERN" || rc=$?
case "$rc" in
  0) echo "ERROR: sanitization failed — sensitive strings in working-tree contents" >&2; failed=1 ;;
  1) ;;  # no match — clean
  *) echo "ERROR: working-tree scan failed unexpectedly (rc=$rc) — fail-closed" >&2; failed=1 ;;
esac

# 2. Tracked filenames themselves
rc=0
git ls-files | grep -E "$SANITIZATION_PATTERN" || rc=$?
case "$rc" in
  0) echo "ERROR: sanitization failed — sensitive strings in tracked filenames" >&2; failed=1 ;;
  1) ;;
  *) echo "ERROR: filename scan failed unexpectedly (rc=$rc) — fail-closed" >&2; failed=1 ;;
esac

# 3. Full rewritten history. -m includes merge diffs (omitted by default
# when -p is set). Covers commit messages, diffs, AND author/committer
# identity headers across all reachable refs — including the rewritten
# github-sync branch and the tag.
rc=0
git log -p -m --all | grep -nE "$SANITIZATION_PATTERN" || rc=$?
case "$rc" in
  0) echo "ERROR: sanitization failed — sensitive strings in rewritten history" >&2; failed=1 ;;
  1) ;;
  *) echo "ERROR: history scan failed unexpectedly (rc=$rc) — fail-closed" >&2; failed=1 ;;
esac

# 4. Annotated tag messages and tag ref names. `git log -p` does NOT
# surface annotated tag messages; check them explicitly.
rc=0
git for-each-ref --format='%(refname) %(contents)' refs/tags \
  | grep -nE "$SANITIZATION_PATTERN" || rc=$?
case "$rc" in
  0) echo "ERROR: sanitization failed — sensitive strings in tag messages or ref names" >&2; failed=1 ;;
  1) ;;
  *) echo "ERROR: tag-message scan failed unexpectedly (rc=$rc) — fail-closed" >&2; failed=1 ;;
esac

if [ "$failed" -ne 0 ]; then
  echo "Sanitization gate FAILED. Refusing to push to public mirror." >&2
  exit 1
fi

echo "Sanitization gate PASSED." >&2
