#!/usr/bin/env bash
set -euo pipefail

if [ -z "${SANITIZATION_PATTERN:-}" ]; then
  echo "ERROR: SANITIZATION_PATTERN env var not set" >&2
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

# 1. Working-tree contents. There is NO exclusion list. Anyone editing
# scripts/verify-sanitization.sh or tests/sanitization_gate.sh must keep
# them pattern-free (use runtime substring construction).
if git grep -nE "$SANITIZATION_PATTERN"; then
  echo "ERROR: sanitization failed — sensitive strings in working-tree contents" >&2
  failed=1
fi

# 2. Tracked filenames themselves
if git ls-files | grep -E "$SANITIZATION_PATTERN"; then
  echo "ERROR: sanitization failed — sensitive strings in tracked filenames" >&2
  failed=1
fi

# 3. Full rewritten history. -m includes merge diffs (omitted by default
# when -p is set). Covers commit messages and diffs across all reachable
# refs — including the rewritten github-sync branch and the tag.
if git log -p -m --all | grep -nE "$SANITIZATION_PATTERN"; then
  echo "ERROR: sanitization failed — sensitive strings in rewritten history" >&2
  failed=1
fi

# 4. Annotated tag messages and tag ref names. `git log -p` does NOT
# surface annotated tag messages; check them explicitly.
if git for-each-ref --format='%(refname) %(contents)' refs/tags \
     | grep -nE "$SANITIZATION_PATTERN"; then
  echo "ERROR: sanitization failed — sensitive strings in tag messages or ref names" >&2
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  echo "Sanitization gate FAILED. Refusing to push to public mirror." >&2
  exit 1
fi

echo "Sanitization gate PASSED." >&2
