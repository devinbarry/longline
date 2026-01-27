# Allowlist Command Classification

Split allowlist into always-safe (bare) and conditionally-safe (multi-word) entries. Remove bare entries for commands that can be destructive. Add explicit safe invocations. Add rules for destructive variants.

## Approach

Keep single `allowlists.commands` list. No schema change. Bare entries = any invocation allowed. Multi-word entries = only matching invocations allowed. Unmatched invocations fall to `default_decision: ask`.

## Always Safe (bare entries)

Read-only / output-only:
`ls`, `echo`, `pwd`, `whoami`, `date`, `cat`, `head`, `tail`, `wc`, `file`, `which`, `type`, `basename`, `dirname`, `realpath`, `readlink`, `stat`, `du`, `printf`, `md5sum`, `sha256sum`, `sha1sum`, `cksum`, `true`, `false`, `grep`, `rg`, `fd`, `sort`, `uniq`, `tr`, `cut`, `diff`, `jq`, `yq`, `test`

Dev tools (no publish risk, restricting adds friction):
`make`, `cmake`, `rustc`, `java`, `javac`, `node`, `python`, `python3`, `ruby`, `npx`

Filesystem ops (secrets caught by rules):
`mkdir`, `touch`, `ln`, `cp`, `mv`, `tee`, `tar`, `gzip`, `gunzip`, `zip`, `unzip`

Text processing:
`sed`, `awk`, `xargs`, `patch`, `find`

## Conditionally Safe (multi-word entries)

### Git

Read ops (existing): `git status`, `git diff`, `git log`, `git show`, `git branch`, `git stash list`, `git remote`, `git tag`, `git rev-parse`, `git config`

Safe writes (new): `git add`, `git commit`, `git fetch`, `git pull`, `git push`, `git stash`, `git checkout`, `git switch`, `git restore`, `git merge`, `git rebase`, `git cherry-pick`, `git worktree`, `git clone`, `git init`

Read-only extras (new): `git blame`, `git bisect`, `git describe`, `git shortlog`, `git reflog`, `git ls-files`, `git ls-tree`, `git cat-file`

### Cargo

`cargo build`, `cargo test`, `cargo check`, `cargo clippy`, `cargo fmt`, `cargo run`, `cargo bench`, `cargo doc`, `cargo clean`, `cargo update`, `cargo add`, `cargo remove`, `cargo init`, `cargo new`, `cargo tree`, `cargo metadata`, `cargo vendor`

Not allowlisted (falls to ask): `cargo publish`, `cargo login`, `cargo owner`, `cargo yank`

### npm

`npm install`, `npm ci`, `npm test`, `npm run`, `npm start`, `npm ls`, `npm outdated`, `npm audit`, `npm init`, `npm exec`, `npm info`, `npm pack`

Not allowlisted: `npm publish`, `npm unpublish`, `npm deprecate`, `npm access`

### pip / pip3

`pip install`, `pip list`, `pip show`, `pip freeze`, `pip check` (same for `pip3`)

Not allowlisted: `pip uninstall`, `pip upload`

### gem

`gem install`, `gem list`, `gem info`, `gem search`

Not allowlisted: `gem push`, `gem uninstall`

### go

`go build`, `go test`, `go run`, `go vet`, `go fmt`, `go mod`, `go generate`, `go doc`, `go get`, `go clean`, `go env`, `go version`, `go work`

Not allowlisted: `go install` (modifies GOPATH/bin)

## New Rules

```yaml
- id: git-commit-amend
  level: high
  match:
    command: git
    args: ["commit"]
    flags:
      any_of: ["--amend"]
  decision: ask
  reason: "git commit --amend rewrites the previous commit"
```

Existing rules already cover: `git push --force`, `git reset --hard`, `git clean -f`, `git branch -D`, `git checkout .`/`git restore --`.

## Test Changes

- `git.yaml`: `git add`, `git commit`, `git fetch`, `git pull`, `git push` change from `ask` to `allow`. Add `git commit --amend` = `ask`.
- `safe-commands.yaml`: Add tests for expanded build tool invocations.
- New golden file or expand existing: `cargo publish` = `ask`, `npm publish` = `ask`, etc.

## Implementation Steps

1. Update `rules/default-rules.yaml`: restructure allowlist, add `git-commit-amend` rule
2. Update `tests/golden/git.yaml`: flip write ops to `allow`, add `--amend` test
3. Update `tests/golden/safe-commands.yaml`: add build tool safe invocation tests
4. Add golden tests for non-allowlisted build tool commands (publish, etc.)
5. Run `cargo test` to verify all tests pass
