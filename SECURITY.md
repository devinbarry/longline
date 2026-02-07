# Security Considerations

Known gaps and future hardening opportunities.

## Resolved Issues

### Package Installation (resolved 2026-02-02)

All package installation commands now require user confirmation (`ask`). Comprehensive rules cover:

- **Python**: pip, pip3, python -m pip, uv pip, uv add, poetry, pipx, pdm, rye, conda, mamba
- **JavaScript**: npm, yarn, pnpm, bun, npx, deno
- **Ruby**: gem, bundle/bundler
- **Rust**: cargo add, cargo install
- **Go**: go get, go install
- **PHP**: composer require, composer install
- **Elixir**: mix deps.get, mix archive.install
- **Dart/Flutter**: dart pub, flutter pub, pub
- **Haskell**: cabal install, stack install
- **.NET**: dotnet add, nuget install
- **Lua**: luarocks install
- **System**: brew, apt, apt-get, dnf, yum, pacman, apk, snap, flatpak, nix-env
- **Privilege escalation**: sudo/doas wrappers for package managers

All package manager version checks (`--version`) and read-only commands (list, info, show) remain allowed.

Future enhancement: `--allow-package-install` flag could bypass this section for trusted workflows.

### Django Shell Pipe Detection (resolved 2026-02-05)

Dedicated extractor in `ai_judge/extract/django.rs` detects `echo`/`printf`/`cat` piped to `manage.py shell` or `shell_plus`. Code is extracted and routed to the AI judge for evaluation. Covered by 6+ golden test cases in `django.yaml`.

## Future Enhancements

### 1. Pipeline Stage Argument Matching

The pipeline matcher (`StageMatcher`) only checks command names per stage, not arguments. This means `curl | python3 -c 'import json; ...'` (safe JSON processing) is denied identically to `curl | python3` (arbitrary remote code execution).

To distinguish these, `StageMatcher` would need `flags` and `args` fields, and `matches_pipeline()` would need to inspect stage arguments. This would enable rules like:

```yaml
# Block curl | python3 (no inline flag = executing downloaded code)
- id: curl-pipe-interpreter-no-inline
  match:
    pipeline:
      stages:
        - command: [curl, wget]
        - command: [python, python3]
          flags:
            none_of: ["-c", "-e"]
  decision: deny
```

An alternative is to downgrade `wget-pipe-interpreter` from `deny` to `ask` for interpreter targets (keeping `deny` for shell targets), letting the AI judge evaluate the inline code.

### 2. Python File Execution Outside Working Directory

Commands like `uv run python /tmp/script.py` or `python ../script.py` execute arbitrary code. The AI judge extractor (`ai_judge/extract/fs.rs`) validates paths (only allows cwd + `/tmp`), but the rules themselves don't flag these invocations -- they only come into play when `--ask-ai` is enabled.

**Proposed mitigation**:
- Add rules that flag Python script execution with paths outside cwd
- Route to AI judge for inspection
- `manage.py` patterns already covered by Django allowlist

### 3. Copy-Then-Execute Pattern

Compound commands can stage malicious files then execute them:
```bash
cp /tmp/evil.py manage.py && python manage.py test
```

Each command passes individually (`cp` allowlisted, `python manage.py test` allowlisted), but the sequence is dangerous.

**Possible mitigations**:
- Detect `cp`/`mv` followed by execution of target file in same compound command
- Track file provenance across command boundaries (complex)
- Route compound commands with `cp`+execution to AI judge

## Accepted Risks

### Symlink Attacks

An agent could create a symlink pointing to malicious code:
```bash
ln -s /tmp/evil.py ./server/manage.py
python server/manage.py test
```

**Why accepted**:
- Requires two-step attack (symlink creation visible in session)
- Overwriting existing files requires `ln -f` which triggers `ask`
- Not a regression from path normalization
- Human review would catch suspicious symlink creation
