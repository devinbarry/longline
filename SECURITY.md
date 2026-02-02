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

## Future Enhancements

### 1. Django Shell Pipe Detection

When Claude pipes Python code into Django shell:
```bash
echo "User.objects.all().delete()" | python manage.py shell
```

This bypasses command-level analysis. Should route to AI judge for code inspection.

### 2. Python File Execution Outside Working Directory

Commands like `uv run python /tmp/script.py` or `python ../script.py` execute arbitrary code.

**Proposed mitigation**:
- Allowlist scripts inside current working directory (trusted project files)
- Route scripts outside cwd to AI judge for inspection
- Default `manage.py` patterns already covered by Django allowlist

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
