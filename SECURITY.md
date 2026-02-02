# Security Considerations

Known gaps and future hardening opportunities.

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
