# Diagnostic and Override Modes

## Overview

Three additions to the longline CLI: two diagnostic subcommands (`check`, `rules`) and one runtime override flag (`--ask-on-deny`).

## CLI Structure

```
longline                          # hook mode (existing behavior)
longline --ask-on-deny            # hook mode, deny -> ask override
longline check [FILE]             # test commands against rules
longline rules                    # show current rule config
```

## `longline check`

Test commands against the loaded rules. Reads one command per line from a file or stdin. Blank lines and `#` comments skipped.

```
longline check [OPTIONS] [FILE]

Arguments:
  [FILE]    File with one command per line (- or omit for stdin)

Options:
  -c, --config <FILE>       Rules file (same as hook mode)
  -f, --filter <DECISION>   Show only: allow, ask, or deny
```

Output:

```
DECISION  RULE              COMMAND
allow     (allowlist)       ls -la
ask       (default)         curl http://example.com
deny      rm-recursive-rf   rm -rf /
deny      env-file-access   cat .env
ask       (opaque)          eval "$DYNAMIC"
```

Exit code 0 always.

## `longline rules`

Show the current rule configuration in human-readable form.

```
longline rules [OPTIONS]

Options:
  -c, --config <FILE>       Rules file
  -v, --verbose             Show full matcher patterns and details
  -f, --filter <DECISION>   Show only: allow, ask, or deny
  -l, --level <LEVEL>       Show only: critical, high, or strict
  -g, --group-by <FIELD>    Group output by: decision or level
```

Default output (minimal):

```
DECISION  LEVEL     ID                      DESCRIPTION
deny      critical  rm-recursive-rf         Recursive delete targeting critical paths
deny      critical  env-file-access         Access to .env and credential files
ask       high      git-force-push          Force push to any branch
...

Allowlist: cat, ls, echo, grep, find, ... (47 commands)
Safety level: high
Default decision: ask
```

With `--group-by decision`:

```
-- deny -------------------------------------------------------
  critical  rm-recursive-rf         Recursive delete targeting critical paths
  critical  env-file-access         Access to .env and credential files

-- ask --------------------------------------------------------
  high      git-force-push          Force push to any branch
  high      chmod-recursive         Recursive permission changes

Allowlist: cat, ls, echo, ... (47 commands)
Safety level: high | Default decision: ask
```

Filters stack: `--filter deny --level critical` shows only critical denies.

`--verbose` expands each rule to show matcher patterns, flags, args globs, and full reason.

## `--ask-on-deny`

Root-level flag for hook mode. Downgrades deny decisions to ask so the user is prompted instead of blocked.

- Applied after policy evaluation, before output
- Reason prefixed: `[overridden] <original reason>`
- Log records both original and overridden decision with `overridden: true` field
- No effect on allow or ask decisions

Hook config usage:

```json
{
  "hooks": {
    "PreToolUse": [{
      "command": "longline --ask-on-deny --config /path/to/rules.yaml"
    }]
  }
}
```

Log entry with override:

```json
{
  "ts": "2026-01-27T...",
  "command": "rm -rf ./build",
  "decision": "ask",
  "original_decision": "deny",
  "overridden": true,
  "rule_id": "rm-recursive-rf",
  "reason": "[overridden] Recursive delete targeting critical paths"
}
```
