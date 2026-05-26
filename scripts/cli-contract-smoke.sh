#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

export HOME="${TMP_DIR}/home"
export XDG_CONFIG_HOME="${HOME}/.config"
export XDG_STATE_HOME="${HOME}/.local/state"
export HTTP_PROXY="http://127.0.0.1:1"
export HTTPS_PROXY="http://127.0.0.1:1"
export ALL_PROXY="http://127.0.0.1:1"
export NO_PROXY=""
unset CARGO_REGISTRY_TOKEN OPENAI_API_KEY ANTHROPIC_API_KEY CODEX_API_KEY

mkdir -p "${HOME}" "${XDG_CONFIG_HOME}" "${XDG_STATE_HOME}"
WORK_DIR="${TMP_DIR}/work"
mkdir -p "${WORK_DIR}"

if [ -n "${LONGLINE_BIN:-}" ]; then
  if [ ! -x "${LONGLINE_BIN}" ]; then
    echo "ERROR: LONGLINE_BIN is not executable: ${LONGLINE_BIN}" >&2
    exit 2
  fi
  LL="${LONGLINE_BIN}"
else
  LL="$(command -v longline || true)"
  if [ -z "${LL}" ]; then
    echo "ERROR: longline not found on PATH and LONGLINE_BIN is unset" >&2
    exit 2
  fi
fi

echo "Using longline binary: ${LL}"
cd "${WORK_DIR}"

section() {
  printf '\n== %s ==\n' "$1"
}

run_capture() {
  local name="$1"
  shift
  local out="${TMP_DIR}/${name}.out"
  local err="${TMP_DIR}/${name}.err"
  echo "+ $*" >&2
  set +e
  "$@" >"${out}" 2>"${err}"
  local rc=$?
  set -e
  printf '%s\n' "${rc}" >"${TMP_DIR}/${name}.rc"
  echo "${out}"
}

run_stdin_capture() {
  local name="$1"
  local input="$2"
  shift 2
  local out="${TMP_DIR}/${name}.out"
  local err="${TMP_DIR}/${name}.err"
  echo "+ $* <stdin>" >&2
  set +e
  printf '%s' "${input}" | "$@" >"${out}" 2>"${err}"
  local rc=$?
  set -e
  printf '%s\n' "${rc}" >"${TMP_DIR}/${name}.rc"
  echo "${out}"
}

assert_rc() {
  local name="$1"
  local expected="$2"
  local actual
  actual="$(cat "${TMP_DIR}/${name}.rc")"
  if [ "${actual}" != "${expected}" ]; then
    echo "ERROR: ${name} exit code ${actual}, expected ${expected}" >&2
    echo "--- stdout ---" >&2
    cat "${TMP_DIR}/${name}.out" >&2 || true
    echo "--- stderr ---" >&2
    cat "${TMP_DIR}/${name}.err" >&2 || true
    exit 1
  fi
}

assert_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq "${needle}" "${file}"; then
    echo "ERROR: expected ${file} to contain: ${needle}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2 || true
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local needle="$2"
  if grep -Fq "${needle}" "${file}"; then
    echo "ERROR: expected ${file} not to contain: ${needle}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2 || true
    exit 1
  fi
}

assert_empty() {
  local file="$1"
  if [ -s "${file}" ]; then
    echo "ERROR: expected empty stdout in ${file}" >&2
    cat "${file}" >&2 || true
    exit 1
  fi
}

assert_json_path_equals() {
  local file="$1"
  local path="$2"
  local expected="$3"
  python3 - "$file" "$path" "$expected" <<'PY'
import json
import sys

file_name, path, expected = sys.argv[1:4]
with open(file_name, "r", encoding="utf-8") as fh:
    value = json.load(fh)
for part in path.split("."):
    if part.endswith("]"):
        name, index = part[:-1].split("[")
        value = value[name][int(index)]
    else:
        value = value[part]
if str(value) != expected:
    raise SystemExit(f"{file_name}: {path}={value!r}, expected {expected!r}")
PY
}

assert_json_array_has_name() {
  local file="$1"
  local array_path="$2"
  local expected="$3"
  python3 - "$file" "$array_path" "$expected" <<'PY'
import json
import sys

file_name, array_path, expected = sys.argv[1:4]
with open(file_name, "r", encoding="utf-8") as fh:
    value = json.load(fh)
for part in array_path.split("."):
    value = value[part]
if not any(item.get("name") == expected for item in value):
    raise SystemExit(f"{file_name}: no {array_path} entry named {expected!r}")
PY
}

last_log_line() {
  local file="$1"
  if [ ! -f "${file}" ]; then
    echo "ERROR: expected log file to exist: ${file}" >&2
    exit 1
  fi
  tail -n 1 "${file}"
}

claude_bash_json() {
  local command="$1"
  python3 - "$command" "$WORK_DIR" <<'PY'
import json
import sys
print(json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": sys.argv[1]},
    "session_id": "smoke-claude",
    "cwd": sys.argv[2],
}))
PY
}

claude_tool_json() {
  local tool="$1"
  python3 - "$tool" "$WORK_DIR" <<'PY'
import json
import sys
tool = sys.argv[1]
cwd = sys.argv[2]
if tool == "Read":
    tool_input = {"file_path": f"{cwd}/README.md"}
elif tool == "Grep":
    tool_input = {"pattern": "longline", "path": cwd}
elif tool == "Glob":
    tool_input = {"pattern": "*.md", "path": cwd}
else:
    raise SystemExit(f"unknown tool {tool}")
print(json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": tool,
    "tool_input": tool_input,
    "session_id": "smoke-claude",
    "cwd": cwd,
}))
PY
}

codex_json() {
  local event="$1"
  local tool="$2"
  local command="${3:-}"
  python3 - "$event" "$tool" "$command" "$WORK_DIR" <<'PY'
import json
import sys
event, tool, command, cwd = sys.argv[1:5]
tool_input = {"command": command} if command else {}
print(json.dumps({
    "hook_event_name": event,
    "tool_name": tool,
    "tool_input": tool_input,
    "session_id": "smoke-codex",
    "cwd": cwd,
}))
PY
}

section "bare claude hook"
safe_input="$(claude_bash_json "ls -la")"
safe_out="$(run_stdin_capture bare_safe "${safe_input}" "${LL}")"
assert_rc bare_safe 0
assert_json_path_equals "${safe_out}" "hookSpecificOutput.permissionDecision" "allow"

readme_minimal_input='{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
readme_minimal_out="$(run_stdin_capture readme_minimal "${readme_minimal_input}" "${LL}")"
assert_rc readme_minimal 0
assert_json_path_equals "${readme_minimal_out}" "hookSpecificOutput.permissionDecision" "allow"

deny_input="$(claude_bash_json "rm -rf /")"
deny_out="$(run_stdin_capture bare_deny "${deny_input}" "${LL}")"
assert_rc bare_deny 0
assert_json_path_equals "${deny_out}" "hookSpecificOutput.permissionDecision" "deny"

section "rules"
rules_out="$(run_capture rules "${LL}" rules)"
assert_rc rules 0
assert_contains "${rules_out}" "DECISION"
assert_contains "${rules_out}" "rm-recursive-root"
assert_contains "${rules_out}" "Allowlist:"

rules_verbose_out="$(run_capture rules_verbose "${LL}" rules --verbose)"
assert_rc rules_verbose 0
assert_contains "${rules_verbose_out}" "MATCH"

rules_filter_out="$(run_capture rules_filter_deny "${LL}" rules --filter deny)"
assert_rc rules_filter_deny 0
assert_contains "${rules_filter_out}" "rm-recursive-root"
assert_not_contains "${rules_filter_out}" "chmod-777"

rules_level_out="$(run_capture rules_level_high "${LL}" rules --level high)"
assert_rc rules_level_high 0
assert_contains "${rules_level_out}" "Safety level:"

rules_group_out="$(run_capture rules_group "${LL}" rules --group-by decision)"
assert_rc rules_group 0
assert_contains "${rules_group_out}" "DENY"

section "check"
COMMANDS_FILE="${WORK_DIR}/commands.txt"
cat >"${COMMANDS_FILE}" <<'EOF'
ls -la
chmod 777 /tmp/f
rm -rf /
EOF

check_file_out="$(run_capture check_file "${LL}" check "${COMMANDS_FILE}")"
assert_rc check_file 0
assert_contains "${check_file_out}" "allow"
assert_contains "${check_file_out}" "ask"
assert_contains "${check_file_out}" "deny"

check_stdin_out="$(run_stdin_capture check_stdin "rm -rf /" "${LL}" check)"
assert_rc check_stdin 0
assert_contains "${check_stdin_out}" "deny"

check_filter_out="$(run_capture check_filter_ask "${LL}" check "${COMMANDS_FILE}" --filter ask)"
assert_rc check_filter_ask 0
assert_contains "${check_filter_out}" "chmod 777 /tmp/f"
assert_not_contains "${check_filter_out}" "rm -rf /"

section "init and config discovery"
init_out="$(run_capture init "${LL}" init)"
assert_rc init 0
test -f "${HOME}/.config/longline/rules.yaml"
test -f "${HOME}/.config/longline/core-allowlist.yaml"
test -f "${HOME}/.config/longline/git.yaml"

run_capture init_again "${LL}" init >/dev/null
assert_rc init_again 1

init_force_out="$(run_capture init_force "${LL}" init --force)"
assert_rc init_force 0

files_out="$(run_capture files "${LL}" files)"
assert_rc files 0
assert_contains "${files_out}" "Total:"
assert_contains "${files_out}" "rules"

rules_config_out="$(run_capture rules_config "${LL}" rules --config "${HOME}/.config/longline/rules.yaml")"
assert_rc rules_config 0
assert_contains "${rules_config_out}" "rm-recursive-root"

check_config_out="$(run_capture check_config "${LL}" check "${COMMANDS_FILE}" --config "${HOME}/.config/longline/rules.yaml")"
assert_rc check_config 0
assert_contains "${check_config_out}" "rm -rf /"

files_auto_out="$(run_capture files_auto "${LL}" files)"
assert_rc files_auto 0
assert_contains "${files_auto_out}" "Rules manifest: ${HOME}/.config/longline/rules.yaml"

section "profiles"
cat >"${HOME}/.config/longline/longline.yaml" <<'EOF'
defaults:
  codex: strict-smoke
profiles:
  strict-smoke:
    safety_level: strict
    rules:
      - id: strict-smoke-test-rule
        level: high
        match:
          command: strict-smoke-command
        decision: ask
        reason: strict smoke profile rule
EOF

profiles_out="$(run_capture profiles "${LL}" profiles)"
assert_rc profiles 0
assert_contains "${profiles_out}" "strict-smoke"

profiles_runtime_out="$(run_capture profiles_runtime "${LL}" profiles --runtime codex)"
assert_rc profiles_runtime 0
assert_contains "${profiles_runtime_out}" "strict-smoke"

profiles_json_out="$(run_capture profiles_json "${LL}" profiles --json)"
assert_rc profiles_json 0
assert_json_array_has_name "${profiles_json_out}" "profiles" "strict-smoke"
assert_json_path_equals "${profiles_json_out}" "defaults.codex.name" "strict-smoke"
assert_json_path_equals "${profiles_json_out}" "defaults.codex.source" "global"

profile_rules_out="$(run_capture profile_rules "${LL}" rules --profile strict-smoke)"
assert_rc profile_rules 0
assert_contains "${profile_rules_out}" "strict-smoke-test-rule"

profile_files_out="$(run_capture profile_files "${LL}" files --profile strict-smoke)"
assert_rc profile_files 0
assert_contains "${profile_files_out}" "Total:"

profile_check_out="$(run_capture profile_check "${LL}" check --profile strict-smoke "strict-smoke-command")"
assert_rc profile_check 0
assert_contains "${profile_check_out}" "strict-smoke-test-rule"

profile_hook_input="$(claude_bash_json "strict-smoke-command")"
profile_bare_out="$(run_stdin_capture profile_bare "${profile_hook_input}" "${LL}" --profile strict-smoke)"
assert_rc profile_bare 0
assert_contains "${profile_bare_out}" "strict smoke profile rule"
last_log_line "${HOME}/.claude/hooks-logs/longline.jsonl" >"${TMP_DIR}/claude-last.json"
assert_json_path_equals "${TMP_DIR}/claude-last.json" "profile" "strict-smoke"

profile_claude_out="$(run_stdin_capture profile_claude "${profile_hook_input}" "${LL}" hook claude --profile strict-smoke)"
assert_rc profile_claude 0
assert_contains "${profile_claude_out}" "strict smoke profile rule"

profile_codex_input="$(codex_json "PermissionRequest" "Bash" "strict-smoke-command")"
profile_codex_out="$(run_stdin_capture profile_codex "${profile_codex_input}" "${LL}" hook codex --profile strict-smoke)"
assert_rc profile_codex 0
assert_empty "${profile_codex_out}"
last_log_line "${HOME}/.codex/hooks-logs/longline.jsonl" >"${TMP_DIR}/codex-last.json"
assert_json_path_equals "${TMP_DIR}/codex-last.json" "profile" "strict-smoke"
assert_contains "${TMP_DIR}/codex-last.json" "strict-smoke-test-rule"

section "hook subcommands"
claude_safe_out="$(run_stdin_capture claude_safe "${safe_input}" "${LL}" hook claude)"
assert_rc claude_safe 0
assert_json_path_equals "${claude_safe_out}" "hookSpecificOutput.permissionDecision" "allow"

for tool in Read Grep Glob; do
  input="$(claude_tool_json "${tool}")"
  bare_out="$(run_stdin_capture "bare_${tool}" "${input}" "${LL}")"
  explicit_out="$(run_stdin_capture "hook_${tool}" "${input}" "${LL}" hook claude)"
  assert_rc "bare_${tool}" 0
  assert_rc "hook_${tool}" 0
  cmp -s "${bare_out}" "${explicit_out}"
done

sensitive_read="$(python3 - <<'PY'
import json
print(json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Read",
    "tool_input": {"file_path": "/etc/shadow"},
    "session_id": "smoke-claude",
    "cwd": "/tmp",
}))
PY
)"
sensitive_read_out="$(run_stdin_capture sensitive_read "${sensitive_read}" "${LL}")"
assert_rc sensitive_read 0
assert_json_path_equals "${sensitive_read_out}" "hookSpecificOutput.permissionDecision" "ask"

sensitive_grep="$(python3 - <<'PY'
import json
print(json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Grep",
    "tool_input": {"pattern": "root", "path": "/etc/shadow"},
    "session_id": "smoke-claude",
    "cwd": "/tmp",
}))
PY
)"
sensitive_grep_out="$(run_stdin_capture sensitive_grep "${sensitive_grep}" "${LL}")"
assert_rc sensitive_grep 0
assert_json_path_equals "${sensitive_grep_out}" "hookSpecificOutput.permissionDecision" "ask"

sensitive_glob="$(python3 - <<'PY'
import json
print(json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Glob",
    "tool_input": {"pattern": "*", "path": "/home/user/.ssh/"},
    "session_id": "smoke-claude",
    "cwd": "/tmp",
}))
PY
)"
sensitive_glob_out="$(run_stdin_capture sensitive_glob "${sensitive_glob}" "${LL}")"
assert_rc sensitive_glob 0
assert_json_path_equals "${sensitive_glob_out}" "hookSpecificOutput.permissionDecision" "ask"

malformed="{this is not valid json"
malformed_bare_out="$(run_stdin_capture malformed_bare "${malformed}" "${LL}")"
malformed_hook_out="$(run_stdin_capture malformed_hook "${malformed}" "${LL}" hook claude)"
assert_rc malformed_bare 0
assert_rc malformed_hook 0
cmp -s "${malformed_bare_out}" "${malformed_hook_out}"

codex_pre_allow_out="$(run_stdin_capture codex_pre_allow "$(codex_json "PreToolUse" "Bash" "ls")" "${LL}" hook codex)"
assert_rc codex_pre_allow 0
assert_empty "${codex_pre_allow_out}"

codex_pre_ask_out="$(run_stdin_capture codex_pre_ask "$(codex_json "PreToolUse" "Bash" "chmod 777 /tmp/f")" "${LL}" hook codex)"
assert_rc codex_pre_ask 0
assert_empty "${codex_pre_ask_out}"

codex_pre_deny_out="$(run_stdin_capture codex_pre_deny "$(codex_json "PreToolUse" "Bash" "rm -rf /")" "${LL}" hook codex)"
assert_rc codex_pre_deny 0
assert_json_path_equals "${codex_pre_deny_out}" "hookSpecificOutput.permissionDecision" "deny"
assert_not_contains "${codex_pre_allow_out}" "permissionDecision"

codex_perm_allow_out="$(run_stdin_capture codex_perm_allow "$(codex_json "PermissionRequest" "Bash" "ls")" "${LL}" hook codex)"
assert_rc codex_perm_allow 0
assert_json_path_equals "${codex_perm_allow_out}" "hookSpecificOutput.decision.behavior" "allow"

codex_perm_deny_out="$(run_stdin_capture codex_perm_deny "$(codex_json "PermissionRequest" "Bash" "rm -rf /")" "${LL}" hook codex)"
assert_rc codex_perm_deny 0
assert_json_path_equals "${codex_perm_deny_out}" "hookSpecificOutput.decision.behavior" "deny"

codex_perm_ask_out="$(run_stdin_capture codex_perm_ask "$(codex_json "PermissionRequest" "Bash" "chmod 777 /tmp/f")" "${LL}" hook codex)"
assert_rc codex_perm_ask 0
assert_empty "${codex_perm_ask_out}"

codex_apply_patch_out="$(run_stdin_capture codex_apply_patch "$(codex_json "PreToolUse" "apply_patch")" "${LL}" hook codex)"
assert_rc codex_apply_patch 0
assert_empty "${codex_apply_patch_out}"

codex_mcp_out="$(run_stdin_capture codex_mcp "$(codex_json "PermissionRequest" "mcp__filesystem__read_file")" "${LL}" hook codex)"
assert_rc codex_mcp 0
assert_empty "${codex_mcp_out}"

section "ai judge flags"
for flag in --ask-ai --ask-ai-lenient --lenient; do
  out="$(run_stdin_capture "ai_${flag#--}" "${safe_input}" "${LL}" "${flag}" hook claude)"
  assert_rc "ai_${flag#--}" 0
  assert_json_path_equals "${out}" "hookSpecificOutput.permissionDecision" "allow"
done

echo
echo "CLI contract smoke tests passed."
