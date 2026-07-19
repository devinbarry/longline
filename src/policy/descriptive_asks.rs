use crate::domain::{Decision, PolicyResult};
use crate::parser::{SimpleCommand, Statement};

fn ask(rule_id: &str, reason: &str) -> PolicyResult {
    PolicyResult {
        decision: Decision::Ask,
        rule_id: Some(rule_id.to_string()),
        reason: reason.to_string(),
    }
}

fn basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

fn arg(cmd: &SimpleCommand, index: usize) -> Option<&str> {
    cmd.argv.get(index).map(|a| a.text.as_str())
}

fn has_any_assignment(cmd: &SimpleCommand) -> bool {
    !cmd.assignments.is_empty()
}

fn gh_subcommand(cmd: &SimpleCommand) -> Option<&str> {
    arg(cmd, 0)
}

fn sensitive_gh_family(subcommand: &str) -> bool {
    matches!(
        subcommand,
        "api" | "release" | "search" | "gist" | "label" | "secret"
    )
}

fn gh_suspicious_wrapper() -> PolicyResult {
    ask(
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    )
}

fn exec_option_width(text: &str) -> Option<usize> {
    if !text.starts_with('-') || text == "-" {
        return None;
    }

    let mut chars = text[1..].chars();
    while let Some(ch) = chars.next() {
        match ch {
            'c' | 'l' => {}
            'a' => return Some(if chars.as_str().is_empty() { 2 } else { 1 }),
            _ => return None,
        }
    }
    Some(1)
}

fn exec_command_index(cmd: &SimpleCommand) -> Option<usize> {
    let mut index = 0;
    while index < cmd.argv.len() {
        let text = cmd.argv[index].text.as_str();
        if text == "--" {
            return (index + 1 < cmd.argv.len()).then_some(index + 1);
        }
        if text.starts_with('-') {
            index += exec_option_width(text)?;
            continue;
        }
        return Some(index);
    }
    None
}

fn stdbuf_command_index(cmd: &SimpleCommand) -> Option<usize> {
    let mut index = 0;
    while index < cmd.argv.len() {
        let text = cmd.argv[index].text.as_str();
        if text == "--" {
            return (index + 1 < cmd.argv.len()).then_some(index + 1);
        }
        if matches!(
            text,
            "-i" | "-o" | "-e" | "--input" | "--output" | "--error"
        ) {
            index += 2;
            continue;
        }
        if text.starts_with("--input=")
            || text.starts_with("--output=")
            || text.starts_with("--error=")
        {
            index += 1;
            continue;
        }
        if text.len() > 2
            && text.starts_with('-')
            && matches!(text.as_bytes()[1], b'i' | b'o' | b'e')
        {
            index += 1;
            continue;
        }
        if text.starts_with('-') {
            return None;
        }
        return Some(index);
    }
    None
}

fn unbuffer_command_index(cmd: &SimpleCommand) -> Option<usize> {
    let mut index = 0;
    while index < cmd.argv.len() {
        let text = cmd.argv[index].text.as_str();
        if text == "--" {
            return (index + 1 < cmd.argv.len()).then_some(index + 1);
        }
        if text == "-p" {
            index += 1;
            continue;
        }
        if text.starts_with('-') {
            return None;
        }
        return Some(index);
    }
    None
}

fn wrapper_command_index(cmd: &SimpleCommand, wrapper: &str) -> Option<usize> {
    match wrapper {
        "exec" => exec_command_index(cmd),
        "stdbuf" => stdbuf_command_index(cmd),
        "unbuffer" => unbuffer_command_index(cmd),
        _ => None,
    }
}

fn classified_gh_wrapper(cmd: &SimpleCommand, is_extra: bool) -> Option<PolicyResult> {
    let name = basename(cmd.name.as_deref()?);

    if name == "gh" {
        let subcommand = gh_subcommand(cmd)?;
        if (is_extra || has_any_assignment(cmd)) && sensitive_gh_family(subcommand) {
            return Some(gh_suspicious_wrapper());
        }
    }

    if matches!(name, "exec" | "stdbuf" | "unbuffer") {
        if let Some(pos) = wrapper_command_index(cmd, name) {
            let command = cmd.argv.get(pos).map(|arg| arg.text.as_str())?;
            let subcommand = cmd.argv.get(pos + 1).map(|arg| arg.text.as_str());
            if basename(command) == "gh" && subcommand.is_some_and(sensitive_gh_family) {
                return Some(gh_suspicious_wrapper());
            }
        }
    }

    None
}

fn redirected_shell_c(cmd: &SimpleCommand) -> Option<PolicyResult> {
    if cmd.redirects.is_empty() {
        return None;
    }
    // Mirror the gate's safety conditions: skip only when there are
    // no env-var assignments AND the redirect set is a pure output
    // discard (handles `>/dev/null 2>&1` etc.). With assignments
    // present, the gate keeps the wrapper uncovered (per
    // shell_c_covered_via_extras), so this classifier must still
    // ASK to give the user a meaningful reason rather than the
    // generic Unrecognized-command fallback.
    if cmd.assignments.is_empty()
        && crate::policy::redirects::redirects_discard_all_output(&cmd.redirects)
    {
        return None;
    }
    if matches!(
        crate::parser::shell_c::unwrap_shell_c(cmd),
        Some(stmt) if !matches!(stmt, Statement::Opaque(_))
    ) {
        return Some(ask(
            "shell-c-redirect",
            "Shell command wrapper output is redirected",
        ));
    }
    None
}

/// True when `env` has no executable operand and therefore dumps the
/// environment. Policy maps this shape onto the active `printenv` rule so its
/// configured level, decision, reason, replacement, and disable semantics are
/// preserved.
pub(super) fn is_env_dump(cmd: &SimpleCommand) -> bool {
    cmd.name
        .as_deref()
        .is_some_and(|name| basename(name) == "env")
        && crate::parser::wrappers::unwrap_transparent(cmd).is_none()
}

/// Preserve project-script protection for a successfully unwrapped relative
/// `./env` invocation. Ordinary executable `env` forms are transparent and
/// inherit their extracted inner command's policy.
pub(super) fn classify_env(cmd: &SimpleCommand) -> Option<PolicyResult> {
    let full_name = cmd.name.as_deref()?;
    if basename(full_name) != "env" {
        return None;
    }
    if !is_env_dump(cmd) && (full_name.starts_with("./") || full_name.starts_with("../")) {
        return Some(ask("project-script-exec", "Runs a project-local script"));
    }
    None
}

pub(super) fn classify(cmd: &SimpleCommand, is_extra: bool) -> Option<PolicyResult> {
    let full_name = cmd.name.as_deref()?;
    let name = basename(full_name);

    if let Some(result) = classified_gh_wrapper(cmd, is_extra) {
        return Some(result);
    }

    if let Some(result) = redirected_shell_c(cmd) {
        return Some(result);
    }

    match name {
        "tmux" => match arg(cmd, 0) {
            Some(
                "send-keys" | "send" | "new-session" | "new" | "kill-session" | "kill-server"
                | "kill-pane" | "kill-window" | "split-window" | "rename-session" | "rename-window"
                | "move-window" | "swap-pane" | "swap-window",
            ) => Some(ask("tmux-mutate", "Modifies tmux sessions or panes")),
            _ => None,
        },
        "uv" => match (arg(cmd, 0), arg(cmd, 1)) {
            (Some("tool"), Some("install")) => {
                Some(ask("uv-tool-install", "Installs or replaces a uv tool"))
            }
            (Some("version"), _) if cmd.argv.iter().any(|a| a.text == "--bump") => {
                Some(ask("uv-version-bump", "Modifies project version metadata"))
            }
            (Some("remove"), _) => Some(ask("uv-remove", "Removes a project dependency")),
            _ => None,
        },
        "python" | "python3" => Some(ask("python-exec", "Runs arbitrary Python code or scripts")),
        "node" => Some(ask(
            "node-exec",
            "Runs arbitrary JavaScript code or scripts",
        )),
        "source" | "." => Some(ask(
            "source-shell-file",
            "Loads shell code into the current shell",
        )),
        "wait" | "jobs" => Some(ask(
            "shell-job-control",
            "Uses shell job-control or polling constructs",
        )),
        "just" if !cmd.argv.is_empty() => Some(ask(
            "just-unknown-recipe",
            "Runs a project recipe not in the allowlist",
        )),
        _ if full_name.starts_with("./") || full_name.starts_with("../") => {
            Some(ask("project-script-exec", "Runs a project-local script"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse, Statement};

    fn sc(input: &str) -> SimpleCommand {
        match parse(input).expect("parse command") {
            Statement::SimpleCommand(cmd) => cmd,
            other => panic!("expected simple command, got {other:?}"),
        }
    }

    #[test]
    fn identifies_env_dump_and_transparent_executable_shapes() {
        for input in ["env", "env -i", "env FOO=bar"] {
            assert!(is_env_dump(&sc(input)), "environment dump: {input}");
        }

        for input in [
            "env git status",
            "env FOO=bar git status",
            "env -i FOO=bar git status",
        ] {
            assert!(
                !is_env_dump(&sc(input)) && classify_env(&sc(input)).is_none(),
                "executable env wrapper should inherit inner policy: {input}"
            );
        }

        let relative = classify_env(&sc("./env FOO=bar git status"))
            .expect("relative env executable should ask");
        assert_eq!(relative.decision, Decision::Ask);
        assert_eq!(relative.rule_id.as_deref(), Some("project-script-exec"));
    }
}
