use crate::domain::{Decision, PolicyResult};
use crate::parser::SimpleCommand;

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

fn classified_gh_wrapper(cmd: &SimpleCommand, is_extra: bool) -> Option<PolicyResult> {
    let name = basename(cmd.name.as_deref()?);

    if name == "gh" {
        let subcommand = gh_subcommand(cmd)?;
        if (is_extra || has_any_assignment(cmd)) && sensitive_gh_family(subcommand) {
            return Some(gh_suspicious_wrapper());
        }
    }

    if matches!(name, "exec" | "stdbuf" | "unbuffer") {
        let texts: Vec<&str> = cmd.argv.iter().map(|a| a.text.as_str()).collect();
        if let Some(pos) = texts.iter().position(|text| basename(text) == "gh") {
            if texts
                .get(pos + 1)
                .is_some_and(|subcommand| sensitive_gh_family(subcommand))
            {
                return Some(gh_suspicious_wrapper());
            }
        }
    }

    None
}

pub(super) fn classify(cmd: &SimpleCommand, is_extra: bool) -> Option<PolicyResult> {
    let full_name = cmd.name.as_deref()?;
    let name = basename(full_name);

    if let Some(result) = classified_gh_wrapper(cmd, is_extra) {
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
