//! Argv-aware classifier for read-only `gh` (GitHub CLI) invocations.
//!
//! Returns `Some(shape_name)` for provably read-only forms; `None` for
//! mutating, unknown, or non-`gh` commands. Pure function; no I/O, no
//! config dependency. Caller is responsible for wrapper unwrapping
//! (env, command, xargs, etc.) before invoking.
//!
//! See `docs/superpowers/specs/2026-05-05-r7-readonly-gh-classifier-design.md`
//! for the full design rationale.

use crate::parser::{Arg, ArgMeta, SimpleCommand};

/// Body/field flag tokens (long forms). Any token equal to one of these
/// or starting with `<flag>=` triggers `gh api` rejection.
const API_BODY_LONG_FLAGS: &[&str] = &["--field", "--form", "--raw-field", "--input"];

/// Returns true if any argv token has UnsafeString classification.
/// Used to reject `gh api` invocations whose runtime argv may differ
/// from parsed argv (command substitution, variable expansion, etc.).
fn has_unsafe_argv(argv: &[Arg]) -> bool {
    argv.iter().any(|a| matches!(a.meta, ArgMeta::UnsafeString))
}

/// Skip over flag tokens (anything starting with `-`) and return the
/// first non-flag positional. Used to find the endpoint after `gh api`.
/// Note: this is a simple scan — it does NOT pair value-flags with
/// their values; for `gh api` purposes, the first non-flag after the
/// subcommand is the endpoint regardless of intervening flags.
fn first_non_flag(argv: &[Arg]) -> Option<&Arg> {
    argv.iter().find(|a| !a.text.starts_with('-'))
}

/// Returns true if `arg.text` is `flag` exactly OR starts with `flag=`
/// (the single-token `--flag=value` form). Allocation-free.
fn arg_matches_long_flag(arg: &Arg, flag: &str) -> bool {
    arg.text == flag
        || (arg.text.starts_with(flag) && arg.text.as_bytes().get(flag.len()) == Some(&b'='))
}

/// Look up the value of a `<flag> <value>` or `<flag>=<value>` pair
/// in argv. Returns the value if `flag` is present in either form.
/// Allocation-free (manual prefix check, no `format!`).
fn argv_value_for<'a>(argv: &'a [Arg], flag: &str) -> Option<&'a str> {
    for (i, arg) in argv.iter().enumerate() {
        // `--flag=value` form (single token)
        if arg.text.starts_with(flag) && arg.text.as_bytes().get(flag.len()) == Some(&b'=') {
            return Some(&arg.text[flag.len() + 1..]);
        }
        // `--flag value` form (two tokens)
        if arg.text == flag {
            return argv.get(i + 1).map(|a| a.text.as_str());
        }
    }
    None
}

/// Returns true if any of `flags` (with or without `=value` suffix)
/// is present as a complete argv token. Allocation-free.
fn argv_has_any_long_flag(argv: &[Arg], flags: &[&str]) -> bool {
    argv.iter()
        .any(|a| flags.iter().any(|flag| arg_matches_long_flag(a, flag)))
}

/// Returns true if argv contains any short body/field flag form for
/// `gh api`: `-f`, `-F`, or any glued-value form like `-ffoo=bar` or
/// `-Ffoo=bar`. Specifically checks for tokens whose first two
/// characters are `-f` or `-F`. Long-form `--field` etc. are checked
/// separately via `argv_has_any_long_flag`.
fn argv_has_short_body_field_flag(argv: &[Arg]) -> bool {
    argv.iter().any(|a| {
        let bytes = a.text.as_bytes();
        bytes.len() >= 2 && bytes[0] == b'-' && (bytes[1] == b'f' || bytes[1] == b'F')
    })
}

/// Look up the method specified by `-X` / `--method`. Returns:
/// - `Some(method)` if a method flag is present (value extracted)
/// - `None` if no method flag is present (default GET applies)
fn extract_api_method(argv: &[Arg]) -> Option<&str> {
    argv_value_for(argv, "-X").or_else(|| argv_value_for(argv, "--method"))
}

/// Returns the basename of `name`. `gh` matches if the basename is
/// exactly "gh"; this allows absolute-path invocations like `/usr/bin/gh`.
fn basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// Public entry: classify a parsed simple command. Returns the
/// human-readable shape name if read-only `gh`; `None` otherwise.
pub fn classify_gh(cmd: &SimpleCommand) -> Option<&'static str> {
    let name = cmd.name.as_deref()?;
    if basename(name) != "gh" {
        return None;
    }

    // First non-flag argv token is the subcommand (we do NOT skip
    // top-level flags like `-R owner/repo` — see "Known limitations"
    // in the spec; gh -R owner/repo pr view falls through to None and
    // asks via the existing fallthrough).
    let subcommand = first_non_flag(&cmd.argv)?.text.as_str();

    match subcommand {
        "api" => classify_gh_api(cmd),
        "pr" => classify_gh_pr(cmd),
        "issue" => classify_gh_issue(cmd),
        "repo" => classify_gh_repo(cmd),
        "run" => classify_gh_run(cmd),
        "workflow" => classify_gh_workflow(cmd),
        "release" => classify_gh_release(cmd),
        "search" => classify_gh_search(cmd),
        "auth" => classify_gh_auth(cmd),
        "gist" => classify_gh_gist(cmd),
        "label" => classify_gh_label(cmd),
        "status" => Some("status"),
        "secret" => classify_gh_secret(cmd),
        "variable" => classify_gh_variable(cmd),
        "cache" => classify_gh_cache(cmd),
        _ => None,
    }
}

fn classify_gh_api(cmd: &SimpleCommand) -> Option<&'static str> {
    // Step 0a: reject any UnsafeString in argv.
    if has_unsafe_argv(&cmd.argv) {
        return None;
    }

    // Step 0b: reject glued-short method flag forms like `-XGET` or `-XPOST`.
    // These can't be reliably parsed; conservatively reject them. Real callers
    // use `-X GET` (two tokens) or `--method GET`.
    for arg in &cmd.argv {
        let t = arg.text.as_str();
        // A token starting with `-X` but not exactly `-X` is a glued form.
        if t.starts_with("-X") && t != "-X" {
            return None;
        }
    }

    // Step 0c: require at least one non-flag positional AFTER `api`
    // (the endpoint). The first non-flag is `api` itself; we need a
    // second one. We must skip values consumed by value-paired flags
    // (-X <method>, --method <method>) to avoid treating "GET" as the
    // endpoint in `gh api -X GET` (no endpoint).
    let mut found_api = false;
    let mut has_endpoint = false;
    let mut skip_next = false;
    for arg in &cmd.argv {
        if skip_next {
            skip_next = false;
            continue;
        }
        // Mark next token as a flag value if this is a value-taking flag.
        if arg.text == "-X" || arg.text == "--method" {
            skip_next = true;
            continue;
        }
        if !arg.text.starts_with('-') {
            if !found_api {
                found_api = arg.text == "api";
            } else {
                has_endpoint = true;
                break;
            }
        }
    }
    if !has_endpoint {
        return None;
    }

    // Step 1: scan for explicit method flag.
    if let Some(method) = extract_api_method(&cmd.argv) {
        if !method.eq_ignore_ascii_case("GET") {
            return None;
        }
    }
    // (Absent method: default GET — proceed.)

    // Step 2: reject any body/field flag.
    if argv_has_any_long_flag(&cmd.argv, API_BODY_LONG_FLAGS) {
        return None;
    }
    if argv_has_short_body_field_flag(&cmd.argv) {
        return None;
    }

    // Step 3: classify as read-only GET.
    Some("api (GET)")
}

/// Helper for simple-shape per-subcommand classifiers: dispatches on
/// the second non-flag token after `gh <subcommand>`.
fn classify_simple_shape(
    cmd: &SimpleCommand,
    subcommand: &str,
    second_token: &str,
    shape: &'static str,
) -> Option<&'static str> {
    let mut iter = cmd.argv.iter().filter(|a| !a.text.starts_with('-'));
    if iter.next()?.text != subcommand {
        return None;
    }
    if iter.next()?.text == second_token {
        return Some(shape);
    }
    None
}

fn classify_gh_pr(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "pr", "view", "pr view")
        .or_else(|| classify_simple_shape(cmd, "pr", "list", "pr list"))
        .or_else(|| classify_simple_shape(cmd, "pr", "diff", "pr diff"))
        .or_else(|| classify_simple_shape(cmd, "pr", "checks", "pr checks"))
        .or_else(|| classify_simple_shape(cmd, "pr", "status", "pr status"))
}

fn classify_gh_issue(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "issue", "view", "issue view")
        .or_else(|| classify_simple_shape(cmd, "issue", "list", "issue list"))
        .or_else(|| classify_simple_shape(cmd, "issue", "status", "issue status"))
}

fn classify_gh_repo(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "repo", "view", "repo view")
        .or_else(|| classify_simple_shape(cmd, "repo", "list", "repo list"))
}

fn classify_gh_run(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "run", "view", "run view")
        .or_else(|| classify_simple_shape(cmd, "run", "list", "run list"))
        .or_else(|| classify_simple_shape(cmd, "run", "watch", "run watch"))
}

fn classify_gh_workflow(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "workflow", "view", "workflow view")
        .or_else(|| classify_simple_shape(cmd, "workflow", "list", "workflow list"))
}

fn classify_gh_release(cmd: &SimpleCommand) -> Option<&'static str> {
    // Note: `release download` is deliberately NOT classified — its
    // local filesystem write is deferred to R8.
    classify_simple_shape(cmd, "release", "view", "release view")
        .or_else(|| classify_simple_shape(cmd, "release", "list", "release list"))
}

fn classify_gh_search(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "search", "repos", "search repos")
        .or_else(|| classify_simple_shape(cmd, "search", "issues", "search issues"))
        .or_else(|| classify_simple_shape(cmd, "search", "prs", "search prs"))
        .or_else(|| classify_simple_shape(cmd, "search", "code", "search code"))
        .or_else(|| classify_simple_shape(cmd, "search", "commits", "search commits"))
}

fn classify_gh_auth(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "auth", "status", "auth status")
}

fn classify_gh_gist(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "gist", "view", "gist view")
        .or_else(|| classify_simple_shape(cmd, "gist", "list", "gist list"))
}

fn classify_gh_label(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "label", "list", "label list")
}

fn classify_gh_secret(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "secret", "list", "secret list")
}

fn classify_gh_variable(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "variable", "list", "variable list")
}

fn classify_gh_cache(cmd: &SimpleCommand) -> Option<&'static str> {
    classify_simple_shape(cmd, "cache", "list", "cache list")
}
