//! Argv-aware classifier for read-only `gh` (GitHub CLI) invocations.
//!
//! Returns `Some(shape_name)` for provably read-only forms; `None` for
//! mutating, unknown, or non-`gh` commands. Pure function; no I/O, no
//! config dependency. Caller is responsible for wrapper unwrapping
//! (env, command, xargs, etc.) before invoking.
//!
//! See `docs/superpowers/specs/2026-05-05-r7-readonly-gh-classifier-design.md`
//! for the full design rationale.

use super::redirects::is_stderr_devnull;
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

/// Top-level gh flags that take a value as the next argv token. When
/// scanning for subcommands and shape tokens, the VALUE of each pair
/// must be skipped — otherwise `gh release --repo view delete v1`
/// gets misread as `release view` (a read-only shape) when gh actually
/// parses it as `release delete` with --repo="view".
const GH_TOP_LEVEL_VALUE_FLAGS: &[&str] = &["-R", "--repo", "--hostname"];

/// Returns argv with known top-level value-flag pairs removed.
/// Single-token forms (`--repo=owner/repo`, `--hostname=X`) are also
/// removed via prefix check. Allocation: one Vec<&str> per call,
/// short-lived; classifier hot path is not a throughput bottleneck.
fn argv_without_top_level_value_flags(argv: &[Arg]) -> Vec<&str> {
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let t = argv[i].text.as_str();
        // Two-token form: `--flag value`
        if GH_TOP_LEVEL_VALUE_FLAGS.contains(&t) {
            i += 2;
            continue;
        }
        // Single-token form: `--flag=value` — skip just the flag token.
        // (Other flags starting with `-` are passed through; the caller's
        // filter handles them.)
        if t.starts_with("--repo=") || t.starts_with("--hostname=") {
            i += 1;
            continue;
        }
        out.push(t);
        i += 1;
    }
    out
}

/// Walk argv, skip top-level value-flag pairs, then return the first
/// non-flag positional. Used to identify the gh subcommand even when
/// preceded by `-R owner/repo` or `--hostname X`.
fn first_subcommand_token(argv: &[Arg]) -> Option<&str> {
    argv_without_top_level_value_flags(argv)
        .into_iter()
        .find(|t| !t.starts_with('-'))
}

/// R7 round-9 (Codex High): R7-NEW classified families (release, search,
/// gist, label, status, secret list, variable list, cache list) had no
/// pre-R7 YAML allowlist coverage — pre-R7 asked uniformly for them.
/// Without this guard, `PATH=/tmp gh release view v1`,
/// `/tmp/gh status`, `LD_PRELOAD=/tmp/evil.so gh secret list`, etc.
/// would classifier-allow despite running an alternate binary or with
/// a poisoned execution environment.
///
/// This is the same strict check `classify_gh_api` applies via Step
/// 0a-bis. It's NOT applied to pre-R7-allowlisted families
/// (pr/issue/repo/run/workflow/auth) because pre-R7 minimal/standard
/// allowlists matched those by basename and ignored assignments —
/// adding the strict check there would be a R7 regression vs pre-R7.
fn require_strict_invocation(cmd: &SimpleCommand) -> Option<()> {
    if cmd.name.as_deref() != Some("gh") {
        return None;
    }
    if !cmd.assignments.is_empty() {
        return None;
    }
    if !cmd.redirects.iter().all(is_stderr_devnull) {
        return None;
    }
    // R7 round-10 (Opus High): `--hostname` redirects auth to a different
    // host. classify_gh_api has its own --hostname rejection in Step 0d;
    // this guard extends the same protection to R7-NEW families. The
    // round-8 top-level value-flag stripper consumes `--hostname X` for
    // subcommand-token detection (so the subcommand is correctly
    // identified) — but consuming it for *detection* is not the same as
    // rejecting it for *classification*. Subcommand detection wants the
    // real subcommand; classification wants to refuse hostnames that
    // redirect auth.
    //
    // -R / --repo are NOT rejected here: they change WHICH repo is
    // queried, not WHERE the auth token goes. Pre-R7 also allowed
    // them on pre-allowlisted families; for R7-NEW families they're
    // benign.
    if argv_has_any_long_flag(&cmd.argv, &["--hostname"]) {
        return None;
    }
    Some(())
}

/// Known two-token value-taking flags for `gh api` (where the flag consumes
/// the next token as its value rather than encoding it via `--flag=value`).
/// Flags that indicate body/mutation (`-f`, `-F`, `--field`, etc.) are handled
/// separately in the body-flag rejection steps, not listed here.
///
/// Sourced from `gh api --help`: `-X/--method`, `-q/--jq`, `-H/--header`,
/// `-t/--template`, `-p/--preview`, `--cache`, plus the top-level
/// `--hostname`. Long forms (`--jq`, `--template`, `--header`, `--method`,
/// `--preview`, `--hostname`) and short forms (`-X`, `-q`, `-H`, `-t`, `-p`)
/// are all listed so that endpoint detection consumes their values regardless
/// of which form the caller used.
const API_VALUE_TAKING_TWO_TOKEN_FLAGS: &[&str] = &[
    // method
    "-X",
    "--method",
    // jq filter
    "-q",
    "--jq",
    // headers
    "-H",
    "--header",
    // go template
    "-t",
    "--template",
    // preview API version
    "-p",
    "--preview",
    // cache duration
    "--cache",
    // top-level hostname (gh -level flag, but appears in argv before subcommand)
    "--hostname",
];

/// Collect all method values specified via `-X <value>`, `--method <value>`,
/// or `--method=<value>` in argv. Returns a `Vec` so that multiple conflicting
/// method flags (e.g. `-X GET --method=POST`) are all captured.
///
/// A dangling `-X` or `--method` with no following token pushes `""` (empty
/// string), which is not equal to "GET" and will cause the caller to reject.
fn collect_api_methods(argv: &[Arg]) -> Vec<&str> {
    let mut methods = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let text = argv[i].text.as_str();
        // `-X value` — two-token form
        if text == "-X" {
            if let Some(next) = argv.get(i + 1) {
                methods.push(next.text.as_str());
                i += 2;
            } else {
                methods.push(""); // dangling -X — non-GET
                i += 1;
            }
            continue;
        }
        // `--method value` — two-token form
        if text == "--method" {
            if let Some(next) = argv.get(i + 1) {
                methods.push(next.text.as_str());
                i += 2;
            } else {
                methods.push(""); // dangling --method — non-GET
                i += 1;
            }
            continue;
        }
        // `--method=value` — single-token form
        if let Some(value) = text.strip_prefix("--method=") {
            methods.push(value);
        }
        i += 1;
    }
    methods
}

/// Returns true if argv contains a non-flag positional endpoint token after
/// the `api` subcommand. Skips values consumed by known value-taking flags
/// so that e.g. `gh api --jq . repos/foo` correctly identifies `repos/foo`
/// as the endpoint and `gh api --jq .` (no endpoint) returns false.
fn has_api_endpoint(argv: &[Arg]) -> bool {
    let mut iter = argv.iter().peekable();
    let mut found_api = false;
    while let Some(arg) = iter.next() {
        let text = arg.text.as_str();
        if !found_api {
            if text == "api" {
                found_api = true;
            }
            continue;
        }
        if text.starts_with('-') {
            // Long-form `--flag=value` is a single token — no value to skip.
            if text.contains('=') {
                continue;
            }
            // Two-token value-flag: consume the next token as the flag's value.
            if API_VALUE_TAKING_TWO_TOKEN_FLAGS.contains(&text) {
                iter.next();
            }
            continue;
        }
        // First non-flag positional after `api` (after consuming value-flag
        // values) is the endpoint.
        return true;
    }
    false
}

/// Returns true if `arg.text` is `flag` exactly OR starts with `flag=`
/// (the single-token `--flag=value` form). Allocation-free.
fn arg_matches_long_flag(arg: &Arg, flag: &str) -> bool {
    arg.text == flag
        || (arg.text.starts_with(flag) && arg.text.as_bytes().get(flag.len()) == Some(&b'='))
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

/// Returns the basename of `name`. `gh` matches if the basename is
/// exactly "gh"; this allows absolute-path invocations like `/usr/bin/gh`.
fn basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// Public entry: classify a parsed simple command. Returns the
/// human-readable shape name if read-only `gh`; `None` otherwise.
///
/// `is_extra`: true if this leaf was extracted from a wrapper
/// (env / command / nice / timeout / find -exec / xargs / shell-c /
/// command substitution / process substitution), false if it's the
/// original top-level statement leaf. The classifier refuses
/// `gh api` classification on extracted leaves — pre-R7 trust:full
/// asked uniformly for all extracted gh api invocations regardless
/// of wrapper shape, and preserving that ask is the only way to
/// close the wrapper-bypass surface without auditing every
/// extraction site individually for assignment / redirect / runtime-
/// arg propagation. Non-api gh subcommands continue classifying on
/// extras (preserves the proposal's `command gh pr view 123` case).
pub fn classify_gh(cmd: &SimpleCommand, is_extra: bool) -> Option<&'static str> {
    let name = cmd.name.as_deref()?;
    if basename(name) != "gh" {
        return None;
    }

    // R7 round-10 (Codex High): --hostname redirects auth to a
    // potentially attacker-controlled host. Reject it uniformly across
    // all classified gh subcommands. classify_gh_api also has its
    // own --hostname rejection (Step 0d) which becomes redundant for
    // the api path but is harmless. For pre-R7-allowlisted families
    // (pr/issue/repo/run/workflow/auth) this IS technically a
    // tightening vs pre-R7 (which allowed via basename allowlist), but
    // we treat it as defense-in-depth — consistent with the round-7
    // --show-token rejection which had the same "pre-R7 also allowed
    // but high-impact secret leak" character.
    if argv_has_any_long_flag(&cmd.argv, &["--hostname"]) {
        return None;
    }

    // Find the subcommand, skipping top-level value-flag pairs
    // (-R/--repo, --hostname). Without this, `gh release --repo view
    // delete v1` would misclassify as `release view` (a read-only
    // shape) when gh actually parses it as `release delete` with
    // --repo="view" — an R7-introduced bypass surfaced in round-8
    // review.
    let subcommand = first_subcommand_token(&cmd.argv)?;

    match subcommand {
        // gh api: top-level only, with its own strict checks.
        "api" if is_extra => None,
        "api" => classify_gh_api(cmd),
        // Pre-R7-allowlisted families: keep basename match + ignore
        // assignments to preserve pre-R7 minimal/standard allowlist behavior.
        "pr" => classify_gh_pr(cmd),
        "issue" => classify_gh_issue(cmd),
        "repo" => classify_gh_repo(cmd),
        "run" => classify_gh_run(cmd),
        "workflow" => classify_gh_workflow(cmd),
        "auth" => classify_gh_auth(cmd),
        // R7-NEW families: no pre-R7 YAML allowlist coverage — pre-R7
        // asked uniformly. Apply strict invocation guard so PATH= /
        // LD_PRELOAD= / /tmp/gh / inline-assignment forms preserve
        // the pre-R7 ask.
        //
        // R7 round-10 (Codex High): also extend the "extras don't
        // classify" rule from gh api (round-6 architectural fix) to
        // R7-NEW families. Pre-R7 asked uniformly for these regardless
        // of wrapper context; preserving that ask requires NOT
        // classifying R7-NEW shapes on extracted (extra/substitution)
        // leaves. Without this, `bash -c 'gh release view v1'` would
        // classifier-allow because shell-c reparse drops outer
        // assignments, defeating the strict invocation guard.
        "release" if is_extra => None,
        "release" => {
            require_strict_invocation(cmd)?;
            classify_gh_release(cmd)
        }
        "search" if is_extra => None,
        "search" => {
            require_strict_invocation(cmd)?;
            classify_gh_search(cmd)
        }
        "gist" if is_extra => None,
        "gist" => {
            require_strict_invocation(cmd)?;
            classify_gh_gist(cmd)
        }
        "label" if is_extra => None,
        "label" => {
            require_strict_invocation(cmd)?;
            classify_gh_label(cmd)
        }
        "status" if is_extra => None,
        "status" => {
            require_strict_invocation(cmd)?;
            Some("status")
        }
        "secret" if is_extra => None,
        "secret" => {
            require_strict_invocation(cmd)?;
            classify_gh_secret(cmd)
        }
        "variable" if is_extra => None,
        "variable" => {
            require_strict_invocation(cmd)?;
            classify_gh_variable(cmd)
        }
        "cache" if is_extra => None,
        "cache" => {
            require_strict_invocation(cmd)?;
            classify_gh_cache(cmd)
        }
        _ => None,
    }
}

fn classify_gh_api(cmd: &SimpleCommand) -> Option<&'static str> {
    // Step 0a: reject any UnsafeString in argv.
    if has_unsafe_argv(&cmd.argv) {
        return None;
    }

    // Step 0a-bis: require bare `gh` (no absolute path) AND empty inline
    // env assignments. R7's proposal explicitly says "do not weaken secret
    // handling." Pre-R7, EVERY `gh api ...` form asked via the gh api
    // trust:full allowlist — including `/usr/bin/gh api`, `/tmp/gh api`,
    // `PATH=/tmp gh api`, `LD_PRELOAD=evil.so gh api`, and
    // `GH_TOKEN=abc gh api`. R7's classifier (with its broader basename
    // match and ignoring assignments) would invert all of those to allow,
    // weakening secret + execution-environment handling.
    //
    // Conservative restriction: gh api classifies only when invoked as
    // bare `gh` with zero inline assignments. This subsumes
    // executable-resolution overrides (PATH=, LD_PRELOAD=, dyld vars,
    // absolute paths to alternate binaries) AND secret-handling overrides
    // (GH_*, GITHUB_*) in one rule. Non-api gh subcommands continue to
    // accept basename-match (pre-R7 minimal/standard allowlist behaviour
    // is preserved for them).
    //
    // (`env GH_TOKEN=... gh api` is independently gated after transparent
    // wrapper extraction: the assignment is propagated to the inner `gh`,
    // which is attributed to `gh-suspicious-wrapper`. The inline-assignment
    // form had no equivalent guard before this step.)
    if cmd.name.as_deref() != Some("gh") {
        return None;
    }
    if !cmd.assignments.is_empty() {
        return None;
    }

    // Step 0a-ter: reject redirects other than bare `2>/dev/null`.
    // Pre-R7 trust:full asked for every redirect form (`gh api repos/foo
    // > ~/.bashrc`, `gh api repos/foo > ~/.ssh/authorized_keys`).  The
    // existing redirect-write-etc rule only catches /etc/* targets; home-
    // dir files like ~/.ssh/authorized_keys are NOT covered.  Rejecting
    // non-stderr-devnull redirects preserves pre-R7 ask uniformity while
    // allowing the common `gh api ... 2>/dev/null` stderr-suppression
    // pattern, which is read-only and carries no file-write risk.
    if !cmd.redirects.iter().all(is_stderr_devnull) {
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
    // (the endpoint). Uses `has_api_endpoint` which skips values consumed by
    // ALL known value-taking flags (not just -X/--method) so that e.g.
    // `gh api --jq .` (no real endpoint) correctly returns None.
    if !has_api_endpoint(&cmd.argv) {
        return None;
    }

    // Step 0d: reject host-override flag `--hostname`. Pre-R7 this asked via
    // the gh api trust:full allowlist; the classifier preserving that ask
    // matches the proposal's "do not weaken secret handling." A misdirected
    // `gh api --hostname example.invalid repos/foo` would send the auth
    // token to a different host. `--hostname` stays in
    // `API_VALUE_TAKING_TWO_TOKEN_FLAGS` so endpoint detection still
    // consumes its value correctly; this check is the explicit reject step.
    if argv_has_any_long_flag(&cmd.argv, &["--hostname"]) {
        return None;
    }

    // Step 0e: reject `--cache` flag. gh's `--cache` persists API responses
    // locally — same class as `gh release download` (deferred to R8).
    // Network-read but local-write; out of R7's "purely network read-only"
    // contract.
    if argv_has_any_long_flag(&cmd.argv, &["--cache"]) {
        return None;
    }

    // Step 1: collect ALL method-flag occurrences. If any is non-GET (or
    // empty/missing-value), reject. This prevents bypasses like
    // `gh api -X GET repos/foo --method=POST` where the first flag passes
    // but the second would override the method at runtime.
    for method in collect_api_methods(&cmd.argv) {
        if !method.eq_ignore_ascii_case("GET") {
            return None;
        }
    }
    // (No method flags present: default GET — proceed.)

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
    // Skip top-level value-flag pairs (-R/--repo, --hostname) before
    // identifying the subcommand and shape. Without this,
    // `gh release --repo view delete v1` would treat "view" (the value
    // of --repo) as the shape, classifier-allowing what gh executes as
    // `release delete`. Round-8 review (Codex High).
    let tokens = argv_without_top_level_value_flags(&cmd.argv);
    // Find the subcommand position in the stripped tokens (skipping
    // leading non-recognized flags so the subcommand can appear after
    // them).
    let sub_idx = tokens.iter().position(|t| !t.starts_with('-'))?;
    if tokens[sub_idx] != subcommand {
        return None;
    }
    // R7 round-11 (Codex High): the token IMMEDIATELY after the
    // subcommand must be the shape — NOT separated by any
    // unrecognized flag. Without this, `gh release --notes view edit
    // v1`, `gh secret --org list set FOO`, `gh label --description
    // list create bug` etc. would classify as `release view` /
    // `secret list` / `label list` while gh actually executes the
    // mutating subcommand (edit/set/create) with the unrecognized
    // flag's value spelling the apparent shape token. We don't have
    // an exhaustive list of subcommand-level value flags; instead
    // require the shape to be the very next token after the
    // subcommand. Real read-only invocations always have this form
    // (`gh pr view ...`, `gh release view ...`, `gh secret list ...`).
    let next = tokens.get(sub_idx + 1)?;
    if next.starts_with('-') {
        return None;
    }
    if *next == second_token {
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
    // R7 round-7 review (Codex High): `gh auth status --show-token` and
    // `gh auth status -t` print the user's GitHub auth token to stdout,
    // where it's then visible to the calling agent. Reject the flag in
    // both forms so this shape falls through to the existing minimal-
    // trust allowlist (which today allows it — defense-in-depth, not a
    // pre-R7 regression).
    if argv_has_any_long_flag(&cmd.argv, &["--show-token"]) {
        return None;
    }
    if cmd.argv.iter().any(|a| a.text == "-t") {
        return None;
    }
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
