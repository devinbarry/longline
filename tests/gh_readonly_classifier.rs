//! Unit tests for the read-only `gh` classifier.
//!
//! Tests `classify_gh` directly via the existing parser. No filesystem,
//! no longline binary, no JSON. Each assertion independently identifies
//! its input on failure.

use longline::parser::{parse, SimpleCommand, Statement};

/// Find the first SimpleCommand reachable from a parsed statement
/// (recursing into Pipeline / List / Subshell / CommandSubstitution).
/// Returns None if the statement is Empty or Opaque.
fn first_simple_command(stmt: &Statement) -> Option<&SimpleCommand> {
    match stmt {
        Statement::SimpleCommand(c) => Some(c),
        Statement::Pipeline(p) => p.stages.first().and_then(first_simple_command),
        Statement::List(l) => first_simple_command(&l.first),
        Statement::Subshell(inner) => first_simple_command(inner),
        Statement::CommandSubstitution(inner) => first_simple_command(inner),
        Statement::Opaque(_) | Statement::Empty => None,
    }
}

fn classify(input: &str) -> Option<&'static str> {
    let stmt = parse(input).expect("parse");
    let leaf = first_simple_command(&stmt)?;
    // Direct classifier unit tests treat the input as a top-level leaf
    // (is_extra=false). The "extras don't classify gh api" rule is
    // verified end-to-end via the golden test runner.
    longline::policy::gh_classifier::classify_gh(leaf, false)
}

// ============================================================
// gh api: read-only GET variants must classify as Some("api (GET)")
// ============================================================

#[test]
fn api_default_method_with_endpoint_classifies() {
    assert_eq!(
        classify("gh api repos/openai/codex/contents/path"),
        Some("api (GET)"),
        "default method (no -X) is GET"
    );
    assert_eq!(
        classify("gh api repos/openai/codex/contents/path --jq .content"),
        Some("api (GET)"),
        "v0.16 dogfood pain point exact form"
    );
}

#[test]
fn api_explicit_get_method_classifies() {
    assert_eq!(classify("gh api -X GET repos/foo/bar"), Some("api (GET)"));
    assert_eq!(
        classify("gh api --method GET repos/foo/bar"),
        Some("api (GET)")
    );
    assert_eq!(
        classify("gh api --method=GET repos/foo/bar"),
        Some("api (GET)")
    );
}

#[test]
fn api_get_method_is_case_insensitive() {
    assert_eq!(classify("gh api -X get repos/foo/bar"), Some("api (GET)"));
    assert_eq!(
        classify("gh api --method get repos/foo/bar"),
        Some("api (GET)")
    );
    assert_eq!(
        classify("gh api --method=Get repos/foo/bar"),
        Some("api (GET)")
    );
}

// ============================================================
// gh api: mutating / unsafe forms must return None
// ============================================================

#[test]
fn api_non_get_methods_return_none() {
    assert_eq!(classify("gh api -X POST repos/foo/issues"), None);
    assert_eq!(classify("gh api -X PUT repos/foo/something"), None);
    assert_eq!(classify("gh api -X DELETE repos/foo/things/1"), None);
    assert_eq!(classify("gh api -X PATCH repos/foo/issues/1"), None);
    assert_eq!(classify("gh api --method POST repos/foo/issues"), None);
    assert_eq!(classify("gh api --method=DELETE repos/foo/things"), None);
}

#[test]
fn api_body_field_flags_return_none() {
    assert_eq!(classify("gh api repos/foo/issues -f title=x"), None);
    assert_eq!(classify("gh api repos/foo/issues --field title=x"), None);
    assert_eq!(classify("gh api repos/foo/issues --field=title=x"), None);
    assert_eq!(classify("gh api graphql -F query=@q.gql"), None);
    assert_eq!(classify("gh api graphql --form query=foo"), None);
    assert_eq!(classify("gh api graphql --raw-field query=foo"), None);
    assert_eq!(classify("gh api repos/foo --input body.json"), None);
}

#[test]
fn api_glued_short_body_flags_return_none() {
    // `gh` accepts -ffoo=bar and -Ffoo=bar as glued-value short flags.
    // The classifier rejects any token starting with -f or -F.
    assert_eq!(classify("gh api repos/foo/issues -ffoo=bar"), None);
    assert_eq!(classify("gh api repos/foo/issues -Ffoo=bar"), None);
}

#[test]
fn api_glued_short_method_flag_rejected_conservatively() {
    // -XGET (glued, no space) is not parsed; classifier returns None.
    // Real callers use `-X GET` or `--method GET`.
    assert_eq!(classify("gh api -XGET repos/foo"), None);
    assert_eq!(classify("gh api -XPOST repos/foo"), None);
}

#[test]
fn api_no_endpoint_returns_none() {
    // Step 0: must have at least one non-flag positional after `api`.
    assert_eq!(classify("gh api"), None, "bare gh api");
    assert_eq!(
        classify("gh api -X GET"),
        None,
        "gh api -X GET with no endpoint"
    );
    assert_eq!(
        classify("gh api --method GET"),
        None,
        "gh api --method GET with no endpoint"
    );
}

#[test]
fn api_unsafe_argv_returns_none() {
    // Step 0: any UnsafeString meta in argv (command substitution,
    // variable expansion, escape-interpreted strings) returns None.
    // Parsed argv text is not the runtime argv.
    assert_eq!(classify("gh api $(echo repos/foo)"), None);
    assert_eq!(classify("gh api repos/$VAR"), None);
    assert_eq!(classify("gh api \"repos/${ORG}/${REPO}\""), None);
    assert_eq!(
        classify("gh api `cat endpoint.txt`"),
        None,
        "backtick command substitution"
    );
}

#[test]
fn api_short_value_flags_consume_value_for_endpoint_detection() {
    // -q is short for --jq; -t for --template; -p for --preview.
    // Without consuming their values, the value tokens (e.g. ".") would
    // be misidentified as the endpoint and the classifier would allow
    // a malformed command. With proper value-flag handling: no endpoint
    // present after value consumption → return None.
    assert_eq!(classify("gh api -q ."), None, "gh api -q . has no endpoint");
    assert_eq!(
        classify("gh api -t '{{.}}'"),
        None,
        "gh api -t TEMPLATE has no endpoint"
    );
    assert_eq!(
        classify("gh api -p baz"),
        None,
        "gh api -p PREVIEW has no endpoint"
    );
    assert_eq!(
        classify("gh api --preview foo"),
        None,
        "gh api --preview FOO has no endpoint"
    );
    assert_eq!(
        classify("gh api --hostname ghe.example.com"),
        None,
        "gh api --hostname HOST has no endpoint"
    );
}

#[test]
fn api_inline_gh_env_assignments_return_none() {
    // R7 round-3 review (Codex High): inline assignments like
    // `GH_TOKEN=abc gh api repos/foo` would have been allowed without
    // this check, weakening secret handling. The proposal explicitly
    // says "do not weaken secret handling" — pre-R7, gh api trust:full
    // asked these.
    //
    // R7 round-4 review (Codex High): widened the check to reject ANY
    // inline assignment for gh api (not just GH_*/GITHUB_*) — covers
    // PATH= execution-environment overrides, LD_PRELOAD= and dyld vars,
    // plus arbitrary inline assignments that pre-R7 trust:full asked.
    assert_eq!(classify("GH_TOKEN=abc gh api repos/foo"), None);
    assert_eq!(
        classify("GH_ENTERPRISE_TOKEN=abc gh api repos/foo"),
        None,
        "enterprise token override"
    );
    assert_eq!(
        classify("GH_HOST=example.invalid gh api repos/foo"),
        None,
        "host override env var"
    );
    assert_eq!(
        classify("GH_ENTERPRISE_TOKEN=abc GH_HOST=example.invalid gh api repos/foo"),
        None,
        "combined token + host override"
    );
    assert_eq!(
        classify("GITHUB_TOKEN=abc gh api repos/foo"),
        None,
        "GITHUB_-prefixed env var"
    );
}

#[test]
fn api_inline_path_and_dyld_overrides_return_none() {
    // R7 round-4 review (Codex High): execution-environment overrides
    // could let `PATH=/tmp gh api` or `LD_PRELOAD=evil.so gh api` run
    // arbitrary code with the user's gh credentials. Pre-R7 these
    // asked via trust:full; the broader assignment-rejection check
    // preserves that ask.
    assert_eq!(
        classify("PATH=/tmp gh api repos/foo"),
        None,
        "PATH override could redirect gh lookup"
    );
    assert_eq!(
        classify("LD_PRELOAD=/tmp/evil.so gh api repos/foo"),
        None,
        "LD_PRELOAD shim hijacks gh's address space"
    );
    assert_eq!(
        classify("DYLD_INSERT_LIBRARIES=/tmp/evil.dylib gh api repos/foo"),
        None,
        "macOS dyld insert hijacks gh's address space"
    );
    // Even arbitrary harmless-looking vars are rejected — pre-R7
    // trust:full asked for ALL inline assignments uniformly.
    assert_eq!(classify("FOO=bar gh api repos/foo"), None);
}

#[test]
fn api_redirect_returns_none() {
    // R7 round-5 review (Opus High): `gh api repos/foo > ~/.bashrc`
    // would have allowed without this check — the classifier ignored
    // cmd.redirects. The existing redirect-write-etc rule only catches
    // /etc/* targets; sensitive home-dir files (~/.ssh/authorized_keys,
    // ~/.bashrc, ~/.zshrc) were not. Pre-R7 trust:full asked uniformly.
    assert_eq!(
        classify("gh api repos/foo > ~/.ssh/authorized_keys"),
        None,
        "redirect to authorized_keys could inject SSH keys"
    );
    assert_eq!(
        classify("gh api repos/foo > ~/.bashrc"),
        None,
        "redirect to bashrc could inject shell hooks"
    );
    assert_eq!(
        classify("gh api repos/foo >> ~/.zshrc"),
        None,
        "append-redirect to zshrc"
    );
    assert_eq!(
        classify("gh api repos/foo > /tmp/anything"),
        None,
        "any redirect — pre-R7 asked uniformly"
    );
    assert_eq!(
        classify("gh api repos/foo 2> /tmp/err"),
        None,
        "stderr redirect"
    );
}

#[test]
fn api_absolute_path_to_gh_returns_none() {
    // R7 round-4 review (Codex High): a malicious binary at /tmp/gh
    // would otherwise classify as read-only via the basename check.
    // Pre-R7 the allowlist also matched by basename and required
    // trust:full → ask. R7 narrows the classifier to exact-name `gh`
    // for gh api specifically; absolute-path forms fall through to
    // the existing allowlist-asks behaviour. Non-api gh subcommands
    // (pr/issue/etc.) keep the basename match.
    assert_eq!(classify("/tmp/gh api repos/foo"), None);
    assert_eq!(classify("/usr/local/bin/gh api repos/foo"), None);
    assert_eq!(classify("./gh api repos/foo"), None);
}

#[test]
fn api_hostname_flag_returns_none() {
    // R7 round-3 review (Codex High): --hostname redirects auth to a
    // different host. Pre-R7 trust:full asked; preserve that ask.
    assert_eq!(
        classify("gh api --hostname example.invalid repos/foo"),
        None
    );
    assert_eq!(
        classify("gh api --hostname=example.invalid repos/foo"),
        None,
        "single-token --hostname=value"
    );
}

#[test]
fn api_cache_flag_returns_none() {
    // R7 round-3 review (Codex Medium): --cache persists responses
    // locally; same class as gh release download (deferred to R8).
    assert_eq!(classify("gh api --cache 1h repos/foo"), None);
    assert_eq!(
        classify("gh api --cache=1h repos/foo"),
        None,
        "single-token --cache=value"
    );
}

#[test]
fn api_short_value_flags_with_endpoint_classify() {
    // Same flags, but with a real endpoint present after the value.
    // The classifier must consume the value tokens and then identify
    // the trailing positional as the endpoint.
    assert_eq!(
        classify("gh api -q . repos/foo"),
        Some("api (GET)"),
        "endpoint follows -q value"
    );
    assert_eq!(
        classify("gh api -t '{{.}}' repos/foo"),
        Some("api (GET)"),
        "endpoint follows -t value"
    );
    assert_eq!(
        classify("gh api -H 'Accept: text/html' repos/foo"),
        Some("api (GET)"),
        "endpoint follows -H value"
    );
}

// ============================================================
// gh pr: read-only shapes
// ============================================================

#[test]
fn pr_read_only_subcommands_classify() {
    assert_eq!(classify("gh pr view 123"), Some("pr view"));
    assert_eq!(classify("gh pr view 123 --json files"), Some("pr view"));
    assert_eq!(classify("gh pr view 123 --web"), Some("pr view"));
    assert_eq!(classify("gh pr list"), Some("pr list"));
    assert_eq!(classify("gh pr list --limit 10"), Some("pr list"));
    assert_eq!(classify("gh pr diff 123"), Some("pr diff"));
    assert_eq!(classify("gh pr checks 123"), Some("pr checks"));
    assert_eq!(classify("gh pr status"), Some("pr status"));
}

#[test]
fn pr_mutating_subcommands_return_none() {
    assert_eq!(classify("gh pr create --title x --body y"), None);
    assert_eq!(classify("gh pr merge 123"), None);
    assert_eq!(classify("gh pr edit 123"), None);
    assert_eq!(classify("gh pr close 123"), None);
    assert_eq!(classify("gh pr reopen 123"), None);
    assert_eq!(classify("gh pr comment 123 --body hi"), None);
    assert_eq!(classify("gh pr review 123 --approve"), None);
    assert_eq!(classify("gh pr ready 123"), None);
    assert_eq!(classify("gh pr checkout 123"), None, "writes worktree");
}

// ============================================================
// gh issue: read-only shapes
// ============================================================

#[test]
fn issue_read_only_subcommands_classify() {
    assert_eq!(classify("gh issue view 42"), Some("issue view"));
    assert_eq!(classify("gh issue list --state open"), Some("issue list"));
    assert_eq!(classify("gh issue status"), Some("issue status"));
}

#[test]
fn issue_mutating_subcommands_return_none() {
    assert_eq!(classify("gh issue create --title x"), None);
    assert_eq!(classify("gh issue close 1"), None);
    assert_eq!(classify("gh issue reopen 1"), None);
    assert_eq!(classify("gh issue comment 1 --body hi"), None);
    assert_eq!(classify("gh issue edit 1"), None);
    assert_eq!(classify("gh issue delete 1"), None);
}

// ============================================================
// gh repo / run / workflow / release: read-only + mutating
// ============================================================

#[test]
fn repo_read_only_classifies() {
    assert_eq!(classify("gh repo view owner/repo"), Some("repo view"));
    assert_eq!(classify("gh repo view owner/repo --web"), Some("repo view"));
    assert_eq!(classify("gh repo list owner"), Some("repo list"));
}

#[test]
fn repo_mutating_returns_none() {
    assert_eq!(classify("gh repo create new-repo"), None);
    assert_eq!(
        classify("gh repo clone owner/repo"),
        None,
        "writes filesystem"
    );
    assert_eq!(classify("gh repo fork"), None);
    assert_eq!(classify("gh repo edit owner/repo"), None);
    assert_eq!(classify("gh repo delete owner/repo"), None);
}

#[test]
fn run_read_only_classifies() {
    assert_eq!(classify("gh run view 123"), Some("run view"));
    assert_eq!(classify("gh run list"), Some("run list"));
    assert_eq!(classify("gh run watch 123"), Some("run watch"));
}

#[test]
fn run_mutating_returns_none() {
    assert_eq!(classify("gh run rerun 123"), None);
    assert_eq!(classify("gh run cancel 123"), None);
    assert_eq!(classify("gh run delete 123"), None);
}

#[test]
fn workflow_read_only_classifies() {
    assert_eq!(
        classify("gh workflow view release.yml"),
        Some("workflow view")
    );
    assert_eq!(classify("gh workflow list"), Some("workflow list"));
}

#[test]
fn workflow_mutating_returns_none() {
    assert_eq!(classify("gh workflow run release.yml"), None);
    assert_eq!(classify("gh workflow enable release.yml"), None);
    assert_eq!(classify("gh workflow disable release.yml"), None);
}

#[test]
fn release_read_only_classifies() {
    assert_eq!(classify("gh release view v1.0"), Some("release view"));
    assert_eq!(classify("gh release list"), Some("release list"));
}

#[test]
fn release_mutating_or_deferred_returns_none() {
    assert_eq!(classify("gh release create v1.0"), None);
    assert_eq!(classify("gh release upload v1.0 file.tgz"), None);
    assert_eq!(classify("gh release edit v1.0"), None);
    assert_eq!(classify("gh release delete v1.0"), None);
    // Download writes locally — deferred to R8 filesystem policy
    assert_eq!(classify("gh release download v1.0"), None, "R8 deferral");
}

// ============================================================
// gh search: all variants are read-only
// ============================================================

#[test]
fn search_variants_classify() {
    assert_eq!(classify("gh search repos lang:rust"), Some("search repos"));
    assert_eq!(classify("gh search code longline"), Some("search code"));
    assert_eq!(
        classify("gh search issues author:@me"),
        Some("search issues")
    );
    assert_eq!(classify("gh search prs author:@me"), Some("search prs"));
    assert_eq!(
        classify("gh search commits longline"),
        Some("search commits")
    );
}

// ============================================================
// gh auth / gist / label / status / secret / variable / cache
// ============================================================

#[test]
fn auth_status_classifies() {
    assert_eq!(classify("gh auth status"), Some("auth status"));
}

#[test]
fn auth_mutating_returns_none() {
    assert_eq!(classify("gh auth login"), None);
    assert_eq!(classify("gh auth refresh"), None);
    assert_eq!(classify("gh auth token"), None);
    assert_eq!(classify("gh auth setup-git"), None);
}

#[test]
fn gist_read_only_classifies() {
    assert_eq!(classify("gh gist view abc"), Some("gist view"));
    assert_eq!(classify("gh gist list"), Some("gist list"));
}

#[test]
fn gist_mutating_returns_none() {
    assert_eq!(classify("gh gist create file.md"), None);
    assert_eq!(classify("gh gist edit abc"), None);
    assert_eq!(classify("gh gist delete abc"), None);
    assert_eq!(classify("gh gist clone abc"), None);
}

#[test]
fn label_list_classifies() {
    assert_eq!(classify("gh label list"), Some("label list"));
}

#[test]
fn label_mutating_returns_none() {
    assert_eq!(classify("gh label create blocker"), None);
    assert_eq!(classify("gh label edit blocker --color red"), None);
    assert_eq!(classify("gh label delete blocker"), None);
}

#[test]
fn status_top_level_classifies() {
    assert_eq!(classify("gh status"), Some("status"));
}

#[test]
fn secret_list_classifies() {
    // `gh secret list` returns names only, not values — read-only.
    assert_eq!(classify("gh secret list"), Some("secret list"));
}

#[test]
fn secret_mutating_returns_none() {
    assert_eq!(classify("gh secret set FOO --body bar"), None);
    assert_eq!(classify("gh secret delete FOO"), None);
}

#[test]
fn variable_list_classifies() {
    assert_eq!(classify("gh variable list"), Some("variable list"));
}

#[test]
fn variable_mutating_returns_none() {
    assert_eq!(classify("gh variable set FOO --body bar"), None);
    assert_eq!(classify("gh variable delete FOO"), None);
}

#[test]
fn cache_list_classifies() {
    assert_eq!(classify("gh cache list"), Some("cache list"));
}

#[test]
fn cache_mutating_returns_none() {
    assert_eq!(classify("gh cache delete 12345"), None);
}

// ============================================================
// Negative cases: non-gh, bare gh, unknown subcommand
// ============================================================

#[test]
fn non_gh_executable_returns_none() {
    assert_eq!(classify("git status"), None);
    assert_eq!(classify("git pr view"), None);
    assert_eq!(classify("ghi status"), None, "basename mismatch");
    assert_eq!(classify("ls"), None);
}

#[test]
fn bare_gh_returns_none() {
    assert_eq!(classify("gh"), None);
}

#[test]
fn unknown_subcommand_returns_none() {
    assert_eq!(classify("gh foo bar"), None);
    assert_eq!(classify("gh attestation verify file.tgz"), None);
    assert_eq!(classify("gh extension list"), None);
    assert_eq!(classify("gh codespace list"), None);
}

#[test]
fn version_check_returns_none_classifier_does_not_handle_it() {
    // --version short-circuits via is_version_check upstream;
    // classifier returns None for it.
    assert_eq!(classify("gh --version"), None);
    assert_eq!(classify("gh -V"), None);
}

// ============================================================
// Bug 2 — method-flag bypass: conflicting method flags must reject (R7 fix)
// ============================================================

#[test]
fn api_conflicting_method_flags_x_then_method_equals_returns_none() {
    // `-X GET` first, then `--method=POST` — the second flag wins at runtime
    // but only the first was previously checked. Must return None.
    assert_eq!(
        classify("gh api -X GET repos/foo --method=POST"),
        None,
        "conflicting method flags: -X GET then --method=POST"
    );
}

#[test]
fn api_conflicting_method_flags_method_then_method_equals_returns_none() {
    // `--method GET` then `--method=POST` — conflicting flags, must reject.
    assert_eq!(
        classify("gh api --method GET repos/foo --method=POST"),
        None,
        "conflicting method flags: --method GET then --method=POST"
    );
}

#[test]
fn api_post_method_still_returns_none() {
    // Baseline regression: single non-GET method flag still rejects.
    assert_eq!(
        classify("gh api -X POST repos/foo"),
        None,
        "single POST method flag"
    );
}

#[test]
fn api_dangling_x_flag_returns_none() {
    // `-X` with no following value (dangling) is treated as non-GET and rejected.
    assert_eq!(
        classify("gh api -X"),
        None,
        "dangling -X with no method value"
    );
}

// ============================================================
// Bug 3 — value-flag values mistaken for endpoint (R7 fix)
// ============================================================

#[test]
fn api_jq_only_no_endpoint_returns_none() {
    // `gh api --jq .` — `.` is the jq filter value, not an endpoint.
    assert_eq!(
        classify("gh api --jq ."),
        None,
        "gh api --jq . has no endpoint; jq value must not be treated as endpoint"
    );
}

#[test]
fn api_header_only_no_endpoint_returns_none() {
    // `gh api -H foo` — `foo` is the header value, not an endpoint.
    assert_eq!(
        classify("gh api -H foo"),
        None,
        "gh api -H foo has no endpoint; header value must not be treated as endpoint"
    );
}

#[test]
fn api_template_only_no_endpoint_returns_none() {
    // `gh api --template t` — `t` is the template value, not an endpoint.
    assert_eq!(
        classify("gh api --template t"),
        None,
        "gh api --template t has no endpoint; template value must not be treated as endpoint"
    );
}

#[test]
fn api_jq_with_endpoint_classifies() {
    // `gh api --jq . repos/foo` — the endpoint follows the jq filter.
    assert_eq!(
        classify("gh api --jq . repos/foo"),
        Some("api (GET)"),
        "gh api --jq . repos/foo has a real endpoint after the jq value"
    );
}

#[test]
fn api_header_with_endpoint_classifies() {
    // `gh api -H "Accept: foo" repos/bar` — endpoint follows the header value.
    assert_eq!(
        classify("gh api -H \"Accept: foo\" repos/bar"),
        Some("api (GET)"),
        "gh api -H <header> repos/bar has a real endpoint after the header value"
    );
}
