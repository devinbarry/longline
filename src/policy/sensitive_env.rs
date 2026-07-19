//! Argv/assignment-aware classifier for sensitive cross-leaf env assignments.
//!
//! Returns `Some(PolicyResult { decision: Ask, rule_id: "sensitive-env-assignment", .. })`
//! when a leaf assigns — or `read`s into — a command-resolution / code-injection
//! environment variable; `None` otherwise. Pure function; no I/O.
//!
//! Inverse polarity of `set_forms`: it returns `Ask`, which dominates via
//! most-restrictive-wins and skips the `all_covered` gate, so no coverage-predicate
//! wiring is needed. "Fail-closed" here means *ask*, which lets the recognizers be
//! deliberately coarse (e.g. the `read` token scan) and still be safe.
//! See `docs/plans/2026-05-31-r11-sensitive-env-assignment-guard-design.md`.

use crate::domain::{Decision, PolicyResult};
use crate::parser::{Arg, Assignment, SimpleCommand};

use super::value_safety::{is_safe_program_value, SafeProgramClass};

/// The only environment-variable program channels for which exact static
/// `true` is a reviewed safe value. Keep this case-sensitive: lowercase names
/// are different Unix variables and do not qualify for the exception.
const SAFE_EDITOR_OVERRIDE_NAMES: &[&str] =
    &["GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "EDITOR", "VISUAL"];

/// Exact-match sensitive variable names (compared case-sensitively). Includes
/// the full `git-env-rce-vars` `env.any_of` plain names — the drift-guard test
/// asserts this stays a superset of that rule.
const SENSITIVE_EXACT: &[&str] = &[
    // Command / startup resolution
    "PATH",
    "CDPATH",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    // Interpreter / toolchain knobs
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYOPT",
    "RUBYLIB",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    // Pager / browser program substitution
    "PAGER",
    "MANPAGER",
    "GIT_WEB_BROWSER",
    // git-env-rce-vars plain names
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "EDITOR",
    "VISUAL",
    "GIT_PAGER",
    "GIT_PROXY_COMMAND",
    "GIT_EXTERNAL_DIFF",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG",
    "GIT_SSL_NO_VERIFY",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_ALLOW_PROTOCOL",
    "GIT_TRACE2",
    "GIT_TRACE2_EVENT",
    "GIT_TRACE2_PERF",
    "GIT_TRACE2_CONFIG_PARAMS",
    "GIT_TRACE2_ENV_VARS",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "GIT_SSL_VERSION",
];

/// Glob-pattern sensitive variable names (matched case-sensitively with
/// `glob_match`, the same matcher the YAML rules use). The trailing `_*`
/// carries the underscore boundary so `LDFLAGS` does not match `LD_*` and
/// `GIT_CONFIG_KEYBOARD` does not match `GIT_CONFIG_KEY_*`.
const SENSITIVE_GLOB: &[&str] = &["LD_*", "DYLD_*", "GIT_CONFIG_KEY_*", "GIT_CONFIG_VALUE_*"];

/// Strip a trailing `[...]` array subscript from a variable name so
/// `PATH[0]` / `read PATH[$i]` normalize to `PATH`. (For the *assignment*
/// subscript form the parser already destroyed the name to `""`; this strip is
/// defensive and harmless there — see the design's parser-gap note.)
fn strip_subscript(name: &str) -> &str {
    match name.find('[') {
        Some(i) => &name[..i],
        None => name,
    }
}

/// True if `name` (after subscript strip) is a sensitive variable. Matching is
/// CASE-SENSITIVE: Unix env var names are case-sensitive, and lowercase/mixed
/// forms (`path`, `ld_preload`) are distinct benign variables that cannot hijack
/// a later command — matching them would be a pure false positive.
fn is_sensitive_var(name: &str) -> bool {
    let name = strip_subscript(name);
    if name.is_empty() {
        return false;
    }
    SENSITIVE_EXACT.contains(&name)
        || SENSITIVE_GLOB
            .iter()
            .any(|p| glob_match::glob_match(p, name))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SensitiveAssignment<'a> {
    SafeKnownOverride,
    Sensitive(&'a str),
    NotSensitive,
}

fn classify_assignment(assignment: &Assignment) -> SensitiveAssignment<'_> {
    let name = strip_subscript(&assignment.name);
    if SAFE_EDITOR_OVERRIDE_NAMES.contains(&name)
        && is_safe_program_value(
            SafeProgramClass::ShellNoop,
            &assignment.value,
            assignment.value_meta,
        )
    {
        SensitiveAssignment::SafeKnownOverride
    } else if is_sensitive_var(name) {
        SensitiveAssignment::Sensitive(name)
    } else {
        SensitiveAssignment::NotSensitive
    }
}

/// Extract the target variable of a `printf -v NAME ...` invocation. `printf`
/// parses options only BEFORE the format string, and `--` ends option parsing,
/// so we scan only leading option tokens: stop at `--` or at the first token
/// that is not an option (the format string). Handles separate (`-v NAME`) and
/// combined (`-vNAME`) forms. Returns `None` if there is no `-v` option.
/// Precise on purpose — printf format strings/args routinely contain "PATH".
fn printf_v_target(argv: &[Arg]) -> Option<&str> {
    for (i, a) in argv.iter().enumerate() {
        let t = a.text.as_str();
        if t == "--" {
            return None; // option terminator, no -v among options
        }
        if t == "-v" {
            return argv.get(i + 1).map(|a| a.text.as_str());
        }
        if let Some(rest) = t.strip_prefix("-v") {
            if !rest.is_empty() && !t.starts_with("--") {
                return Some(rest); // combined -vNAME
            }
        }
        if !t.starts_with('-') {
            return None; // first non-option token = format string; options ended
        }
        // else: some other leading option (printf has none beyond -v/--help/--version) — skip
    }
    None
}

/// Build the standard Ask result naming the offending variable.
fn ask_for(var: &str) -> PolicyResult {
    PolicyResult {
        decision: Decision::Ask,
        rule_id: Some("sensitive-env-assignment".to_string()),
        reason: format!(
            "sets a sensitive environment variable ({var}) that can hijack a later command's resolution or execution"
        ),
    }
}

/// Classify a leaf. See module docs.
pub fn classify_sensitive_env(cmd: &SimpleCommand) -> Option<PolicyResult> {
    // Assignment vector — any leaf, commandless or inline.
    for a in &cmd.assignments {
        match classify_assignment(a) {
            SensitiveAssignment::SafeKnownOverride | SensitiveAssignment::NotSensitive => {}
            SensitiveAssignment::Sensitive(name) => return Some(ask_for(name)),
        }
    }
    // `read` vector — coarse: any argv token that names a sensitive var.
    if cmd.name.as_deref() == Some("read") {
        for arg in &cmd.argv {
            if is_sensitive_var(&arg.text) {
                return Some(ask_for(strip_subscript(&arg.text)));
            }
        }
    }
    // `printf -v NAME ...` assigns shell variable NAME (the `-v` operand only).
    if cmd.name.as_deref() == Some("printf") {
        if let Some(var) = printf_v_target(&cmd.argv) {
            if is_sensitive_var(var) {
                return Some(ask_for(strip_subscript(var)));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse, Statement};

    /// Parse a single command string into its `SimpleCommand` for testing.
    fn sc(input: &str) -> SimpleCommand {
        match parse(input).expect("parse failed") {
            Statement::SimpleCommand(c) => c,
            other => panic!("expected SimpleCommand, got {other:?}"),
        }
    }

    fn asks(input: &str) -> bool {
        matches!(
            classify_sensitive_env(&sc(input)),
            Some(PolicyResult { decision: Decision::Ask, ref rule_id, .. })
                if rule_id.as_deref() == Some("sensitive-env-assignment")
        )
    }

    #[test]
    fn sensitive_predicate_exact_and_glob() {
        assert!(is_sensitive_var("PATH"));
        assert!(is_sensitive_var("BASH_ENV"));
        assert!(is_sensitive_var("ZDOTDIR"));
        assert!(is_sensitive_var("NODE_PATH"));
        assert!(is_sensitive_var("RUSTC_WRAPPER"));
        assert!(is_sensitive_var("MANPAGER"));
        assert!(is_sensitive_var("GIT_WEB_BROWSER"));
        assert!(is_sensitive_var("EDITOR"));
        assert!(is_sensitive_var("VISUAL"));
        assert!(is_sensitive_var("GIT_SSH_COMMAND"));
        // Glob families
        assert!(is_sensitive_var("LD_PRELOAD"));
        assert!(is_sensitive_var("LD_LIBRARY_PATH"));
        assert!(is_sensitive_var("DYLD_INSERT_LIBRARIES"));
        assert!(is_sensitive_var("GIT_CONFIG_KEY_0"));
        assert!(is_sensitive_var("GIT_CONFIG_VALUE_3"));
        // Subscript stripped
        assert!(is_sensitive_var("PATH[0]"));
        assert!(is_sensitive_var("PATH[$i]"));
    }

    #[test]
    fn names_are_case_sensitive() {
        // Unix env var names are case-sensitive; lowercase/mixed-case are
        // distinct, benign variables that do NOT hijack a later command.
        assert!(!is_sensitive_var("path"));
        assert!(!is_sensitive_var("Path"));
        assert!(!is_sensitive_var("ld_preload"));
        assert!(!is_sensitive_var("Ld_Preload"));
        assert!(!is_sensitive_var("git_ssh_command"));
        assert!(!is_sensitive_var("git_config_key_0"));
        // Exact / glob uppercase forms still match.
        assert!(is_sensitive_var("PATH"));
        assert!(is_sensitive_var("LD_PRELOAD"));
        assert!(is_sensitive_var("GIT_CONFIG_KEY_0"));
    }

    #[test]
    fn benign_predicate_negatives() {
        assert!(!is_sensitive_var("FOO"));
        assert!(!is_sensitive_var("NODE_ENV")); // NODE_OPTIONS/NODE_PATH are, NODE_ENV is not
        assert!(!is_sensitive_var("GIT_AUTHOR_NAME"));
        assert!(!is_sensitive_var("SSH_AUTH_SOCK"));
        assert!(!is_sensitive_var("LDFLAGS")); // LD_* boundary: needs the underscore
        assert!(!is_sensitive_var("ENVIRONMENT")); // ENV is exact, not a prefix
        assert!(!is_sensitive_var("MY_ENV"));
        assert!(!is_sensitive_var("GIT_CONFIG_KEYBOARD")); // GIT_CONFIG_KEY_* needs the trailing _
        assert!(!is_sensitive_var("BROWSER"));
        assert!(!is_sensitive_var("IFS"));
        assert!(!is_sensitive_var("HOME"));
        assert!(!is_sensitive_var("")); // empty (subscript-assignment name) → false
    }

    #[test]
    fn assignment_vector_asks() {
        assert!(asks("PATH=.:$PATH")); // commandless
        assert!(asks("LD_PRELOAD=/evil.so ls")); // inline on allowlisted
        assert!(asks("export PATH=.:$PATH")); // declaration builtin
        assert!(asks("PATH+=(/evil) ls")); // append form, name captured as PATH
        assert!(asks("EDITOR=vim"));
        assert!(asks("VISUAL=code some-tool"));
        assert!(asks("EDITOR=\"$EDITOR\""));
    }

    #[test]
    fn exact_static_editor_noops_are_transparent() {
        for input in [
            "GIT_EDITOR=true",
            "GIT_SEQUENCE_EDITOR=true",
            "EDITOR=true",
            "VISUAL=true",
            "EDITOR='true' echo hi",
            "VISUAL=\"true\" echo hi",
        ] {
            assert!(
                classify_sensitive_env(&sc(input)).is_none(),
                "static no-op should be transparent: {input}"
            );
        }
    }

    #[test]
    fn editor_noop_requires_exact_value_and_static_provenance() {
        for input in [
            "EDITOR=TRUE",
            "EDITOR=/bin/true",
            "EDITOR='true --help'",
            "EDITOR=",
            "EDITOR=\"$EDITOR\"",
            "EDITOR=\"$(printf true)\"",
            "EDITOR='tr''ue'",
        ] {
            assert!(asks(input), "unsafe editor value should ask: {input}");
        }
    }

    #[test]
    fn printf_v_vector_asks() {
        assert!(asks("printf -v PATH /tmp")); // separate -v operand
        assert!(asks("printf -vPATH /tmp")); // combined -vNAME form
        assert!(asks("printf -v LD_PRELOAD /e.so"));
        assert!(asks("printf -v EDITOR vim"));
        assert!(asks("printf -vVISUAL code"));
    }

    #[test]
    fn printf_without_sensitive_v_target_returns_none() {
        // PATH only in the format string / args, no -v target → not an assignment.
        assert!(classify_sensitive_env(&sc("printf 'PATH=%s' /tmp")).is_none());
        assert!(classify_sensitive_env(&sc("printf -v FOO bar")).is_none()); // benign target
        assert!(classify_sensitive_env(&sc("printf hello")).is_none());
        assert!(classify_sensitive_env(&sc("printf -v path x")).is_none()); // lowercase benign
    }

    #[test]
    fn printf_v_respects_option_terminator_and_format_boundary() {
        // `--` terminates printf options; `-v` after the format string is a
        // positional arg — neither assigns the variable, so neither should ask.
        assert!(classify_sensitive_env(&sc("printf -- -v PATH")).is_none());
        assert!(classify_sensitive_env(&sc("printf '%s' -vPATH")).is_none());
        assert!(classify_sensitive_env(&sc("printf foo -v PATH")).is_none());
        // The real assignment forms must still be caught.
        assert!(asks("printf -v PATH /tmp"));
        assert!(asks("printf -vPATH /tmp"));
    }

    #[test]
    fn read_vector_asks() {
        assert!(asks("read PATH"));
        assert!(asks("read -r PATH foo"));
        assert!(asks("read PATH[0]")); // subscript on the read token
        assert!(asks("read EDITOR"));
        assert!(asks("read VISUAL"));
    }

    #[test]
    fn benign_commands_return_none() {
        assert!(classify_sensitive_env(&sc("FOO=bar")).is_none());
        assert!(classify_sensitive_env(&sc("NODE_ENV=production npm test")).is_none());
        assert!(classify_sensitive_env(&sc("ls -la")).is_none());
        assert!(classify_sensitive_env(&sc("read answer")).is_none());
        assert!(classify_sensitive_env(&sc("git status")).is_none());
        // Subscript-ASSIGNMENT is out of scope: parser yields name "" so we
        // cannot see PATH — must NOT pretend to catch it (deferred to parser fix).
        assert!(classify_sensitive_env(&sc("PATH[0]=evil")).is_none());
    }

    /// The R11 set must remain a superset of `git-env-rce-vars`'s `env.any_of`.
    /// Asserts against a CONCRETE instance of each pattern (trailing `*` →
    /// representative token), so storing `GIT_CONFIG_KEY_*` as a literal
    /// exact-name (which would miss the runtime `GIT_CONFIG_KEY_0`) fails here.
    #[test]
    fn covers_all_git_env_rce_vars() {
        use crate::policy::{load_embedded_rules, Matcher};
        let cfg = load_embedded_rules().expect("load embedded rules");
        let rule = cfg
            .rules
            .iter()
            .find(|r| r.id == "git-env-rce-vars")
            .expect("git-env-rce-vars rule present");
        let Matcher::Command { env: Some(env), .. } = &rule.matcher else {
            panic!("git-env-rce-vars should be a Command matcher with an env block");
        };
        assert!(
            !env.any_of.is_empty(),
            "git-env-rce-vars env.any_of is empty"
        );
        for pat in &env.any_of {
            // Concrete instance: GIT_CONFIG_KEY_* -> GIT_CONFIG_KEY_0; plain names unchanged.
            let concrete = pat.replace('*', "0");
            assert!(
                is_sensitive_var(&concrete),
                "R11 sensitive set must cover git-env-rce-vars entry '{pat}' (concrete '{concrete}')",
            );
        }
    }

    #[test]
    fn editor_exception_and_r11_classifier_cannot_drift() {
        use crate::config::rules::EnvValueClass;
        use crate::policy::{load_embedded_rules, Matcher};
        use std::collections::BTreeSet;

        let expected_names =
            BTreeSet::from(["EDITOR", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "VISUAL"]);
        let rust_safe_names = SAFE_EDITOR_OVERRIDE_NAMES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(rust_safe_names, expected_names);
        let cfg = load_embedded_rules().expect("load embedded rules");
        let rule = cfg
            .rules
            .iter()
            .find(|r| r.id == "git-env-rce-vars")
            .expect("git-env-rce-vars rule present");
        let Matcher::Command { env: Some(env), .. } = &rule.matcher else {
            panic!("git-env-rce-vars should be a Command matcher with an env block");
        };

        assert_eq!(env.except.len(), 1, "exactly one reviewed exception");
        let exception = &env.except[0];
        assert!(
            !exception.name_case_insensitive,
            "editor exception names must be case-sensitive"
        );
        assert_eq!(exception.value_class, EnvValueClass::ShellNoop);
        let yaml_names = exception
            .names
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(yaml_names, expected_names);

        let r11_names = SENSITIVE_EXACT
            .iter()
            .copied()
            .filter(|name| expected_names.contains(name))
            .collect::<BTreeSet<_>>();
        assert_eq!(r11_names, expected_names);
    }
}
