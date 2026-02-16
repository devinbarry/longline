//! Transparent wrapper command unwrapping.
//!
//! Some commands (timeout, nice, env, nohup, strace) modify execution context
//! but delegate actual work to an inner command. This module extracts inner
//! commands so the policy evaluator can assess what actually runs.
//!
//! To add a new wrapper: add one entry to the WRAPPERS table.

use super::{SimpleCommand, Statement};

/// Maximum recursion depth for chained wrappers.
/// If exceeded, evaluation falls back to ask via an Opaque node.
const MAX_UNWRAP_DEPTH: usize = 16;

/// How to skip past wrapper-specific arguments to find the inner command.
#[derive(Debug, Clone, Copy)]
enum ArgSkip {
    /// Skip N positional args after flags (e.g., timeout: skip 1 for DURATION)
    Positional(usize),
    /// Skip VAR=val pairs until first non-assignment (e.g., env)
    Assignments,
    /// Skip nothing -- next arg after flags is the command (e.g., nohup)
    None,
}

struct WrapperDef {
    /// Command name (matched after basename extraction)
    name: &'static str,
    /// Flags that consume the following token as a value (e.g., -s SIGNAL)
    value_flags: &'static [&'static str],
    /// Flags that stand alone with no value (e.g., --verbose)
    bool_flags: &'static [&'static str],
    /// How to find the inner command after flags are consumed
    skip: ArgSkip,
}

static WRAPPERS: &[WrapperDef] = &[
    WrapperDef {
        name: "timeout",
        value_flags: &["-s", "--signal", "-k", "--kill-after"],
        bool_flags: &["--preserve-status", "--foreground", "-v", "--verbose"],
        skip: ArgSkip::Positional(1),
    },
    WrapperDef {
        name: "nice",
        value_flags: &["-n", "--adjustment"],
        bool_flags: &[],
        skip: ArgSkip::None,
    },
    WrapperDef {
        name: "env",
        value_flags: &["-u", "--unset"],
        bool_flags: &["-i", "-0", "--null", "--ignore-environment"],
        skip: ArgSkip::Assignments,
    },
    WrapperDef {
        name: "nohup",
        value_flags: &[],
        bool_flags: &[],
        skip: ArgSkip::None,
    },
    WrapperDef {
        name: "strace",
        value_flags: &["-e", "-o", "-p", "-s", "-P", "-I"],
        bool_flags: &[
            "-f", "-ff", "-c", "-C", "-t", "-tt", "-ttt", "-T", "-v", "-V", "-x", "-xx", "-y",
            "-yy",
        ],
        skip: ArgSkip::None,
    },
    WrapperDef {
        name: "time",
        value_flags: &[],
        bool_flags: &["-p"],
        skip: ArgSkip::None,
    },
];

/// Extract basename from a command name for wrapper matching.
/// Handles /usr/bin/timeout, ./env, etc.
fn wrapper_basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// Find the WrapperDef for a command name, if any.
fn find_wrapper(name: &str) -> Option<&'static WrapperDef> {
    let basename = wrapper_basename(name);
    WRAPPERS.iter().find(|w| w.name == basename)
}

/// Check if a token is a valid environment variable assignment (NAME=VALUE).
/// NAME must match [A-Za-z_][A-Za-z0-9_]*.
fn is_env_assignment(token: &str) -> bool {
    let Some(eq_pos) = token.find('=') else {
        return false;
    };
    let name_part = &token[..eq_pos];
    if name_part.is_empty() {
        return false;
    }
    let mut chars = name_part.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// If cmd is a known wrapper, extract the inner command as a new SimpleCommand.
/// Returns None if not a wrapper or no inner command found.
pub fn unwrap_transparent(cmd: &SimpleCommand) -> Option<SimpleCommand> {
    let cmd_name = cmd.name.as_deref()?;
    let wrapper = find_wrapper(cmd_name)?;

    let argv = &cmd.argv;
    let mut i = 0;

    // Phase 1: Consume flags
    while i < argv.len() {
        let token = &argv[i];

        // -- ends flag processing
        if token == "--" {
            i += 1;
            break;
        }

        // Check value_flag exact match (e.g., "-s" followed by value)
        if wrapper.value_flags.iter().any(|f| *f == token) {
            i += 2; // skip flag + value
            continue;
        }

        // Check value_flag=value form (e.g., "--signal=TERM")
        if wrapper
            .value_flags
            .iter()
            .any(|f| token.starts_with(f) && token.as_bytes().get(f.len()) == Some(&b'='))
        {
            i += 1;
            continue;
        }

        // Check value_flag combined form (e.g., "-n10" for short flag "-n")
        if wrapper.value_flags.iter().any(|f| {
            f.starts_with('-')
                && !f.starts_with("--")
                && token.starts_with(f)
                && token.len() > f.len()
        }) {
            i += 1;
            continue;
        }

        // Check bool_flag exact match
        if wrapper.bool_flags.iter().any(|f| *f == token) {
            i += 1;
            continue;
        }

        // Not a flag -- stop flag processing
        break;
    }

    // Phase 2: Apply skip rule
    match wrapper.skip {
        ArgSkip::Positional(n) => {
            i += n;
        }
        ArgSkip::Assignments => {
            while i < argv.len() && is_env_assignment(&argv[i]) {
                i += 1;
            }
        }
        ArgSkip::None => {}
    }

    // Phase 3: Construct inner command
    if i >= argv.len() {
        return None;
    }

    let inner_name = argv[i].clone();
    let inner_argv: Vec<String> = argv[i + 1..].to_vec();

    Some(SimpleCommand {
        name: Some(inner_name),
        argv: inner_argv,
        redirects: cmd.redirects.clone(),
        assignments: vec![],
        embedded_substitutions: cmd.embedded_substitutions.clone(),
    })
}

/// Walk a statement tree, find all wrapper SimpleCommands, unwrap them
/// recursively (max depth 16, then ask), return all synthesized inner commands.
pub fn extract_inner_commands(stmt: &Statement) -> Vec<Statement> {
    let mut results = Vec::new();
    collect_inner_commands(stmt, &mut results);
    results
}

fn collect_inner_commands(stmt: &Statement, out: &mut Vec<Statement>) {
    match stmt {
        Statement::SimpleCommand(cmd) => {
            unwrap_recursive(cmd, out, 0);
            for sub in &cmd.embedded_substitutions {
                collect_inner_commands(sub, out);
            }
        }
        Statement::Pipeline(p) => {
            for stage in &p.stages {
                collect_inner_commands(stage, out);
            }
        }
        Statement::List(l) => {
            collect_inner_commands(&l.first, out);
            for (_, s) in &l.rest {
                collect_inner_commands(s, out);
            }
        }
        Statement::Subshell(inner) | Statement::CommandSubstitution(inner) => {
            collect_inner_commands(inner, out);
        }
        Statement::Opaque(_) | Statement::Empty => {}
    }
}

fn unwrap_recursive(cmd: &SimpleCommand, out: &mut Vec<Statement>, depth: usize) {
    if let Some(inner) = unwrap_transparent(cmd) {
        if depth >= MAX_UNWRAP_DEPTH {
            out.push(Statement::Opaque(
                "wrapper depth limit exceeded".to_string(),
            ));
            return;
        }
        out.push(Statement::SimpleCommand(inner.clone()));
        unwrap_recursive(&inner, out, depth + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(name: &str, argv: &[&str]) -> SimpleCommand {
        SimpleCommand {
            name: Some(name.to_string()),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        }
    }

    // ── Helper tests ────────────────────────────────────────────

    #[test]
    fn test_wrapper_basename_plain() {
        assert_eq!(wrapper_basename("timeout"), "timeout");
    }

    #[test]
    fn test_wrapper_basename_absolute() {
        assert_eq!(wrapper_basename("/usr/bin/timeout"), "timeout");
    }

    #[test]
    fn test_wrapper_basename_relative() {
        assert_eq!(wrapper_basename("./env"), "env");
    }

    #[test]
    fn test_wrapper_basename_nested() {
        assert_eq!(wrapper_basename("/usr/local/bin/nice"), "nice");
    }

    #[test]
    fn test_find_wrapper_known() {
        assert!(find_wrapper("timeout").is_some());
        assert!(find_wrapper("nice").is_some());
        assert!(find_wrapper("env").is_some());
        assert!(find_wrapper("nohup").is_some());
        assert!(find_wrapper("strace").is_some());
    }

    #[test]
    fn test_find_wrapper_unknown() {
        assert!(find_wrapper("ls").is_none());
        assert!(find_wrapper("rm").is_none());
        assert!(find_wrapper("cargo").is_none());
    }

    #[test]
    fn test_find_wrapper_with_path() {
        assert!(find_wrapper("/usr/bin/env").is_some());
        assert!(find_wrapper("./timeout").is_some());
    }

    // ── is_env_assignment tests ─────────────────────────────────

    #[test]
    fn test_env_assignment_valid() {
        assert!(is_env_assignment("FOO=bar"));
        assert!(is_env_assignment("_FOO=bar"));
        assert!(is_env_assignment("FOO123=bar"));
        assert!(is_env_assignment("PATH=/usr/bin:/usr/local/bin"));
        assert!(is_env_assignment("FOO=bar=baz"));
        assert!(is_env_assignment("FOO="));
        assert!(is_env_assignment("A=1"));
    }

    #[test]
    fn test_env_assignment_invalid() {
        assert!(!is_env_assignment("1FOO=bar"));
        assert!(!is_env_assignment("=bar"));
        assert!(!is_env_assignment("FOO"));
        assert!(!is_env_assignment("--foo=bar"));
        assert!(!is_env_assignment("-f=bar"));
        assert!(!is_env_assignment(""));
        assert!(!is_env_assignment("FOO-BAR=baz"));
    }

    // ── timeout unwrap tests ────────────────────────────────────

    #[test]
    fn test_timeout_basic() {
        let cmd = make_cmd("timeout", &["30", "ls", "-la"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
        assert_eq!(inner.argv, vec!["-la"]);
    }

    #[test]
    fn test_timeout_with_signal_flag() {
        let cmd = make_cmd("timeout", &["-s", "KILL", "30", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
        assert!(inner.argv.is_empty());
    }

    #[test]
    fn test_timeout_with_signal_eq() {
        let cmd = make_cmd("timeout", &["--signal=TERM", "10", "echo", "hi"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("echo"));
        assert_eq!(inner.argv, vec!["hi"]);
    }

    #[test]
    fn test_timeout_with_kill_after() {
        let cmd = make_cmd("timeout", &["-k", "5", "30", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_timeout_with_kill_after_eq() {
        let cmd = make_cmd("timeout", &["--kill-after=5", "30", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_timeout_with_bool_flags() {
        let cmd = make_cmd(
            "timeout",
            &["--preserve-status", "--foreground", "--verbose", "30", "ls"],
        );
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_timeout_all_flags() {
        let cmd = make_cmd(
            "timeout",
            &[
                "-s",
                "KILL",
                "-k",
                "5",
                "--verbose",
                "--preserve-status",
                "--foreground",
                "30",
                "ls",
            ],
        );
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_timeout_no_inner_command() {
        let cmd = make_cmd("timeout", &["30"]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    #[test]
    fn test_timeout_empty_argv() {
        let cmd = make_cmd("timeout", &[]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    #[test]
    fn test_timeout_preserves_inner_argv() {
        let cmd = make_cmd("timeout", &["30", "rm", "-rf", "/"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("rm"));
        assert_eq!(inner.argv, vec!["-rf", "/"]);
    }

    #[test]
    fn test_timeout_double_dash() {
        let cmd = make_cmd("timeout", &["--", "30", "ls"]);
        // -- stops flags, "30" is DURATION positional, "ls" is inner
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    // ── nice unwrap tests ───────────────────────────────────────

    #[test]
    fn test_nice_basic() {
        let cmd = make_cmd("nice", &["ls", "-la"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
        assert_eq!(inner.argv, vec!["-la"]);
    }

    #[test]
    fn test_nice_with_n_flag() {
        let cmd = make_cmd("nice", &["-n", "10", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_nice_with_n_combined() {
        let cmd = make_cmd("nice", &["-n10", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_nice_with_adjustment_eq() {
        let cmd = make_cmd("nice", &["--adjustment=5", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_nice_negative_priority() {
        let cmd = make_cmd("nice", &["-n", "-5", "echo", "hello"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("echo"));
        assert_eq!(inner.argv, vec!["hello"]);
    }

    #[test]
    fn test_nice_bare() {
        let cmd = make_cmd("nice", &[]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    // ── env unwrap tests ────────────────────────────────────────

    #[test]
    fn test_env_with_assignment() {
        let cmd = make_cmd("env", &["FOO=bar", "echo", "hello"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("echo"));
        assert_eq!(inner.argv, vec!["hello"]);
    }

    #[test]
    fn test_env_multi_assignments() {
        let cmd = make_cmd("env", &["FOO=1", "BAR=2", "BAZ=three", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
        assert!(inner.argv.is_empty());
    }

    #[test]
    fn test_env_with_i_flag() {
        let cmd = make_cmd("env", &["-i", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_env_with_u_flag() {
        let cmd = make_cmd("env", &["-u", "HOME", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_env_with_unset_eq() {
        let cmd = make_cmd("env", &["--unset=HOME", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_env_multiple_u_flags() {
        let cmd = make_cmd("env", &["-u", "HOME", "-u", "USER", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_env_flags_then_assignments() {
        let cmd = make_cmd(
            "env",
            &["-i", "-u", "HOME", "PATH=/usr/bin", "FOO=bar", "ls"],
        );
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_env_val_with_equals() {
        let cmd = make_cmd("env", &["FOO=bar=baz", "echo", "hello"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("echo"));
    }

    #[test]
    fn test_env_empty_val() {
        let cmd = make_cmd("env", &["FOO=", "echo", "hello"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("echo"));
    }

    #[test]
    fn test_env_invalid_var_name_digit() {
        // 1FOO=bar doesn't match assignment pattern, becomes inner command
        let cmd = make_cmd("env", &["1FOO=bar"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("1FOO=bar"));
    }

    #[test]
    fn test_env_only_assignments_no_inner() {
        let cmd = make_cmd("env", &["FOO=bar"]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    #[test]
    fn test_env_only_assignments_multi_no_inner() {
        let cmd = make_cmd("env", &["FOO=bar", "BAZ=1"]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    #[test]
    fn test_env_bare() {
        let cmd = make_cmd("env", &[]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    #[test]
    fn test_env_only_flags_no_inner() {
        let cmd = make_cmd("env", &["-i"]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    #[test]
    fn test_env_absolute_path() {
        let cmd = make_cmd("/usr/bin/env", &["FOO=bar", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_env_relative_path() {
        let cmd = make_cmd("./env", &["FOO=bar", "ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    // ── nohup unwrap tests ──────────────────────────────────────

    #[test]
    fn test_nohup_basic() {
        let cmd = make_cmd("nohup", &["echo", "hello"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("echo"));
        assert_eq!(inner.argv, vec!["hello"]);
    }

    #[test]
    fn test_nohup_bare() {
        let cmd = make_cmd("nohup", &[]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    // ── strace unwrap tests ─────────────────────────────────────

    #[test]
    fn test_strace_basic() {
        let cmd = make_cmd("strace", &["ls"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_strace_with_f() {
        let cmd = make_cmd("strace", &["-f", "ls", "-la"]);
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
        assert_eq!(inner.argv, vec!["-la"]);
    }

    #[test]
    fn test_strace_with_value_flags() {
        let cmd = make_cmd(
            "strace",
            &["-e", "trace=open", "-o", "/tmp/trace.log", "ls"],
        );
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
    }

    #[test]
    fn test_strace_p_pid_no_inner() {
        let cmd = make_cmd("strace", &["-p", "1234"]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    #[test]
    fn test_strace_bare() {
        let cmd = make_cmd("strace", &[]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    // ── Non-wrapper passthrough ─────────────────────────────────

    #[test]
    fn test_non_wrapper_returns_none() {
        let cmd = make_cmd("ls", &["-la"]);
        assert!(unwrap_transparent(&cmd).is_none());
    }

    #[test]
    fn test_no_name_returns_none() {
        let cmd = SimpleCommand {
            name: None,
            argv: vec!["foo".to_string()],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        };
        assert!(unwrap_transparent(&cmd).is_none());
    }

    // ── Redirect propagation ────────────────────────────────────

    #[test]
    fn test_redirects_propagated() {
        use crate::parser::{Redirect, RedirectOp};
        let cmd = SimpleCommand {
            name: Some("timeout".to_string()),
            argv: vec!["30".to_string(), "ls".to_string()],
            redirects: vec![Redirect {
                fd: None,
                op: RedirectOp::Write,
                target: "/tmp/out".to_string(),
            }],
            assignments: vec![],
            embedded_substitutions: vec![],
        };
        let inner = unwrap_transparent(&cmd).unwrap();
        assert_eq!(inner.name.as_deref(), Some("ls"));
        assert_eq!(inner.redirects.len(), 1);
        assert_eq!(inner.redirects[0].target, "/tmp/out");
    }

    // ── extract_inner_commands tests ────────────────────────────

    #[test]
    fn test_extract_from_simple_wrapper() {
        let stmt = Statement::SimpleCommand(make_cmd("timeout", &["30", "ls"]));
        let inners = extract_inner_commands(&stmt);
        assert_eq!(inners.len(), 1);
        if let Statement::SimpleCommand(ref cmd) = inners[0] {
            assert_eq!(cmd.name.as_deref(), Some("ls"));
        } else {
            panic!("Expected SimpleCommand");
        }
    }

    #[test]
    fn test_extract_from_non_wrapper() {
        let stmt = Statement::SimpleCommand(make_cmd("ls", &["-la"]));
        let inners = extract_inner_commands(&stmt);
        assert!(inners.is_empty());
    }

    #[test]
    fn test_extract_chained_two_deep() {
        // env VAR=1 timeout 30 ls
        let stmt = Statement::SimpleCommand(make_cmd("env", &["VAR=1", "timeout", "30", "ls"]));
        let inners = extract_inner_commands(&stmt);
        // Should have: "timeout 30 ls" and "ls"
        assert_eq!(inners.len(), 2);
        if let Statement::SimpleCommand(ref cmd) = inners[0] {
            assert_eq!(cmd.name.as_deref(), Some("timeout"));
        } else {
            panic!("Expected SimpleCommand at [0]");
        }
        if let Statement::SimpleCommand(ref cmd) = inners[1] {
            assert_eq!(cmd.name.as_deref(), Some("ls"));
        } else {
            panic!("Expected SimpleCommand at [1]");
        }
    }

    #[test]
    fn test_extract_chained_three_deep() {
        // env VAR=1 timeout 30 nice -n 5 ls
        let stmt = Statement::SimpleCommand(make_cmd(
            "env",
            &["VAR=1", "timeout", "30", "nice", "-n", "5", "ls"],
        ));
        let inners = extract_inner_commands(&stmt);
        // Should have: "timeout 30 nice -n 5 ls", "nice -n 5 ls", "ls"
        assert_eq!(inners.len(), 3);
        if let Statement::SimpleCommand(ref cmd) = inners[2] {
            assert_eq!(cmd.name.as_deref(), Some("ls"));
        } else {
            panic!("Expected SimpleCommand at [2]");
        }
    }

    #[test]
    fn test_extract_from_pipeline() {
        use crate::parser::Pipeline;
        let stmt = Statement::Pipeline(Pipeline {
            stages: vec![
                Statement::SimpleCommand(make_cmd("timeout", &["30", "cat", "file.txt"])),
                Statement::SimpleCommand(make_cmd("grep", &["pattern"])),
            ],
            negated: false,
        });
        let inners = extract_inner_commands(&stmt);
        // Only the timeout stage has an inner command
        assert_eq!(inners.len(), 1);
        if let Statement::SimpleCommand(ref cmd) = inners[0] {
            assert_eq!(cmd.name.as_deref(), Some("cat"));
        } else {
            panic!("Expected SimpleCommand");
        }
    }

    #[test]
    fn test_extract_from_list() {
        use crate::parser::{List, ListOp};
        let stmt = Statement::List(List {
            first: Box::new(Statement::SimpleCommand(make_cmd("timeout", &["30", "ls"]))),
            rest: vec![(
                ListOp::And,
                Statement::SimpleCommand(make_cmd("nice", &["echo", "done"])),
            )],
        });
        let inners = extract_inner_commands(&stmt);
        assert_eq!(inners.len(), 2); // ls from timeout, echo from nice
    }

    #[test]
    fn test_extract_depth_limit() {
        // Build 18 layers: nice nohup nice nohup ... rm -rf /
        let mut argv: Vec<&str> = Vec::new();
        for i in 0..18 {
            if i % 2 == 0 {
                argv.push("nice");
            } else {
                argv.push("nohup");
            }
        }
        argv.extend_from_slice(&["rm", "-rf", "/"]);

        let stmt = Statement::SimpleCommand(make_cmd("nice", &argv[1..]));
        let inners = extract_inner_commands(&stmt);

        // Should hit depth limit -- last entry should be Opaque
        let last = inners.last().unwrap();
        assert!(
            matches!(last, Statement::Opaque(_)),
            "Depth limit should produce Opaque, got: {:?}",
            last
        );
    }

    #[test]
    fn test_extract_within_depth_limit() {
        // 3 layers: nice nice nice ls
        let stmt = Statement::SimpleCommand(make_cmd("nice", &["nice", "nice", "ls"]));
        let inners = extract_inner_commands(&stmt);
        // Should get: "nice nice ls", "nice ls", "ls"
        assert_eq!(inners.len(), 3);
        // Last should be SimpleCommand(ls), not Opaque
        if let Statement::SimpleCommand(ref cmd) = inners[2] {
            assert_eq!(cmd.name.as_deref(), Some("ls"));
        } else {
            panic!("Expected SimpleCommand(ls)");
        }
    }
}
