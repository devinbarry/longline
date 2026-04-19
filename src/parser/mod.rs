mod convert;
mod helpers;
pub(crate) mod shell_c;
pub mod wrappers;

use std::fmt;

use convert::convert_program;
use tree_sitter::Parser as TsParser;

/// Top-level parsed representation of a bash command string.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    SimpleCommand(SimpleCommand),
    Pipeline(Pipeline),
    List(List),
    Subshell(Box<Statement>),
    CommandSubstitution(Box<Statement>),
    Opaque(String),
    /// Empty statement (e.g., comments) - evaluates to allow
    Empty,
}

/// A single command argument, carrying both its text and a classification of
/// the original AST node that produced it.
///
/// Classification exists so that a future consumer (the shell-c wrapper
/// unwrapper described in Spec B) can decide whether the text is safe to
/// re-parse as a shell command — a decision that depends on whether bash
/// would execute the text verbatim (raw single-quoted strings, escape-free
/// double-quoted strings) or transform it at runtime (expansions,
/// substitutions, escaped strings, concatenations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg {
    pub text: String,
    pub meta: ArgMeta,
}

/// Classification of an argv element based on its AST origin.
///
/// See `classify_arg_node` in `helpers.rs` for the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgMeta {
    /// Bareword token: `ls`, `--flag`, `FOO=bar`, `/usr/bin/ls`, `42`.
    PlainWord,
    /// Single-quoted string: `'docker ps'`. Contents are literal — no escape
    /// interpretation, no variable expansion. Text is exactly what bash sees.
    RawString,
    /// Double-quoted string containing only plain content (no backslash
    /// escapes, no `$expansions`, no `$(substitutions)`). Text is exactly
    /// what bash sees. An empty double-quoted string is `SafeString`.
    SafeString,
    /// Any argument whose extracted text may diverge from what bash actually
    /// executes: escapes, expansions, substitutions, concatenations, ANSI-C
    /// strings, process substitutions, arithmetic expansions, brace
    /// expressions, parse-recovery error fragments, or unknown node kinds.
    /// Spec B's shell-c unwrapper must refuse to re-parse these.
    UnsafeString,
}

impl Arg {
    /// Test helper: construct an `Arg` with `PlainWord` meta. Production
    /// code (parser/wrappers/extractors) must NOT use this — synthesized
    /// inner commands preserve their original `ArgMeta` by slicing the
    /// existing `Vec<Arg>`.
    pub fn plain(text: impl Into<String>) -> Self {
        Arg {
            text: text.into(),
            meta: ArgMeta::PlainWord,
        }
    }
}

impl AsRef<str> for Arg {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleCommand {
    pub name: Option<String>,
    pub argv: Vec<Arg>,
    pub redirects: Vec<Redirect>,
    pub assignments: Vec<Assignment>,
    pub embedded_substitutions: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pipeline {
    pub stages: Vec<Statement>,
    pub negated: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct List {
    pub first: Box<Statement>,
    pub rest: Vec<(ListOp, Statement)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListOp {
    Semi,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Redirect {
    pub fd: Option<u32>,
    pub op: RedirectOp,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectOp {
    Write,     // >
    Append,    // >>
    Read,      // <
    ReadWrite, // <>
    DupOutput, // >&
    DupInput,  // <&
    Clobber,   // >|
}

impl fmt::Display for RedirectOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedirectOp::Write => write!(f, ">"),
            RedirectOp::Append => write!(f, ">>"),
            RedirectOp::Read => write!(f, "<"),
            RedirectOp::ReadWrite => write!(f, "<>"),
            RedirectOp::DupOutput => write!(f, ">&"),
            RedirectOp::DupInput => write!(f, "<&"),
            RedirectOp::Clobber => write!(f, ">|"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub name: String,
    pub value: String,
}

/// Parse a command string into a Statement.
pub fn parse(command: &str) -> Result<Statement, String> {
    if command.is_empty() {
        return Ok(Statement::Opaque(String::new()));
    }

    let mut parser = TsParser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|e| format!("Failed to load bash grammar: {e}"))?;

    let tree = parser
        .parse(command, None)
        .ok_or_else(|| "tree-sitter parse returned None".to_string())?;

    let root = tree.root_node();

    // If the root itself is an ERROR node, return Opaque
    if root.is_error() {
        return Ok(Statement::Opaque(command.to_string()));
    }

    Ok(convert_program(root, command))
}

/// Flatten a Statement into its leaf SimpleCommand, Opaque, and Empty nodes.
pub fn flatten(stmt: &Statement) -> Vec<&Statement> {
    match stmt {
        Statement::SimpleCommand(cmd) => {
            let mut out = vec![stmt];
            for sub in &cmd.embedded_substitutions {
                out.extend(flatten(sub));
            }
            out
        }
        Statement::Opaque(_) | Statement::Empty => vec![stmt],
        Statement::Pipeline(p) => p.stages.iter().flat_map(flatten).collect(),
        Statement::List(l) => {
            let mut out = flatten(&l.first);
            for (_, s) in &l.rest {
                out.extend(flatten(s));
            }
            out
        }
        Statement::Subshell(inner) => flatten(inner),
        Statement::CommandSubstitution(inner) => flatten(inner),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flatten_simple_command() {
        let cmd = Statement::SimpleCommand(SimpleCommand {
            name: Some("ls".into()),
            argv: vec![],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        });
        let leaves = flatten(&cmd);
        assert_eq!(leaves.len(), 1);
    }

    #[test]
    fn test_flatten_pipeline() {
        let pipe = Statement::Pipeline(Pipeline {
            stages: vec![
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("curl".into()),
                    argv: vec![Arg::plain("http://example.com")],
                    redirects: vec![],
                    assignments: vec![],
                    embedded_substitutions: vec![],
                }),
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("sh".into()),
                    argv: vec![],
                    redirects: vec![],
                    assignments: vec![],
                    embedded_substitutions: vec![],
                }),
            ],
            negated: false,
        });
        let leaves = flatten(&pipe);
        assert_eq!(leaves.len(), 2);
    }

    #[test]
    fn test_flatten_list() {
        let list = Statement::List(List {
            first: Box::new(Statement::SimpleCommand(SimpleCommand {
                name: Some("echo".into()),
                argv: vec![Arg::plain("hello")],
                redirects: vec![],
                assignments: vec![],
                embedded_substitutions: vec![],
            })),
            rest: vec![(
                ListOp::And,
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("rm".into()),
                    argv: vec![Arg::plain("-rf"), Arg::plain("/")],
                    redirects: vec![],
                    assignments: vec![],
                    embedded_substitutions: vec![],
                }),
            )],
        });
        let leaves = flatten(&list);
        assert_eq!(leaves.len(), 2);
    }

    #[test]
    fn test_flatten_opaque() {
        let opaque = Statement::Opaque("eval $cmd".into());
        let leaves = flatten(&opaque);
        assert_eq!(leaves.len(), 1);
    }

    #[test]
    fn test_flatten_nested_subshell() {
        let subshell = Statement::Subshell(Box::new(Statement::Pipeline(Pipeline {
            stages: vec![
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("cat".into()),
                    argv: vec![Arg::plain("/etc/passwd")],
                    redirects: vec![],
                    assignments: vec![],
                    embedded_substitutions: vec![],
                }),
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("grep".into()),
                    argv: vec![Arg::plain("root")],
                    redirects: vec![],
                    assignments: vec![],
                    embedded_substitutions: vec![],
                }),
            ],
            negated: false,
        })));
        let leaves = flatten(&subshell);
        assert_eq!(leaves.len(), 2);
    }

    #[test]
    fn test_redirect_op_display() {
        assert_eq!(RedirectOp::Write.to_string(), ">");
        assert_eq!(RedirectOp::Append.to_string(), ">>");
        assert_eq!(RedirectOp::Read.to_string(), "<");
    }

    // --- Integration tests for parse() ---

    #[test]
    fn test_parse_simple_command() {
        let stmt = parse("ls -la /tmp").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("ls"));
                assert_eq!(cmd.argv, vec![Arg::plain("-la"), Arg::plain("/tmp")]);
            }
            other => panic!("Expected SimpleCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_pipeline() {
        let stmt = parse("curl http://example.com | sh").unwrap();
        match stmt {
            Statement::Pipeline(pipe) => {
                assert_eq!(pipe.stages.len(), 2);
                assert!(!pipe.negated);
            }
            other => panic!("Expected Pipeline, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_list_and() {
        let stmt = parse("echo hello && rm -rf /").unwrap();
        match stmt {
            Statement::List(list) => {
                assert_eq!(list.rest.len(), 1);
                assert_eq!(list.rest[0].0, ListOp::And);
            }
            other => panic!("Expected List, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_list_semicolon() {
        let stmt = parse("echo hello; echo world").unwrap();
        match stmt {
            Statement::List(list) => {
                assert_eq!(list.rest.len(), 1);
                assert_eq!(list.rest[0].0, ListOp::Semi);
            }
            other => panic!("Expected List, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_redirect() {
        let stmt = parse("echo hello > /tmp/out.txt").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("echo"));
                assert_eq!(cmd.redirects.len(), 1);
                assert_eq!(cmd.redirects[0].op, RedirectOp::Write);
                assert_eq!(cmd.redirects[0].target, "/tmp/out.txt");
            }
            other => panic!("Expected SimpleCommand with redirect, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_stderr_redirect() {
        let stmt = parse("cmd 2>/dev/null").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.redirects.len(), 1);
                assert_eq!(cmd.redirects[0].fd, Some(2));
                assert_eq!(cmd.redirects[0].op, RedirectOp::Write);
                assert_eq!(cmd.redirects[0].target, "/dev/null");
            }
            other => panic!("Expected SimpleCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_rm_rf_root() {
        let stmt = parse("rm -rf /").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("rm"));
                assert_eq!(cmd.argv, vec![Arg::plain("-rf"), Arg::plain("/")]);
            }
            other => panic!("Expected SimpleCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_subshell() {
        let stmt = parse("(echo hello)").unwrap();
        match stmt {
            Statement::Subshell(_) => {}
            other => panic!("Expected Subshell, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_empty_command() {
        let stmt = parse("").unwrap();
        match stmt {
            Statement::Opaque(s) => assert!(s.is_empty()),
            other => panic!("Expected Opaque for empty, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_git_status() {
        let stmt = parse("git status").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("git"));
                assert_eq!(cmd.argv, vec![Arg::plain("status")]);
            }
            other => panic!("Expected SimpleCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_complex_pipeline() {
        let stmt = parse("find . -name '*.rs' | xargs grep 'fn main'").unwrap();
        match stmt {
            Statement::Pipeline(pipe) => {
                assert_eq!(pipe.stages.len(), 2);
            }
            other => panic!("Expected Pipeline, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_variable_assignment() {
        let stmt = parse("FOO=bar cmd arg").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("cmd"));
                assert_eq!(cmd.assignments.len(), 1);
                assert_eq!(cmd.assignments[0].name, "FOO");
                assert_eq!(cmd.assignments[0].value, "bar");
            }
            other => panic!("Expected SimpleCommand, got {other:?}"),
        }
    }

    // --- Embedded command substitution tests ---

    #[test]
    fn test_parse_command_with_substitution() {
        let stmt = parse("echo $(rm -rf /)").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("echo"));
                assert_eq!(
                    cmd.embedded_substitutions.len(),
                    1,
                    "Should have 1 embedded substitution"
                );
                match &cmd.embedded_substitutions[0] {
                    Statement::CommandSubstitution(inner) => match inner.as_ref() {
                        Statement::SimpleCommand(inner_cmd) => {
                            assert_eq!(inner_cmd.name.as_deref(), Some("rm"));
                        }
                        other => panic!("Expected inner SimpleCommand, got {other:?}"),
                    },
                    other => panic!("Expected CommandSubstitution, got {other:?}"),
                }
            }
            other => panic!("Expected SimpleCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_backtick_substitution() {
        let stmt = parse("echo `rm -rf /`").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.embedded_substitutions.len(), 1);
            }
            other => panic!("Expected SimpleCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_no_substitution_normal_command() {
        let stmt = parse("ls -la /tmp").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert!(cmd.embedded_substitutions.is_empty());
            }
            other => panic!("Expected SimpleCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_safe_substitution() {
        let stmt = parse("echo $(date)").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.embedded_substitutions.len(), 1);
                match &cmd.embedded_substitutions[0] {
                    Statement::CommandSubstitution(inner) => match inner.as_ref() {
                        Statement::SimpleCommand(inner_cmd) => {
                            assert_eq!(inner_cmd.name.as_deref(), Some("date"));
                        }
                        other => panic!("Expected inner SimpleCommand, got {other:?}"),
                    },
                    other => panic!("Expected CommandSubstitution, got {other:?}"),
                }
            }
            other => panic!("Expected SimpleCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_flatten_includes_embedded_substitutions() {
        let stmt = parse("echo $(rm -rf /)").unwrap();
        let leaves = flatten(&stmt);
        // Should have: echo (SimpleCommand) + rm (SimpleCommand from substitution)
        assert!(
            leaves.len() >= 2,
            "Should flatten embedded substitution: got {} leaves",
            leaves.len()
        );
    }

    // --- Compound statement parsing tests ---

    #[test]
    fn test_parse_for_loop() {
        let stmt = parse("for f in *.yaml; do echo $f; done").unwrap();
        let leaves = flatten(&stmt);
        // Should extract the echo command from the loop body
        assert!(
            !leaves.is_empty(),
            "For loop should have at least 1 leaf, got {}",
            leaves.len()
        );
        // Verify we got the echo command
        let has_echo = leaves.iter().any(|leaf| {
            if let Statement::SimpleCommand(cmd) = leaf {
                cmd.name.as_deref() == Some("echo")
            } else {
                false
            }
        });
        assert!(has_echo, "For loop body should contain echo command");
    }

    #[test]
    fn test_parse_while_loop() {
        let stmt = parse("while true; do ls; done").unwrap();
        let leaves = flatten(&stmt);
        // Should extract both the condition (true) and body (ls)
        assert!(
            leaves.len() >= 2,
            "While loop should have at least 2 leaves, got {}",
            leaves.len()
        );
    }

    #[test]
    fn test_parse_if_statement() {
        let stmt = parse("if true; then echo yes; else echo no; fi").unwrap();
        let leaves = flatten(&stmt);
        // Should have: true (condition), echo yes (then), echo no (else)
        assert!(
            leaves.len() >= 3,
            "If statement should have at least 3 leaves, got {}",
            leaves.len()
        );
    }

    #[test]
    fn test_parse_case_statement() {
        let stmt = parse("case $x in a) echo a;; b) echo b;; esac").unwrap();
        let leaves = flatten(&stmt);
        // Should have echo commands from both case items
        assert!(
            leaves.len() >= 2,
            "Case statement should have at least 2 leaves, got {}",
            leaves.len()
        );
    }

    #[test]
    fn test_parse_compound_statement() {
        let stmt = parse("{ echo a; echo b; }").unwrap();
        let leaves = flatten(&stmt);
        assert!(
            leaves.len() >= 2,
            "Compound statement should have at least 2 leaves, got {}",
            leaves.len()
        );
    }

    #[test]
    fn test_parse_comment_returns_empty() {
        let stmt = parse("# this is a comment").unwrap();
        match stmt {
            Statement::Empty => {}
            other => panic!("Expected Empty for comment, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_test_command_returns_empty() {
        let stmt = parse("[[ -f file.txt ]]").unwrap();
        match stmt {
            Statement::Empty => {}
            other => panic!("Expected Empty for test command, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_test_command_with_substitution() {
        // Test commands with substitutions should extract the substitution
        let stmt = parse("[[ $(cat /etc/passwd) == root ]]").unwrap();
        let leaves = flatten(&stmt);
        // Should have the cat command from the substitution
        let has_cat = leaves.iter().any(|leaf| {
            if let Statement::SimpleCommand(cmd) = leaf {
                cmd.name.as_deref() == Some("cat")
            } else {
                false
            }
        });
        assert!(
            has_cat,
            "Test command with substitution should extract inner command"
        );
    }

    #[test]
    fn test_parse_c_style_for_loop() {
        let stmt = parse("for ((i=0; i<10; i++)); do echo $i; done").unwrap();
        let leaves = flatten(&stmt);
        assert!(
            !leaves.is_empty(),
            "C-style for loop should have at least 1 leaf, got {}",
            leaves.len()
        );
    }

    #[test]
    fn test_parse_function_definition() {
        let stmt = parse("foo() { echo hi; }").unwrap();
        let leaves = flatten(&stmt);
        // Function definitions should extract the body commands
        let has_echo = leaves.iter().any(|leaf| {
            if let Statement::SimpleCommand(cmd) = leaf {
                cmd.name.as_deref() == Some("echo")
            } else {
                false
            }
        });
        assert!(has_echo, "Function definition should contain echo command");
    }

    #[test]
    fn test_flatten_empty() {
        let stmt = Statement::Empty;
        let leaves = flatten(&stmt);
        assert_eq!(leaves.len(), 1, "Empty should flatten to itself");
        assert!(matches!(leaves[0], Statement::Empty));
    }

    // --- Declaration command parsing (export/declare/local/readonly/typeset) ---

    #[test]
    fn test_parse_export_var() {
        let stmt = parse("export FOO=bar").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("export"));
            }
            other => panic!("Expected SimpleCommand for export, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_export_name_only() {
        let stmt = parse("export FOO").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("export"));
                assert_eq!(cmd.argv, vec![Arg::plain("FOO")]);
            }
            other => panic!("Expected SimpleCommand for export, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_declare_x() {
        let stmt = parse("declare -x FOO=bar").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("declare"));
            }
            other => panic!("Expected SimpleCommand for declare, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_local_var() {
        let stmt = parse("local x=1").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("local"));
            }
            other => panic!("Expected SimpleCommand for local, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_readonly_var() {
        let stmt = parse("readonly X=42").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("readonly"));
            }
            other => panic!("Expected SimpleCommand for readonly, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_typeset_var() {
        let stmt = parse("typeset -i num=5").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("typeset"));
            }
            other => panic!("Expected SimpleCommand for typeset, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_export_in_list() {
        // export in a && list should produce a List, not Opaque
        let stmt = parse("export FOO=bar && echo hello").unwrap();
        match &stmt {
            Statement::List(_) => {
                let leaves = flatten(&stmt);
                assert!(
                    leaves.len() >= 2,
                    "export && echo should have at least 2 leaves, got {}",
                    leaves.len()
                );
                // Neither leaf should be Opaque
                for leaf in &leaves {
                    assert!(
                        !matches!(leaf, Statement::Opaque(_)),
                        "No leaf should be Opaque in 'export FOO=bar && echo hello'"
                    );
                }
            }
            other => panic!("Expected List for 'export && echo', got {other:?}"),
        }
    }

    // --- Unset command parsing ---

    #[test]
    fn test_parse_unset_var() {
        let stmt = parse("unset FOO").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("unset"));
                assert_eq!(cmd.argv, vec![Arg::plain("FOO")]);
            }
            other => panic!("Expected SimpleCommand for unset, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_unset_f() {
        let stmt = parse("unset -f my_function").unwrap();
        match stmt {
            Statement::SimpleCommand(cmd) => {
                assert_eq!(cmd.name.as_deref(), Some("unset"));
                assert_eq!(cmd.argv, vec![Arg::plain("-f"), Arg::plain("my_function")]);
            }
            other => panic!("Expected SimpleCommand for unset -f, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_unset_in_list() {
        let stmt = parse("unset FOO && echo done").unwrap();
        match &stmt {
            Statement::List(_) => {
                let leaves = flatten(&stmt);
                for leaf in &leaves {
                    assert!(
                        !matches!(leaf, Statement::Opaque(_)),
                        "No leaf should be Opaque in 'unset FOO && echo done'"
                    );
                }
            }
            other => panic!("Expected List for 'unset && echo', got {other:?}"),
        }
    }

    // --- Process substitution parsing ---

    #[test]
    fn test_parse_process_substitution_extracted() {
        // Process substitution inner commands should be extracted like command substitutions
        let stmt = parse("echo <(rm -rf /)").unwrap();
        let leaves = flatten(&stmt);
        let has_rm = leaves.iter().any(|leaf| {
            if let Statement::SimpleCommand(cmd) = leaf {
                cmd.name.as_deref() == Some("rm")
            } else {
                false
            }
        });
        assert!(
            has_rm,
            "Process substitution <(rm -rf /) should be extracted and flattened"
        );
    }

    #[test]
    fn test_parse_process_substitution_safe() {
        let stmt = parse("diff <(date) <(date -u)").unwrap();
        let leaves = flatten(&stmt);
        let date_count = leaves
            .iter()
            .filter(|leaf| {
                if let Statement::SimpleCommand(cmd) = leaf {
                    cmd.name.as_deref() == Some("date")
                } else {
                    false
                }
            })
            .count();
        assert!(
            date_count >= 2,
            "Both process substitutions should be extracted, got {date_count} date commands"
        );
    }

    #[test]
    fn test_parse_process_substitution_in_diff() {
        // diff <(cat .env) <(echo test) should extract cat
        let stmt = parse("diff <(cat .env) <(echo test)").unwrap();
        let leaves = flatten(&stmt);
        let has_cat = leaves.iter().any(|leaf| {
            if let Statement::SimpleCommand(cmd) = leaf {
                cmd.name.as_deref() == Some("cat")
            } else {
                false
            }
        });
        assert!(
            has_cat,
            "Process substitution <(cat .env) should extract 'cat' for evaluation"
        );
    }

    #[test]
    fn test_parse_mixed_substitutions() {
        // Both command sub and process sub should be extracted
        let stmt = parse("echo $(date) <(rm -rf /)").unwrap();
        let leaves = flatten(&stmt);
        let has_date = leaves.iter().any(|leaf| {
            if let Statement::SimpleCommand(cmd) = leaf {
                cmd.name.as_deref() == Some("date")
            } else {
                false
            }
        });
        let has_rm = leaves.iter().any(|leaf| {
            if let Statement::SimpleCommand(cmd) = leaf {
                cmd.name.as_deref() == Some("rm")
            } else {
                false
            }
        });
        assert!(has_date, "Command substitution $(date) should be extracted");
        assert!(
            has_rm,
            "Process substitution <(rm -rf /) should be extracted"
        );
    }

    // --- Error recovery: backticks in arguments ---

    #[test]
    fn test_parse_grep_backtick_regex_recovers_command() {
        // tree-sitter splits this at the backtick boundary: `grep -oE` (command) +
        // ERROR (the double-quoted pattern). We should recover the command name
        // so grep can still match the allowlist.
        let cmd = r#"grep -oE "Host\(\`[^`]+\`\)" file.txt"#;
        let result = parse(cmd).unwrap();
        let leaves = flatten(&result);
        let has_grep = leaves.iter().any(|leaf| {
            if let Statement::SimpleCommand(cmd) = leaf {
                cmd.name.as_deref() == Some("grep")
            } else {
                false
            }
        });
        assert!(
            has_grep,
            "Should recover grep command name despite backtick parse error, got: {result:?}"
        );
        // Should NOT have any Opaque nodes
        let has_opaque = leaves
            .iter()
            .any(|leaf| matches!(leaf, Statement::Opaque(_)));
        assert!(
            !has_opaque,
            "Recovered command should not produce Opaque leaves, got: {result:?}"
        );
    }

    #[test]
    fn test_parse_backtick_error_recovery_in_pipeline() {
        // Same issue but in a pipeline: grep | grep-with-backticks | sort
        let cmd = r#"grep -r "pattern" src/ | grep -oE "Host\(\`[^`]+\`\)" | sort -u"#;
        let result = parse(cmd).unwrap();
        let leaves = flatten(&result);
        // Should have grep (x2) and sort - no Opaque
        let has_opaque = leaves
            .iter()
            .any(|leaf| matches!(leaf, Statement::Opaque(_)));
        assert!(
            !has_opaque,
            "Pipeline with backtick regex should not produce Opaque, got: {result:?}"
        );
    }
}
