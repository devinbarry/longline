use std::fmt;

use tree_sitter::{Node, Parser as TsParser};

/// Top-level parsed representation of a bash command string.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    SimpleCommand(SimpleCommand),
    Pipeline(Pipeline),
    List(List),
    Subshell(Box<Statement>),
    CommandSubstitution(Box<Statement>),
    Opaque(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleCommand {
    pub name: Option<String>,
    pub argv: Vec<String>,
    pub redirects: Vec<Redirect>,
    pub assignments: Vec<Assignment>,
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
    Write,      // >
    Append,     // >>
    Read,       // <
    ReadWrite,  // <>
    DupOutput,  // >&
    DupInput,   // <&
    Clobber,    // >|
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

/// Handle the top-level "program" node.
fn convert_program(node: Node, source: &str) -> Statement {
    let mut children: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        children.push(convert_node(child, source));
    }

    match children.len() {
        0 => Statement::Opaque(String::new()),
        1 => children.into_iter().next().unwrap(),
        _ => {
            // Multiple top-level statements -> wrap in a List with Semi operators
            let mut iter = children.into_iter();
            let first = Box::new(iter.next().unwrap());
            let rest: Vec<(ListOp, Statement)> =
                iter.map(|s| (ListOp::Semi, s)).collect();
            Statement::List(List { first, rest })
        }
    }
}

/// Dispatch a node by its kind to the appropriate converter.
fn convert_node(node: Node, source: &str) -> Statement {
    match node.kind() {
        "command" => convert_command(node, source),
        "pipeline" => convert_pipeline(node, source),
        "list" => convert_list(node, source),
        "subshell" => convert_subshell(node, source),
        "command_substitution" => convert_command_substitution(node, source),
        "redirected_statement" => convert_redirected_statement(node, source),
        "negated_command" => convert_negated_command(node, source),
        "variable_assignment" => convert_bare_assignment(node, source),
        "variable_assignments" => convert_bare_assignment(node, source),
        _ => Statement::Opaque(node_text(node, source).to_string()),
    }
}

/// Convert a "command" node to a SimpleCommand.
fn convert_command(node: Node, source: &str) -> Statement {
    let mut name: Option<String> = None;
    let mut argv: Vec<String> = Vec::new();
    let mut redirects: Vec<Redirect> = Vec::new();
    let mut assignments: Vec<Assignment> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "command_name" => {
                name = Some(resolve_node_text(child, source));
            }
            "word" | "string" | "raw_string" | "number" | "concatenation"
            | "simple_expansion" | "expansion" | "string_content" => {
                argv.push(resolve_node_text(child, source));
            }
            "variable_assignment" => {
                assignments.push(parse_assignment(child, source));
            }
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                redirects.push(parse_redirect(child, source));
            }
            _ => {
                // Other argument-like nodes: treat as arguments
                argv.push(resolve_node_text(child, source));
            }
        }
    }

    Statement::SimpleCommand(SimpleCommand {
        name,
        argv,
        redirects,
        assignments,
    })
}

/// Convert a "pipeline" node.
fn convert_pipeline(node: Node, source: &str) -> Statement {
    let mut stages: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        stages.push(convert_node(child, source));
    }

    Statement::Pipeline(Pipeline {
        stages,
        negated: false,
    })
}

/// Convert a "list" node.
fn convert_list(node: Node, source: &str) -> Statement {
    let mut items: Vec<Statement> = Vec::new();
    let mut operators: Vec<ListOp> = Vec::new();

    let child_count = node.child_count();
    for i in 0..child_count {
        let child = node.child(i).unwrap();
        if child.is_named() {
            items.push(convert_node(child, source));
        } else {
            let text = node_text(child, source);
            match text {
                "&&" => operators.push(ListOp::And),
                "||" => operators.push(ListOp::Or),
                ";" => operators.push(ListOp::Semi),
                _ => {}
            }
        }
    }

    if items.is_empty() {
        return Statement::Opaque(node_text(node, source).to_string());
    }

    let mut iter = items.into_iter();
    let first = Box::new(iter.next().unwrap());
    let rest: Vec<(ListOp, Statement)> = operators
        .into_iter()
        .zip(iter)
        .collect();

    Statement::List(List { first, rest })
}

/// Convert a "subshell" node.
fn convert_subshell(node: Node, source: &str) -> Statement {
    let mut cursor = node.walk();
    let inner = node
        .named_children(&mut cursor)
        .next()
        .map(|child| convert_node(child, source))
        .unwrap_or_else(|| Statement::Opaque(node_text(node, source).to_string()));

    Statement::Subshell(Box::new(inner))
}

/// Convert a "command_substitution" node.
fn convert_command_substitution(node: Node, source: &str) -> Statement {
    let mut cursor = node.walk();
    let inner = node
        .named_children(&mut cursor)
        .next()
        .map(|child| convert_node(child, source))
        .unwrap_or_else(|| Statement::Opaque(node_text(node, source).to_string()));

    Statement::CommandSubstitution(Box::new(inner))
}

/// Convert a "redirected_statement" node: body + redirects.
fn convert_redirected_statement(node: Node, source: &str) -> Statement {
    let mut body: Option<Statement> = None;
    let mut redirects: Vec<Redirect> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                redirects.push(parse_redirect(child, source));
            }
            _ => {
                if body.is_none() {
                    body = Some(convert_node(child, source));
                }
            }
        }
    }

    let mut stmt = body.unwrap_or_else(|| Statement::Opaque(node_text(node, source).to_string()));

    // If body is a SimpleCommand, attach the redirects to it
    if !redirects.is_empty() {
        if let Statement::SimpleCommand(ref mut cmd) = stmt {
            cmd.redirects.extend(redirects);
        }
        // For non-SimpleCommand bodies, the redirects are lost in this model.
        // A more complete implementation would wrap them, but for now this suffices.
    }

    stmt
}

/// Convert a "negated_command" node (! cmd).
fn convert_negated_command(node: Node, source: &str) -> Statement {
    let mut cursor = node.walk();
    let inner = node
        .named_children(&mut cursor)
        .next()
        .map(|child| convert_node(child, source))
        .unwrap_or_else(|| Statement::Opaque(node_text(node, source).to_string()));

    // Wrap as a negated pipeline
    match inner {
        Statement::Pipeline(mut p) => {
            p.negated = true;
            Statement::Pipeline(p)
        }
        other => Statement::Pipeline(Pipeline {
            stages: vec![other],
            negated: true,
        }),
    }
}

/// Convert a bare "variable_assignment" or "variable_assignments" node (no command).
fn convert_bare_assignment(node: Node, source: &str) -> Statement {
    let mut assignments = Vec::new();

    if node.kind() == "variable_assignment" {
        assignments.push(parse_assignment(node, source));
    } else {
        // variable_assignments: multiple assignments
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "variable_assignment" {
                assignments.push(parse_assignment(child, source));
            }
        }
    }

    Statement::SimpleCommand(SimpleCommand {
        name: None,
        argv: vec![],
        redirects: vec![],
        assignments,
    })
}

/// Parse a variable_assignment node into an Assignment.
fn parse_assignment(node: Node, source: &str) -> Assignment {
    let mut name = String::new();
    let mut value = String::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "variable_name" => {
                name = node_text(child, source).to_string();
            }
            _ => {
                value = resolve_node_text(child, source);
            }
        }
    }

    Assignment { name, value }
}

/// Parse a file_redirect node into a Redirect.
fn parse_redirect(node: Node, source: &str) -> Redirect {
    let mut fd: Option<u32> = None;
    let mut op = RedirectOp::Write;
    let mut target = String::new();

    let child_count = node.child_count();
    for i in 0..child_count {
        let child = node.child(i).unwrap();
        match child.kind() {
            "file_descriptor" => {
                fd = node_text(child, source).parse::<u32>().ok();
            }
            ">" => op = RedirectOp::Write,
            ">>" => op = RedirectOp::Append,
            "<" => op = RedirectOp::Read,
            "<>" => op = RedirectOp::ReadWrite,
            ">&" => op = RedirectOp::DupOutput,
            "<&" => op = RedirectOp::DupInput,
            ">|" => op = RedirectOp::Clobber,
            "word" | "string" | "raw_string" | "number" | "concatenation" => {
                target = resolve_node_text(child, source);
            }
            _ => {
                // For other target nodes, use the text
                if child.is_named() && target.is_empty() {
                    target = resolve_node_text(child, source);
                }
            }
        }
    }

    Redirect { fd, op, target }
}

/// Get the raw text of a node from the source.
fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

/// Resolve node text, stripping quotes from strings and recursing into command_name.
fn resolve_node_text(node: Node, source: &str) -> String {
    match node.kind() {
        "raw_string" => {
            let text = node_text(node, source);
            // Strip surrounding single quotes
            if text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2 {
                text[1..text.len() - 1].to_string()
            } else {
                text.to_string()
            }
        }
        "string" => {
            // Double-quoted string: strip surrounding quotes
            let text = node_text(node, source);
            if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 {
                text[1..text.len() - 1].to_string()
            } else {
                text.to_string()
            }
        }
        "command_name" => {
            // Recurse into the child
            let mut cursor = node.walk();
            let result = node
                .named_children(&mut cursor)
                .next()
                .map(|child| resolve_node_text(child, source))
                .unwrap_or_else(|| node_text(node, source).to_string());
            result
        }
        _ => node_text(node, source).to_string(),
    }
}

/// Flatten a Statement into its leaf SimpleCommand and Opaque nodes.
pub fn flatten(stmt: &Statement) -> Vec<&Statement> {
    match stmt {
        Statement::SimpleCommand(_) | Statement::Opaque(_) => vec![stmt],
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
                    argv: vec!["http://example.com".into()],
                    redirects: vec![],
                    assignments: vec![],
                }),
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("sh".into()),
                    argv: vec![],
                    redirects: vec![],
                    assignments: vec![],
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
                argv: vec!["hello".into()],
                redirects: vec![],
                assignments: vec![],
            })),
            rest: vec![(
                ListOp::And,
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("rm".into()),
                    argv: vec!["-rf".into(), "/".into()],
                    redirects: vec![],
                    assignments: vec![],
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
                    argv: vec!["/etc/passwd".into()],
                    redirects: vec![],
                    assignments: vec![],
                }),
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("grep".into()),
                    argv: vec!["root".into()],
                    redirects: vec![],
                    assignments: vec![],
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
                assert_eq!(cmd.argv, vec!["-la", "/tmp"]);
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
                assert_eq!(cmd.argv, vec!["-rf", "/"]);
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
                assert_eq!(cmd.argv, vec!["status"]);
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
}
