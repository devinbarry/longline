//! Functions to convert tree-sitter nodes to Statement AST.

use tree_sitter::Node;

use super::helpers::{node_text, parse_assignment, parse_redirect, resolve_node_text};
use super::{Assignment, List, ListOp, Pipeline, Redirect, SimpleCommand, Statement};

/// Handle the top-level "program" node.
pub fn convert_program(node: Node, source: &str) -> Statement {
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
            let rest: Vec<(ListOp, Statement)> = iter.map(|s| (ListOp::Semi, s)).collect();
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
    let mut embedded_substitutions: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "command_name" => {
                name = Some(resolve_node_text(child, source));
            }
            "command_substitution" => {
                // Keep the raw text as an argument for display/matching purposes
                argv.push(resolve_node_text(child, source));
                // Parse the inner command for security evaluation
                embedded_substitutions.push(convert_command_substitution(child, source));
            }
            "word" | "string" | "raw_string" | "number" | "concatenation" | "simple_expansion"
            | "expansion" | "string_content" => {
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
        embedded_substitutions,
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
    let rest: Vec<(ListOp, Statement)> = operators.into_iter().zip(iter).collect();

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
pub fn convert_command_substitution(node: Node, source: &str) -> Statement {
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
        embedded_substitutions: vec![],
    })
}
