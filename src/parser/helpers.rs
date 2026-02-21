//! Helper functions for parsing tree-sitter nodes.

use tree_sitter::Node;

use super::{Assignment, Redirect, RedirectOp};

/// Get the raw text of a node from the source.
pub fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

/// Resolve node text, stripping quotes from strings and recursing into command_name.
pub fn resolve_node_text(node: Node, source: &str) -> String {
    match node.kind() {
        "raw_string" => {
            let text = node_text(node, source);
            if text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2 {
                text[1..text.len() - 1].to_string()
            } else {
                text.to_string()
            }
        }
        "string" => {
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

/// Parse a variable_assignment node into an Assignment and any embedded command substitutions.
pub fn parse_assignment(node: Node, source: &str) -> (Assignment, Vec<super::Statement>) {
    let mut name = String::new();
    let mut value = String::new();
    let mut substitutions = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "variable_name" => {
                name = node_text(child, source).to_string();
            }
            _ => {
                value = resolve_node_text(child, source);
                super::convert::collect_descendant_substitutions_pub(
                    child,
                    source,
                    &mut substitutions,
                );
            }
        }
    }

    (Assignment { name, value }, substitutions)
}

/// Parse a file_redirect node into a Redirect and any embedded command substitutions.
pub fn parse_redirect(node: Node, source: &str) -> (Redirect, Vec<super::Statement>) {
    let mut fd: Option<u32> = None;
    let mut op = RedirectOp::Write;
    let mut target = String::new();
    let mut substitutions = Vec::new();

    let child_count = node.child_count();
    for i in 0..child_count as u32 {
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
                super::convert::collect_descendant_substitutions_pub(
                    child,
                    source,
                    &mut substitutions,
                );
            }
            _ => {
                if child.is_named() && target.is_empty() {
                    target = resolve_node_text(child, source);
                    super::convert::collect_descendant_substitutions_pub(
                        child,
                        source,
                        &mut substitutions,
                    );
                }
            }
        }
    }

    (Redirect { fd, op, target }, substitutions)
}
