//! Helper functions for parsing tree-sitter nodes.

use tree_sitter::Node;

use super::{ArgMeta, Assignment, Redirect, RedirectOp};

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

/// Classify an argv-position tree-sitter node into an `ArgMeta`.
///
/// Grammar reference: tree-sitter-bash 0.25.x. Rules:
/// - `word`, `number` → `PlainWord`
/// - `raw_string` (single-quoted) → `RawString`
/// - `string` (double-quoted) → delegated to `classify_string_node`
/// - `ansi_c_string`, `translated_string` → `UnsafeString`
/// - `simple_expansion`, `expansion`, `command_substitution`,
///   `process_substitution`, `arithmetic_expansion`,
///   `brace_expression`, `concatenation` → `UnsafeString`
/// - bare `$` (grammar-legal as an argument token) → `UnsafeString`
/// - anything else (unknown / error) → `UnsafeString` (conservative default)
pub fn classify_arg_node(node: Node, source: &str) -> ArgMeta {
    match node.kind() {
        "word" | "number" => ArgMeta::PlainWord,
        "raw_string" => ArgMeta::RawString,
        "string" => classify_string_node(node, source),
        // Everything below is UnsafeString — text may differ from bash execution value.
        // Some arms (`translated_string`, `brace_expression`) are not produced by
        // tree-sitter-bash 0.25 in practice (`$"..."` parses as `string`, `{a,b,c}`
        // as `concatenation`) but are retained as defense-in-depth against future
        // grammar changes.
        "ansi_c_string"
        | "translated_string"
        | "simple_expansion"
        | "expansion"
        | "command_substitution"
        | "process_substitution"
        | "arithmetic_expansion"
        | "brace_expression"
        | "concatenation"
        | "$"
        | "ERROR" => ArgMeta::UnsafeString,
        _ => ArgMeta::UnsafeString,
    }
}

/// Classify a `string` node (double-quoted).
fn classify_string_node(node: Node, source: &str) -> ArgMeta {
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor).peekable();

    if children.peek().is_none() {
        // Empty `""` — zero named children.
        return ArgMeta::SafeString;
    }

    for child in children {
        match child.kind() {
            "string_content" => {
                if node_text(child, source).contains('\\') {
                    return ArgMeta::UnsafeString;
                }
            }
            "simple_expansion" | "expansion" | "command_substitution" => {
                return ArgMeta::UnsafeString;
            }
            _ => {
                // Unknown child kind inside a string — fail closed.
                return ArgMeta::UnsafeString;
            }
        }
    }
    ArgMeta::SafeString
}

#[cfg(test)]
mod classification_tests {
    use crate::parser::{Arg, ArgMeta};
    use tree_sitter::Parser as TsParser;

    fn classify_first_arg(input: &str) -> Arg {
        let mut parser = TsParser::new();
        parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .expect("load bash grammar");
        let source = format!("cmd {input}");
        let tree = parser.parse(&source, None).expect("parse");
        let root = tree.root_node();

        fn find_command<'a>(n: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
            if n.kind() == "command" {
                return Some(n);
            }
            let mut cur = n.walk();
            for child in n.named_children(&mut cur) {
                if let Some(found) = find_command(child) {
                    return Some(found);
                }
            }
            None
        }

        let cmd_node = find_command(root).expect("command node");
        let mut saw_name = false;
        let mut cursor = cmd_node.walk();
        for child in cmd_node.named_children(&mut cursor) {
            if child.kind() == "command_name" {
                saw_name = true;
                continue;
            }
            if saw_name {
                return crate::parser::convert::convert_arg_node(child, &source);
            }
        }
        panic!("no argv element found in: {input}");
    }

    // ── PlainWord ──────────────────────────────────────────────
    #[test]
    fn plain_word_bareword() {
        let arg = classify_first_arg("ls");
        assert_eq!(arg.text, "ls");
        assert_eq!(arg.meta, ArgMeta::PlainWord);
    }

    #[test]
    fn plain_word_flag() {
        assert_eq!(classify_first_arg("--flag").meta, ArgMeta::PlainWord);
    }

    #[test]
    fn plain_word_assignment_shape() {
        assert_eq!(classify_first_arg("FOO=bar").meta, ArgMeta::PlainWord);
    }

    #[test]
    fn plain_word_absolute_path() {
        assert_eq!(classify_first_arg("/usr/bin/ls").meta, ArgMeta::PlainWord);
    }

    #[test]
    fn plain_word_number() {
        assert_eq!(classify_first_arg("42").meta, ArgMeta::PlainWord);
    }

    // ── RawString ──────────────────────────────────────────────
    #[test]
    fn raw_string_single_quoted() {
        let arg = classify_first_arg("'docker ps'");
        assert_eq!(arg.text, "docker ps");
        assert_eq!(arg.meta, ArgMeta::RawString);
    }

    #[test]
    fn raw_string_empty() {
        assert_eq!(classify_first_arg("''").meta, ArgMeta::RawString);
    }

    #[test]
    fn raw_string_with_double_quote_inside() {
        let arg = classify_first_arg("'echo \"hi\"'");
        assert_eq!(arg.text, "echo \"hi\"");
        assert_eq!(arg.meta, ArgMeta::RawString);
    }

    // ── SafeString ─────────────────────────────────────────────
    #[test]
    fn safe_string_double_quoted() {
        let arg = classify_first_arg("\"docker ps\"");
        assert_eq!(arg.text, "docker ps");
        assert_eq!(arg.meta, ArgMeta::SafeString);
    }

    #[test]
    fn safe_string_empty() {
        let arg = classify_first_arg("\"\"");
        assert_eq!(arg.meta, ArgMeta::SafeString);
    }

    #[test]
    fn safe_string_single_space() {
        // tree-sitter emits zero named children for " " (whitespace-only body); SafeString via the zero-children rule.
        assert_eq!(classify_first_arg("\" \"").meta, ArgMeta::SafeString);
    }

    // ── UnsafeString: escapes ──────────────────────────────────
    #[test]
    fn unsafe_escaped_double_quote() {
        assert_eq!(
            classify_first_arg("\"echo \\\"hi\\\"\"").meta,
            ArgMeta::UnsafeString
        );
    }

    #[test]
    fn unsafe_escape_sequence() {
        assert_eq!(classify_first_arg("\"a\\nb\"").meta, ArgMeta::UnsafeString);
    }

    // ── UnsafeString: expansions ───────────────────────────────
    #[test]
    fn unsafe_simple_expansion_inside_string() {
        assert_eq!(classify_first_arg("\"$HOME\"").meta, ArgMeta::UnsafeString);
    }

    #[test]
    fn unsafe_expansion_inside_string() {
        assert_eq!(
            classify_first_arg("\"${VAR:-default}\"").meta,
            ArgMeta::UnsafeString
        );
    }

    #[test]
    fn unsafe_bare_simple_expansion() {
        assert_eq!(classify_first_arg("$HOME").meta, ArgMeta::UnsafeString);
    }

    // ── UnsafeString: substitutions ────────────────────────────
    #[test]
    fn unsafe_command_substitution_inside_string() {
        assert_eq!(
            classify_first_arg("\"$(date)\"").meta,
            ArgMeta::UnsafeString
        );
    }

    #[test]
    fn unsafe_bare_command_substitution() {
        assert_eq!(classify_first_arg("$(date)").meta, ArgMeta::UnsafeString);
    }

    #[test]
    fn unsafe_backtick_substitution() {
        assert_eq!(classify_first_arg("\"`date`\"").meta, ArgMeta::UnsafeString);
    }

    // ── UnsafeString: process/arith/ansi-c/brace ───────────────
    #[test]
    fn unsafe_process_substitution_input() {
        assert_eq!(classify_first_arg("<(date)").meta, ArgMeta::UnsafeString);
    }

    #[test]
    fn unsafe_process_substitution_output() {
        assert_eq!(classify_first_arg(">(cat)").meta, ArgMeta::UnsafeString);
    }

    #[test]
    fn unsafe_arithmetic_expansion() {
        assert_eq!(classify_first_arg("$((1+2))").meta, ArgMeta::UnsafeString);
    }

    #[test]
    fn unsafe_ansi_c_string() {
        assert_eq!(classify_first_arg("$'ansi\\n'").meta, ArgMeta::UnsafeString);
    }

    #[test]
    fn unsafe_brace_expression() {
        assert_eq!(classify_first_arg("{a,b,c}").meta, ArgMeta::UnsafeString);
    }

    // ── UnsafeString: concatenation ────────────────────────────
    #[test]
    fn unsafe_concat_word_string() {
        assert_eq!(classify_first_arg("foo\"bar\"").meta, ArgMeta::UnsafeString);
    }

    #[test]
    fn unsafe_concat_two_strings() {
        assert_eq!(classify_first_arg("\"a\"\"b\"").meta, ArgMeta::UnsafeString);
    }

    #[test]
    fn unsafe_concat_word_raw_string() {
        // Conservatively unsafe even though both parts are safe individually —
        // Spec B may refine later.
        assert_eq!(classify_first_arg("foo'bar'").meta, ArgMeta::UnsafeString);
    }
}
