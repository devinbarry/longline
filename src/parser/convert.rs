//! Functions to convert tree-sitter nodes to Statement AST.

use tree_sitter::Node;

use super::helpers::{
    classify_arg_node, node_text, parse_assignment, parse_redirect, resolve_node_text,
};
use super::{Arg, ArgMeta, Assignment, List, ListOp, Pipeline, Redirect, SimpleCommand, Statement};

/// Convert an argv-position tree-sitter node into an `Arg` carrying both the
/// resolved text and an `ArgMeta` classification.
///
/// This is the single entry point for building `Arg` values from the AST.
/// Used by `convert_command` for every argv child, and by
/// `merge_error_into_statement` for recovered ERROR fragments (which always
/// classify as `UnsafeString`).
pub(crate) fn convert_arg_node(node: Node, source: &str) -> Arg {
    Arg {
        text: resolve_node_text(node, source),
        meta: classify_arg_node(node, source),
    }
}

/// Handle the top-level "program" node.
pub fn convert_program(node: Node, source: &str) -> Statement {
    let mut children: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    let named: Vec<Node> = node.named_children(&mut cursor).collect();

    let mut i = 0;
    while i < named.len() {
        let child = named[i];
        if child.is_error() {
            // ERROR node: try to merge into the preceding command/pipeline.
            // This handles tree-sitter parse failures from backticks inside
            // double-quoted strings (e.g. grep -oE "Host\(`[^`]+`\)") where
            // the parser splits the command at the backtick boundary.
            if let Some(prev) = children.last_mut() {
                merge_error_into_statement(prev, child, source);
            } else {
                // No preceding statement to merge into
                children.push(Statement::Opaque(node_text(child, source).to_string()));
            }
        } else {
            children.push(convert_node(child, source));
        }
        i += 1;
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

/// Merge an ERROR node's text into the last SimpleCommand of a statement.
/// This recovers command identity when tree-sitter fails on argument content
/// (e.g. backticks in regex patterns) but successfully parsed the command name.
fn merge_error_into_statement(stmt: &mut Statement, error_node: Node, source: &str) {
    let error_text = node_text(error_node, source).to_string();
    match stmt {
        Statement::SimpleCommand(cmd) => {
            cmd.argv.push(Arg {
                text: error_text,
                meta: ArgMeta::UnsafeString,
            });
        }
        Statement::Pipeline(pipeline) => {
            // Merge into the last stage of the pipeline
            if let Some(last) = pipeline.stages.last_mut() {
                merge_error_into_statement(last, error_node, source);
            }
        }
        _ => {
            // Can't merge into other statement types; leave as-is
            // (the ERROR will be silently dropped, which is acceptable
            // since the preceding statement already determines the decision)
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
        // Compound statements - extract body commands for evaluation
        "for_statement" | "c_style_for_statement" => convert_for_statement(node, source),
        "while_statement" => convert_while_statement(node, source),
        "if_statement" => convert_if_statement(node, source),
        "case_statement" => convert_case_statement(node, source),
        "compound_statement" => convert_compound_statement(node, source),
        "function_definition" => convert_function_definition(node, source),
        // Shell declaration builtins (export/declare/local/readonly/typeset)
        "declaration_command" => convert_declaration_command(node, source),
        // Shell unset/unsetenv builtins
        "unset_command" => convert_unset_command(node, source),
        // Test commands and comments - no executable commands inside
        "test_command" => convert_test_command(node, source),
        "comment" => Statement::Empty,
        _ => Statement::Opaque(node_text(node, source).to_string()),
    }
}

/// Recursively collect command_substitution and process_substitution nodes
/// from within string, concatenation, and other compound argument nodes.
/// Stops recursion at substitution boundaries to avoid double-processing
/// (the substitution's own children are handled by convert_command_substitution).
fn collect_descendant_substitutions(node: Node, source: &str, out: &mut Vec<Statement>) {
    if node.kind() == "command_substitution" || node.kind() == "process_substitution" {
        out.push(convert_command_substitution(node, source));
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_descendant_substitutions(child, source, out);
    }
}

/// Public wrapper for `collect_descendant_substitutions` for use from sibling modules.
pub fn collect_descendant_substitutions_pub(node: Node, source: &str, out: &mut Vec<Statement>) {
    collect_descendant_substitutions(node, source, out);
}

/// Convert a "command" node to a SimpleCommand.
fn convert_command(node: Node, source: &str) -> Statement {
    let mut name: Option<String> = None;
    let mut argv: Vec<Arg> = Vec::new();
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
                argv.push(convert_arg_node(child, source));
                // Parse the inner command for security evaluation
                embedded_substitutions.push(convert_command_substitution(child, source));
            }
            "word" | "string" | "raw_string" | "number" | "concatenation" | "simple_expansion"
            | "expansion" => {
                // NOTE: "string_content" removed — it is only a child of `string`,
                // never a direct argv child. If it ever appears here the
                // catch-all below will still classify it as UnsafeString.
                argv.push(convert_arg_node(child, source));
                collect_descendant_substitutions(child, source, &mut embedded_substitutions);
            }
            "variable_assignment" => {
                let (assignment, subs) = parse_assignment(child, source);
                assignments.push(assignment);
                embedded_substitutions.extend(subs);
            }
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                let (redirect, subs) = parse_redirect(child, source);
                redirects.push(redirect);
                embedded_substitutions.extend(subs);
            }
            _ => {
                // Other argument-like nodes: treat as UnsafeString via convert_arg_node's default.
                argv.push(convert_arg_node(child, source));
                collect_descendant_substitutions(child, source, &mut embedded_substitutions);
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
    for i in 0..child_count as u32 {
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
    let mut redirect_substitutions: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                let (redirect, subs) = parse_redirect(child, source);
                redirects.push(redirect);
                redirect_substitutions.extend(subs);
            }
            _ => {
                if body.is_none() {
                    body = Some(convert_node(child, source));
                }
            }
        }
    }

    let mut stmt = body.unwrap_or_else(|| Statement::Opaque(node_text(node, source).to_string()));

    // Attach redirects and substitutions to the body statement
    if let Statement::SimpleCommand(ref mut cmd) = stmt {
        if !redirects.is_empty() {
            cmd.redirects.extend(redirects);
        }
        cmd.embedded_substitutions.extend(redirect_substitutions);
    } else {
        // For compound bodies (subshells, lists, etc.), inject redirects
        // into all SimpleCommand leaves within the body.
        if !redirects.is_empty() {
            inject_redirects_into_leaves(&mut stmt, &redirects);
        }
        // Propagate redirect substitutions for compound bodies by wrapping
        // body + substitutions into a List so both get evaluated.
        if !redirect_substitutions.is_empty() {
            let mut parts = vec![stmt];
            parts.extend(redirect_substitutions);
            return wrap_as_list(parts);
        }
    }

    stmt
}

/// Inject redirects into all SimpleCommand leaves of a statement tree.
/// Used when redirects are attached to compound statements (subshells, brace groups).
fn inject_redirects_into_leaves(stmt: &mut Statement, redirects: &[Redirect]) {
    match stmt {
        Statement::SimpleCommand(cmd) => cmd.redirects.extend_from_slice(redirects),
        Statement::Pipeline(p) => {
            for stage in &mut p.stages {
                inject_redirects_into_leaves(stage, redirects);
            }
        }
        Statement::List(l) => {
            inject_redirects_into_leaves(&mut l.first, redirects);
            for (_, s) in &mut l.rest {
                inject_redirects_into_leaves(s, redirects);
            }
        }
        Statement::Subshell(inner) | Statement::CommandSubstitution(inner) => {
            inject_redirects_into_leaves(inner, redirects);
        }
        Statement::Opaque(_) | Statement::Empty => {}
    }
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
    let mut embedded_substitutions = Vec::new();

    if node.kind() == "variable_assignment" {
        let (assignment, subs) = parse_assignment(node, source);
        assignments.push(assignment);
        embedded_substitutions.extend(subs);
    } else {
        // variable_assignments: multiple assignments
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "variable_assignment" {
                let (assignment, subs) = parse_assignment(child, source);
                assignments.push(assignment);
                embedded_substitutions.extend(subs);
            }
        }
    }

    Statement::SimpleCommand(SimpleCommand {
        name: None,
        argv: vec![],
        redirects: vec![],
        assignments,
        embedded_substitutions,
    })
}

/// Convert a "declaration_command" node (export/declare/local/readonly/typeset).
/// The keyword is the first anonymous child; remaining named children are
/// variable_assignment, variable_name, or literal arguments (e.g. flags like -x).
fn convert_declaration_command(node: Node, source: &str) -> Statement {
    // First child (anonymous) is the keyword: export, declare, local, readonly, typeset
    let keyword = node
        .child(0)
        .map(|c| node_text(c, source).to_string())
        .unwrap_or_default();

    let mut argv: Vec<Arg> = Vec::new();
    let mut assignments: Vec<Assignment> = Vec::new();
    let mut embedded_substitutions: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "variable_assignment" => {
                let (assignment, subs) = parse_assignment(child, source);
                assignments.push(assignment);
                embedded_substitutions.extend(subs);
            }
            _ => {
                argv.push(convert_arg_node(child, source));
                collect_descendant_substitutions(child, source, &mut embedded_substitutions);
            }
        }
    }

    Statement::SimpleCommand(SimpleCommand {
        name: Some(keyword),
        argv,
        redirects: vec![],
        assignments,
        embedded_substitutions,
    })
}

/// Convert an "unset_command" node (unset/unsetenv).
/// The keyword is the first anonymous child; remaining named children are
/// variable_name or literal arguments (e.g. flags like -f, -v).
fn convert_unset_command(node: Node, source: &str) -> Statement {
    // First child (anonymous) is the keyword: unset or unsetenv
    let keyword = node
        .child(0)
        .map(|c| node_text(c, source).to_string())
        .unwrap_or_default();

    let mut argv: Vec<Arg> = Vec::new();
    let mut embedded_substitutions: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        argv.push(convert_arg_node(child, source));
        collect_descendant_substitutions(child, source, &mut embedded_substitutions);
    }

    Statement::SimpleCommand(SimpleCommand {
        name: Some(keyword),
        argv,
        redirects: vec![],
        assignments: vec![],
        embedded_substitutions,
    })
}

// --- Compound statement converters ---

/// Convert a "for_statement" or "c_style_for_statement" node.
/// Extracts the do_group body for security evaluation.
fn convert_for_statement(node: Node, source: &str) -> Statement {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "do_group" {
            return convert_do_group(child, source);
        }
    }
    // No do_group found - shouldn't happen for valid syntax
    Statement::Opaque(node_text(node, source).to_string())
}

/// Convert a "while_statement" node.
/// Extracts BOTH the condition AND the do_group body - the condition can contain dangerous commands.
fn convert_while_statement(node: Node, source: &str) -> Statement {
    let mut condition: Option<Statement> = None;
    let mut body: Option<Statement> = None;

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "do_group" => {
                body = Some(convert_do_group(child, source));
            }
            _ => {
                // First non-do_group child is the condition
                if condition.is_none() {
                    condition = Some(convert_node(child, source));
                }
            }
        }
    }

    // Combine condition and body into a list for evaluation
    match (condition, body) {
        (Some(c), Some(b)) => wrap_as_list(vec![c, b]),
        (None, Some(b)) => b,
        (Some(c), None) => c,
        (None, None) => Statement::Opaque(node_text(node, source).to_string()),
    }
}

/// Convert an "if_statement" node.
/// Extracts condition, then-body, and any elif/else clauses.
fn convert_if_statement(node: Node, source: &str) -> Statement {
    let mut parts: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "elif_clause" | "else_clause" => {
                // Recursively extract commands from elif/else
                let mut inner_cursor = child.walk();
                for inner in child.named_children(&mut inner_cursor) {
                    parts.push(convert_node(inner, source));
                }
            }
            _ => {
                // Condition and then-body commands
                parts.push(convert_node(child, source));
            }
        }
    }

    wrap_as_list(parts)
}

/// Convert a "case_statement" node.
/// Extracts all case_item bodies.
fn convert_case_statement(node: Node, source: &str) -> Statement {
    let mut parts: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "case_item" {
            // Extract commands from this case item (skip the pattern)
            let mut inner_cursor = child.walk();
            for inner in child.named_children(&mut inner_cursor) {
                // Skip pattern words, only convert commands
                if inner.kind() != "word" && inner.kind() != "concatenation" {
                    parts.push(convert_node(inner, source));
                }
            }
        }
    }

    wrap_as_list(parts)
}

/// Convert a "compound_statement" node ({ ... }).
fn convert_compound_statement(node: Node, source: &str) -> Statement {
    let mut parts: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        parts.push(convert_node(child, source));
    }

    wrap_as_list(parts)
}

/// Convert a "function_definition" node.
/// Note: Defining a function doesn't execute it, but we still parse the body
/// in case the function is called later in the same command.
fn convert_function_definition(node: Node, source: &str) -> Statement {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "compound_statement" {
            return convert_compound_statement(child, source);
        }
    }
    Statement::Empty
}

/// Convert a "test_command" node ([[ ... ]] or [ ... ]).
/// These don't execute commands, but may contain command substitutions.
fn convert_test_command(node: Node, source: &str) -> Statement {
    // Look for any command_substitution children that need evaluation
    let mut substitutions: Vec<Statement> = Vec::new();

    fn find_substitutions(node: Node, source: &str, out: &mut Vec<Statement>) {
        if node.kind() == "command_substitution" {
            out.push(convert_command_substitution(node, source));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            find_substitutions(child, source, out);
        }
    }

    find_substitutions(node, source, &mut substitutions);

    if substitutions.is_empty() {
        Statement::Empty
    } else {
        wrap_as_list(substitutions)
    }
}

/// Convert a "do_group" node (the body of for/while loops).
fn convert_do_group(node: Node, source: &str) -> Statement {
    let mut parts: Vec<Statement> = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        parts.push(convert_node(child, source));
    }

    wrap_as_list(parts)
}

/// Helper to wrap multiple statements as a List, or return single/empty appropriately.
fn wrap_as_list(parts: Vec<Statement>) -> Statement {
    match parts.len() {
        0 => Statement::Empty,
        1 => parts.into_iter().next().unwrap(),
        _ => {
            let mut iter = parts.into_iter();
            let first = Box::new(iter.next().unwrap());
            let rest: Vec<(ListOp, Statement)> = iter.map(|s| (ListOp::Semi, s)).collect();
            Statement::List(List { first, rest })
        }
    }
}
