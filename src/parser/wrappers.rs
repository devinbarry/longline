//! Transparent wrapper command unwrapping.
//!
//! Some commands (timeout, nice, env, nohup, strace) modify execution context
//! but delegate actual work to an inner command. This module extracts inner
//! commands so the policy evaluator can assess what actually runs.
//!
//! To add a new wrapper: add one entry to the WRAPPERS table.

#![allow(dead_code, unused_variables)]

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
    todo!()
}

/// Walk a statement tree, find all wrapper SimpleCommands, unwrap them
/// recursively (max depth 16, then ask), return all synthesized inner commands.
pub fn extract_inner_commands(stmt: &Statement) -> Vec<Statement> {
    todo!()
}
