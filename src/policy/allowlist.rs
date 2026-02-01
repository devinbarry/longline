//! Allowlist matching logic.

use crate::parser::{SimpleCommand, Statement};

use super::config::RulesConfig;

/// Check if a leaf node is allowlisted.
pub fn is_allowlisted(config: &RulesConfig, leaf: &Statement) -> bool {
    match leaf {
        Statement::SimpleCommand(cmd) => find_allowlist_match(config, cmd).is_some(),
        _ => false,
    }
}

/// Find the matching allowlist entry for a SimpleCommand.
/// Entries like "git status" match command name + required args.
/// Bare entries like "ls" match any invocation of that command.
/// Returns the matching entry string, or None if no match.
pub fn find_allowlist_match<'a>(config: &'a RulesConfig, cmd: &SimpleCommand) -> Option<&'a str> {
    let cmd_name = match &cmd.name {
        Some(n) => n.as_str(),
        None => return None,
    };

    for entry in &config.allowlists.commands {
        let parts: Vec<&str> = entry.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        if parts[0] != cmd_name {
            continue;
        }
        if parts.len() == 1 {
            // Bare command name matches any invocation
            return Some(entry);
        }
        // Multi-word entry: all additional parts must appear in argv
        let required_args = &parts[1..];
        let all_present = required_args
            .iter()
            .all(|req| cmd.argv.iter().any(|a| a == req));
        if all_present {
            return Some(entry);
        }
    }
    None
}
