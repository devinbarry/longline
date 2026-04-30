use serde::Deserialize;

use crate::config::rules::{Rule, RulesConfig, SafetyLevel, TrustLevel};

/// Tracks whether a rule/entry came from built-in defaults, global config, or project config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleSource {
    #[default]
    BuiltIn,
    Global,
    Project,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistEntry {
    pub command: String,
    pub trust: TrustLevel,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(skip)]
    pub source: RuleSource,
}

#[derive(Debug, Default, Deserialize)]
pub struct Allowlists {
    #[serde(default)]
    pub commands: Vec<AllowlistEntry>,
    #[serde(default)]
    #[allow(dead_code)]
    pub paths: Vec<String>,
}

/// Per-project AI judge customization in `.claude/longline.yaml`.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProjectAiJudgeConfig {
    /// Full reasoning prompt that overrides the built-in template.
    /// When set, must contain `{language}`, `{code}`, and `{cwd}` placeholders.
    /// `{extractor_context}` is optional. Validation runs at config-load time.
    pub prompt: Option<String>,
}

/// Per-project config loaded from `.claude/longline.yaml`.
/// All fields are optional; only specified fields override the global config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub override_safety_level: Option<SafetyLevel>,
    pub override_trust_level: Option<TrustLevel>,
    pub allowlists: Option<Allowlists>,
    pub rules: Option<Vec<Rule>>,
    pub disable_rules: Option<Vec<String>>,
    pub ai_judge: Option<ProjectAiJudgeConfig>,
}

/// Merge a project config into a rules config (mutates in place).
/// - override_safety_level replaces safety_level
/// - allowlists are appended
/// - disable_rules filters out matching rule IDs (applied before rules are appended)
/// - rules are appended (not affected by disable_rules)
pub fn merge_project_config(config: &mut RulesConfig, project: ProjectConfig) {
    merge_overlay_config(config, project, RuleSource::Project);
}

/// Merge an overlay config into a rules config, tagging entries with the given source.
pub fn merge_overlay_config(config: &mut RulesConfig, overlay: ProjectConfig, source: RuleSource) {
    if let Some(level) = overlay.override_safety_level {
        config.safety_level = level;
    }

    if let Some(level) = overlay.override_trust_level {
        config.trust_level = level;
    }

    if let Some(allowlists) = overlay.allowlists {
        for mut entry in allowlists.commands {
            entry.source = source;
            config.allowlists.commands.push(entry);
        }
        config.allowlists.paths.extend(allowlists.paths);
    }

    if let Some(disable) = overlay.disable_rules {
        config.rules.retain(|r| !disable.contains(&r.id));
    }

    if let Some(rules) = overlay.rules {
        for mut rule in rules {
            rule.source = source;
            config.rules.push(rule);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::rules::{Matcher, StringOrList};
    use crate::domain::Decision;

    #[test]
    fn test_project_config_all_fields() {
        let yaml = r#"
override_safety_level: strict

allowlists:
  commands:
    - { command: "docker compose", trust: standard }

rules:
  - id: project-allow-docker-build
    level: high
    match:
      command: docker
      args:
        any_of: ["build"]
    decision: allow
    reason: "Docker builds are routine in this project"

disable_rules:
  - npm-install
  - npx-run
"#;
        let config: ProjectConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.override_safety_level, Some(SafetyLevel::Strict));
        assert_eq!(config.allowlists.as_ref().unwrap().commands.len(), 1);
        assert_eq!(config.rules.as_ref().unwrap().len(), 1);
        assert_eq!(config.disable_rules.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_project_config_empty() {
        let yaml = "{}";
        let config: ProjectConfig = serde_norway::from_str(yaml).unwrap();
        assert!(config.override_safety_level.is_none());
        assert!(config.allowlists.is_none());
        assert!(config.rules.is_none());
        assert!(config.disable_rules.is_none());
    }

    #[test]
    fn test_project_config_partial() {
        let yaml = "override_safety_level: critical\n";
        let config: ProjectConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.override_safety_level, Some(SafetyLevel::Critical));
        assert!(config.allowlists.is_none());
    }

    #[test]
    fn test_merge_project_config_safety_level() {
        let mut config = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: SafetyLevel::High,
            trust_level: TrustLevel::default(),
            allowlists: Allowlists::default(),
            rules: vec![],
        };
        let project = ProjectConfig {
            override_safety_level: Some(SafetyLevel::Strict),
            override_trust_level: None,
            allowlists: None,
            rules: None,
            disable_rules: None,
            ai_judge: None,
        };
        merge_project_config(&mut config, project);
        assert_eq!(config.safety_level, SafetyLevel::Strict);
    }

    #[test]
    fn test_merge_project_config_allowlists() {
        let mut config = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: SafetyLevel::High,
            trust_level: TrustLevel::default(),
            allowlists: Allowlists {
                commands: vec![AllowlistEntry {
                    command: "ls".to_string(),
                    trust: TrustLevel::Standard,
                    reason: None,
                    source: RuleSource::default(),
                }],
                paths: vec![],
            },
            rules: vec![],
        };
        let project = ProjectConfig {
            override_safety_level: None,
            override_trust_level: None,
            allowlists: Some(Allowlists {
                commands: vec![AllowlistEntry {
                    command: "docker compose".to_string(),
                    trust: TrustLevel::Standard,
                    reason: None,
                    source: RuleSource::default(),
                }],
                paths: vec![],
            }),
            rules: None,
            disable_rules: None,
            ai_judge: None,
        };
        merge_project_config(&mut config, project);
        assert_eq!(config.allowlists.commands.len(), 2);
        assert!(config.allowlists.commands.iter().any(|e| e.command == "ls"));
        assert!(config
            .allowlists
            .commands
            .iter()
            .any(|e| e.command == "docker compose"));
    }

    #[test]
    fn test_merge_project_config_disable_rules() {
        let mut config = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: SafetyLevel::High,
            trust_level: TrustLevel::default(),
            allowlists: Allowlists::default(),
            rules: vec![
                Rule {
                    id: "rule-a".to_string(),
                    level: SafetyLevel::High,
                    matcher: Matcher::Command {
                        command: StringOrList::Single("rm".to_string()),
                        flags: None,
                        args: None,
                    },
                    decision: Decision::Deny,
                    reason: "test".to_string(),
                    source: RuleSource::default(),
                },
                Rule {
                    id: "rule-b".to_string(),
                    level: SafetyLevel::High,
                    matcher: Matcher::Command {
                        command: StringOrList::Single("chmod".to_string()),
                        flags: None,
                        args: None,
                    },
                    decision: Decision::Ask,
                    reason: "test".to_string(),
                    source: RuleSource::default(),
                },
            ],
        };
        let project = ProjectConfig {
            override_safety_level: None,
            override_trust_level: None,
            allowlists: None,
            rules: None,
            disable_rules: Some(vec!["rule-a".to_string()]),
            ai_judge: None,
        };
        merge_project_config(&mut config, project);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "rule-b");
    }

    #[test]
    fn test_merge_project_config_adds_rules() {
        let mut config = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: SafetyLevel::High,
            trust_level: TrustLevel::default(),
            allowlists: Allowlists::default(),
            rules: vec![],
        };
        let project_yaml = r#"
rules:
  - id: project-rule
    level: high
    match:
      command: docker
    decision: allow
    reason: "Project allows docker"
"#;
        let project: ProjectConfig = serde_norway::from_str(project_yaml).unwrap();
        merge_project_config(&mut config, project);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "project-rule");
    }

    #[test]
    fn test_merge_project_config_empty_is_noop() {
        let mut config = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: SafetyLevel::High,
            trust_level: TrustLevel::default(),
            allowlists: Allowlists {
                commands: vec![AllowlistEntry {
                    command: "ls".to_string(),
                    trust: TrustLevel::Standard,
                    reason: None,
                    source: RuleSource::default(),
                }],
                paths: vec![],
            },
            rules: vec![],
        };
        let project = ProjectConfig {
            override_safety_level: None,
            override_trust_level: None,
            allowlists: None,
            rules: None,
            disable_rules: None,
            ai_judge: None,
        };
        merge_project_config(&mut config, project);
        assert_eq!(config.safety_level, SafetyLevel::High);
        assert_eq!(config.allowlists.commands.len(), 1);
    }

    #[test]
    fn test_allowlist_entry_deserialize_tagged() {
        let yaml = "command: \"git status\"\ntrust: minimal\n";
        let entry: AllowlistEntry = serde_norway::from_str(yaml).unwrap();
        assert_eq!(entry.command, "git status");
        assert_eq!(entry.trust, TrustLevel::Minimal);
    }

    #[test]
    fn test_allowlist_entry_deserialize_with_reason() {
        let yaml =
            "command: \"git push\"\ntrust: full\nreason: \"Pushes local commits to a remote repository\"\n";
        let entry: AllowlistEntry = serde_norway::from_str(yaml).unwrap();
        assert_eq!(entry.command, "git push");
        assert_eq!(entry.trust, TrustLevel::Full);
        assert_eq!(
            entry.reason.as_deref(),
            Some("Pushes local commits to a remote repository")
        );
    }

    #[test]
    fn test_allowlist_entry_deserialize_without_reason() {
        let yaml = "command: ls\ntrust: minimal\n";
        let entry: AllowlistEntry = serde_norway::from_str(yaml).unwrap();
        assert_eq!(entry.command, "ls");
        assert_eq!(entry.reason, None);
    }

    #[test]
    fn test_allowlist_entry_rejects_bare_string() {
        let result: Result<AllowlistEntry, _> = serde_norway::from_str("ls");
        assert!(result.is_err(), "Bare strings should be rejected");
    }

    #[test]
    fn test_allowlist_entry_requires_trust_field() {
        let yaml = "command: \"ls\"\n";
        let result: Result<AllowlistEntry, _> = serde_norway::from_str(yaml);
        assert!(result.is_err(), "Missing trust field should be rejected");
    }

    #[test]
    fn test_rule_source_default_is_builtin() {
        let yaml = r#"
version: 1
rules:
  - id: test-rule
    level: high
    match:
      command: rm
    decision: ask
    reason: "Test"
"#;
        let config: RulesConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.rules[0].source, RuleSource::BuiltIn);
    }

    #[test]
    fn test_merge_project_config_tags_rules_as_project() {
        let mut config = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: SafetyLevel::High,
            trust_level: TrustLevel::default(),
            allowlists: Allowlists::default(),
            rules: vec![],
        };
        let project_yaml = r#"
rules:
  - id: project-rule
    level: high
    match:
      command: docker
    decision: allow
    reason: "Project allows docker"
"#;
        let project: ProjectConfig = serde_norway::from_str(project_yaml).unwrap();
        merge_project_config(&mut config, project);
        assert_eq!(config.rules[0].source, RuleSource::Project);
    }

    #[test]
    fn test_merge_project_config_tags_allowlist_as_project() {
        let mut config = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: SafetyLevel::High,
            trust_level: TrustLevel::default(),
            allowlists: Allowlists {
                commands: vec![AllowlistEntry {
                    command: "ls".to_string(),
                    trust: TrustLevel::Standard,
                    reason: None,
                    source: RuleSource::BuiltIn,
                }],
                paths: vec![],
            },
            rules: vec![],
        };
        let project = ProjectConfig {
            override_safety_level: None,
            override_trust_level: None,
            allowlists: Some(Allowlists {
                commands: vec![AllowlistEntry {
                    command: "docker compose".to_string(),
                    trust: TrustLevel::Standard,
                    reason: None,
                    source: RuleSource::default(),
                }],
                paths: vec![],
            }),
            rules: None,
            disable_rules: None,
            ai_judge: None,
        };
        merge_project_config(&mut config, project);
        assert_eq!(config.allowlists.commands[0].source, RuleSource::BuiltIn);
        assert_eq!(config.allowlists.commands[1].source, RuleSource::Project);
    }

    #[test]
    fn test_merge_overlay_config_tags_with_source() {
        let mut config = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: SafetyLevel::High,
            trust_level: TrustLevel::default(),
            allowlists: Allowlists::default(),
            rules: vec![],
        };
        let overlay_yaml = r#"
allowlists:
  commands:
    - { command: mytool, trust: standard }
rules:
  - id: overlay-rule
    level: high
    match:
      command: docker
    decision: allow
    reason: "Test"
"#;
        let overlay: ProjectConfig = serde_norway::from_str(overlay_yaml).unwrap();
        merge_overlay_config(&mut config, overlay, RuleSource::Global);
        assert_eq!(config.allowlists.commands[0].source, RuleSource::Global);
        assert_eq!(config.rules[0].source, RuleSource::Global);
    }

    #[test]
    fn test_project_config_parses_without_ai_judge() {
        let yaml = "allowlists: { commands: [] }";
        let config: ProjectConfig = serde_norway::from_str(yaml).unwrap();
        assert!(config.ai_judge.is_none());
    }

    #[test]
    fn test_project_config_rejects_unknown_ai_judge_fields() {
        let yaml = r#"
ai_judge:
  qux: bogus
"#;
        let result: Result<ProjectConfig, _> = serde_norway::from_str(yaml);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("qux"),
            "expected error to name the unknown inner field, got: {err}"
        );
    }

    #[test]
    fn test_project_config_parses_ai_judge_prompt_with_required_placeholders() {
        let yaml = r#"
ai_judge:
  prompt: |
    Code: {code}
    Language: {language}
    Cwd: {cwd}
"#;
        let config: ProjectConfig = serde_norway::from_str(yaml).unwrap();
        let aj = config.ai_judge.expect("ai_judge should be Some");
        let prompt = aj.prompt.expect("prompt should be Some");
        assert!(prompt.contains("{code}"));
        assert!(prompt.contains("{language}"));
        assert!(prompt.contains("{cwd}"));
    }
}
