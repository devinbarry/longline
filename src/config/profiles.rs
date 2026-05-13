use serde::Deserialize;
use std::collections::BTreeMap;

use crate::config::overlays::{Allowlists, ProjectAiJudgeConfig};
use crate::config::rules::{Rule, SafetyLevel};

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default)]
    pub claude: Option<String>,
    #[serde(default)]
    pub codex: Option<String>,
}

impl Defaults {
    pub fn for_runtime(&self, runtime: &str) -> Option<&str> {
        match runtime {
            "claude" => self.claude.as_deref(),
            "codex" => self.codex.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProfileEntry {
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub safety_level: Option<SafetyLevel>,
    #[serde(default)]
    pub rules: Option<Vec<Rule>>,
    #[serde(default)]
    pub allowlists: Option<Allowlists>,
    #[serde(default)]
    pub ai_judge: Option<ProjectAiJudgeConfig>,
}

pub type Profiles = BTreeMap<String, ProfileEntry>;

pub const UNRESOLVED_SENTINEL: &str = "unresolved";
pub const DEFAULT_NAME: &str = "default";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_entry_full_yaml() {
        let yaml = r#"
extends: default
safety_level: strict
rules:
  - id: p-rule
    level: high
    match: { command: rm }
    decision: deny
    reason: "no rm"
allowlists:
  commands:
    - { command: mytool, trust: standard }
ai_judge:
  prompt: |
    {language} {code} {cwd}
"#;
        let entry: ProfileEntry = serde_norway::from_str(yaml).unwrap();
        assert_eq!(entry.extends.as_deref(), Some("default"));
        assert_eq!(entry.safety_level, Some(SafetyLevel::Strict));
        assert_eq!(entry.rules.as_ref().unwrap().len(), 1);
        assert!(entry.allowlists.is_some());
        assert!(entry.ai_judge.is_some());
    }

    #[test]
    fn test_profile_entry_empty_yaml() {
        let entry: ProfileEntry = serde_norway::from_str("{}").unwrap();
        assert!(entry.extends.is_none());
        assert!(entry.safety_level.is_none());
        assert!(entry.rules.is_none());
        assert!(entry.allowlists.is_none());
        assert!(entry.ai_judge.is_none());
    }

    #[test]
    fn test_profile_entry_rejects_unknown_field() {
        let result: Result<ProfileEntry, _> = serde_norway::from_str("bogus: 42\n");
        assert!(result.unwrap_err().to_string().contains("unknown field"));
    }

    #[test]
    fn test_profile_entry_rejects_disable_rules() {
        // Spec §3: profile entries do NOT accept disable_rules:
        let result: Result<ProfileEntry, _> = serde_norway::from_str("disable_rules: [foo]\n");
        assert!(
            result.is_err(),
            "disable_rules: must not be valid inside a ProfileEntry"
        );
    }

    #[test]
    fn test_defaults_for_runtime() {
        let d: Defaults = serde_norway::from_str("claude: default\ncodex: strict\n").unwrap();
        assert_eq!(d.for_runtime("claude"), Some("default"));
        assert_eq!(d.for_runtime("codex"), Some("strict"));
        assert_eq!(d.for_runtime("unknown"), None);
    }

    #[test]
    fn test_defaults_rejects_unknown_runtime_key() {
        let result: Result<Defaults, _> = serde_norway::from_str("windsurf: foo\n");
        assert!(result.is_err());
    }
}
