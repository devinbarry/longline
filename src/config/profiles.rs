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

/// Resolve the profile name for this invocation.
///
/// Precedence (highest first):
/// 1. CLI flag (`cli_override`)
/// 2. Project `defaults.<runtime>`
/// 3. Global `defaults.<runtime>`
/// 4. Built-in fallback: `"default"`.
///
/// Pure function behind a single seam — adding env-var selection later
/// is a one-line patch between steps 1 and 2.
pub fn resolve_profile_name(
    runtime: &str,
    cli_override: Option<&str>,
    project_defaults: Option<&Defaults>,
    global_defaults: Option<&Defaults>,
) -> String {
    if let Some(n) = cli_override {
        return n.to_string();
    }
    if let Some(n) = project_defaults.and_then(|d| d.for_runtime(runtime)) {
        return n.to_string();
    }
    if let Some(n) = global_defaults.and_then(|d| d.for_runtime(runtime)) {
        return n.to_string();
    }
    DEFAULT_NAME.to_string()
}

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

    #[test]
    fn test_resolve_profile_name_cli_wins() {
        let proj = Defaults {
            claude: Some("p-c".into()),
            codex: Some("p-x".into()),
        };
        let glob = Defaults {
            claude: Some("g-c".into()),
            codex: Some("g-x".into()),
        };
        assert_eq!(
            resolve_profile_name("codex", Some("flag"), Some(&proj), Some(&glob)),
            "flag"
        );
    }

    #[test]
    fn test_resolve_profile_name_project_beats_global() {
        let proj = Defaults {
            claude: Some("p-c".into()),
            codex: None,
        };
        let glob = Defaults {
            claude: Some("g-c".into()),
            codex: Some("g-x".into()),
        };
        assert_eq!(
            resolve_profile_name("claude", None, Some(&proj), Some(&glob)),
            "p-c"
        );
    }

    #[test]
    fn test_resolve_profile_name_falls_through_to_global() {
        let glob = Defaults {
            claude: None,
            codex: Some("g-x".into()),
        };
        assert_eq!(
            resolve_profile_name("codex", None, None, Some(&glob)),
            "g-x"
        );
    }

    #[test]
    fn test_resolve_profile_name_builtin_fallback() {
        assert_eq!(
            resolve_profile_name("codex", None, None, None),
            DEFAULT_NAME
        );
        assert_eq!(
            resolve_profile_name("claude", None, None, None),
            DEFAULT_NAME
        );
    }

    #[test]
    fn test_resolve_profile_name_unknown_runtime_falls_to_default() {
        assert_eq!(
            resolve_profile_name("windsurf", None, None, None),
            DEFAULT_NAME
        );
    }
}
