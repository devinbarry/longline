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

/// Walk a profile's extends: chain root → leaf, returning ordered tuples.
///
/// The implicit `default` is treated as the root when no user-defined
/// `default` exists; in that case it is *not* included in the returned
/// chain (the layer-5 application is a no-op for the implicit empty
/// profile).
///
/// Errors:
/// - cycle in the extends graph (error names members of the cycle)
/// - unknown extends target (error names the profile and its missing parent)
/// - `extends:` declared on `default` (it is the implicit root)
/// - unknown starting profile name
pub fn walk_extends_chain<'a>(
    start: &str,
    profiles: &'a Profiles,
) -> Result<Vec<(String, &'a ProfileEntry)>, String> {
    if start != DEFAULT_NAME && !profiles.contains_key(start) {
        return Err(format!("unknown profile: '{start}'"));
    }
    let mut leaf_to_root: Vec<String> = Vec::new();
    let mut cursor = start.to_string();
    loop {
        if leaf_to_root.iter().any(|n| n == &cursor) {
            leaf_to_root.push(cursor.clone());
            return Err(format!(
                "profile extends: chain cycle: {}",
                leaf_to_root.join(" -> ")
            ));
        }
        let entry: Option<&ProfileEntry> = profiles.get(&cursor);
        if cursor == DEFAULT_NAME {
            if let Some(e) = entry {
                if e.extends.is_some() {
                    return Err(
                        "profile 'default' may not declare extends:; it is the implicit root"
                            .to_string(),
                    );
                }
            }
            leaf_to_root.push(cursor.clone());
            break;
        }
        let entry = match entry {
            Some(e) => e,
            None => {
                let parent_of = leaf_to_root.last().cloned().unwrap_or_default();
                return Err(format!(
                    "profile '{parent_of}' extends unknown profile '{cursor}'"
                ));
            }
        };
        leaf_to_root.push(cursor.clone());
        cursor = entry
            .extends
            .clone()
            .unwrap_or_else(|| DEFAULT_NAME.to_string());
    }
    leaf_to_root.reverse();
    let mut chain = Vec::with_capacity(leaf_to_root.len());
    for name in leaf_to_root {
        if let Some(e) = profiles.get(&name) {
            chain.push((name, e));
        }
        // Implicit `default` with no user-defined entry: skip (no-op layer).
    }
    Ok(chain)
}

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

    fn mk(extends: Option<&str>) -> ProfileEntry {
        ProfileEntry {
            extends: extends.map(String::from),
            safety_level: None,
            rules: None,
            allowlists: None,
            ai_judge: None,
        }
    }

    #[test]
    fn test_walk_chain_root() {
        let mut p: Profiles = Profiles::new();
        p.insert("default".into(), mk(None));
        let chain = walk_extends_chain("default", &p).unwrap();
        let names: Vec<_> = chain.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["default"]);
    }

    #[test]
    fn test_walk_chain_multi_level_root_first() {
        let mut p: Profiles = Profiles::new();
        p.insert("default".into(), mk(None));
        p.insert("strict".into(), mk(Some("default")));
        p.insert("afterhours".into(), mk(Some("strict")));
        let chain = walk_extends_chain("afterhours", &p).unwrap();
        let names: Vec<_> = chain.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["default", "strict", "afterhours"]);
    }

    #[test]
    fn test_walk_chain_implicit_default_parent() {
        // A profile that omits extends: implicitly extends "default".
        // When "default" is not user-defined, chain includes only the leaf
        // (the implicit empty default contributes nothing at layer 5).
        let mut p: Profiles = Profiles::new();
        p.insert("strict".into(), mk(None));
        let chain = walk_extends_chain("strict", &p).unwrap();
        let names: Vec<_> = chain.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["strict"],
            "implicit default with no user-defined default is a no-op layer"
        );
    }

    #[test]
    fn test_walk_chain_implicit_default_with_user_defined_default() {
        let mut p: Profiles = Profiles::new();
        p.insert("default".into(), mk(None));
        p.insert("strict".into(), mk(None));
        let chain = walk_extends_chain("strict", &p).unwrap();
        let names: Vec<_> = chain.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["default", "strict"]);
    }

    #[test]
    fn test_walk_chain_cycle() {
        let mut p: Profiles = Profiles::new();
        p.insert("a".into(), mk(Some("b")));
        p.insert("b".into(), mk(Some("a")));
        let err = walk_extends_chain("a", &p).unwrap_err();
        assert!(err.contains("cycle"));
        assert!(err.contains("a") && err.contains("b"));
    }

    #[test]
    fn test_walk_chain_unknown_extends_target() {
        let mut p: Profiles = Profiles::new();
        p.insert("strict".into(), mk(Some("ghost")));
        let err = walk_extends_chain("strict", &p).unwrap_err();
        assert!(err.contains("unknown") && err.contains("ghost") && err.contains("strict"));
    }

    #[test]
    fn test_walk_chain_default_with_extends_rejected() {
        let mut p: Profiles = Profiles::new();
        p.insert("default".into(), mk(Some("strict")));
        p.insert("strict".into(), mk(None));
        let err = walk_extends_chain("default", &p).unwrap_err();
        assert!(err.contains("default") && err.contains("extends"));
    }

    #[test]
    fn test_walk_chain_unknown_starting_name() {
        let p: Profiles = Profiles::new();
        let err = walk_extends_chain("ghost", &p).unwrap_err();
        assert!(err.contains("unknown profile") && err.contains("ghost"));
    }
}
