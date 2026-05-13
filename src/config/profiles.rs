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

    #[test]
    fn test_merge_names_disjoint() {
        let mut g: Profiles = Profiles::new();
        g.insert("strict".into(), mk(Some("default")));
        let mut p: Profiles = Profiles::new();
        p.insert("paranoid".into(), mk(Some("strict")));
        let names = check_and_merge_profile_names(&g, &p).unwrap();
        let mut sorted = names.iter().cloned().collect::<Vec<_>>();
        sorted.sort();
        assert_eq!(sorted, vec!["paranoid", "strict"]);
    }

    #[test]
    fn test_merge_names_extends_redeclared_errors() {
        let mut g: Profiles = Profiles::new();
        g.insert("strict".into(), mk(Some("default")));
        let mut p: Profiles = Profiles::new();
        p.insert("strict".into(), mk(Some("hardened")));
        let err = check_and_merge_profile_names(&g, &p).unwrap_err();
        assert!(err.contains("strict") && err.contains("default") && err.contains("hardened"));
        assert!(err.contains("conflicting extends"));
    }

    #[test]
    fn test_merge_names_extends_redeclared_equal_target_also_errors() {
        // Spec §3 (post-R2): presence-based check, not value-based.
        // Global with no extends (implicit default) + project with explicit
        // extends: default is also a conflict.
        let mut g: Profiles = Profiles::new();
        g.insert("strict".into(), mk(None));
        let mut p: Profiles = Profiles::new();
        p.insert("strict".into(), mk(Some("default")));
        let err = check_and_merge_profile_names(&g, &p).unwrap_err();
        assert!(err.contains("strict"));
        assert!(err.contains("default") && err.contains("(implicit)"));
    }

    #[test]
    fn test_merge_names_project_only_extends_ok_when_global_silent() {
        // If global doesn't define the profile, project may declare extends freely.
        let g: Profiles = Profiles::new();
        let mut p: Profiles = Profiles::new();
        p.insert("strict".into(), mk(Some("default")));
        let names = check_and_merge_profile_names(&g, &p).unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn test_merge_names_global_silent_extends_project_silent_extends_ok() {
        // Both sides define `strict` but neither declares extends — no conflict.
        let mut g: Profiles = Profiles::new();
        g.insert("strict".into(), mk(None));
        let mut p: Profiles = Profiles::new();
        p.insert("strict".into(), mk(None));
        let names = check_and_merge_profile_names(&g, &p).unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn test_validate_rejects_user_defined_unresolved() {
        let mut p: Profiles = Profiles::new();
        p.insert(UNRESOLVED_SENTINEL.into(), mk(None));
        let err = validate_profiles(&p, None).unwrap_err();
        assert!(err.contains(UNRESOLVED_SENTINEL) && err.contains("reserved"));
    }

    #[test]
    fn test_validate_allows_user_defined_default_without_extends() {
        let mut p: Profiles = Profiles::new();
        p.insert("default".into(), mk(None));
        validate_profiles(&p, None).unwrap();
    }

    #[test]
    fn test_validate_defaults_target_must_exist() {
        let p: Profiles = Profiles::new();
        let d = Defaults {
            claude: None,
            codex: Some("ghost".into()),
        };
        let err = validate_profiles(&p, Some(&d)).unwrap_err();
        assert!(err.contains("ghost") && err.contains("codex"));
    }

    #[test]
    fn test_validate_defaults_target_default_is_always_valid() {
        let p: Profiles = Profiles::new();
        let d = Defaults {
            claude: Some("default".into()),
            codex: Some("default".into()),
        };
        validate_profiles(&p, Some(&d)).unwrap();
    }

    #[test]
    fn test_validate_ai_judge_prompt_placeholders_required() {
        let mut p: Profiles = Profiles::new();
        p.insert(
            "weird".into(),
            ProfileEntry {
                extends: None,
                safety_level: None,
                rules: None,
                allowlists: None,
                ai_judge: Some(crate::config::overlays::ProjectAiJudgeConfig {
                    prompt: Some("no placeholders here".into()),
                }),
            },
        );
        let err = validate_profiles(&p, None).unwrap_err();
        assert!(err.contains("placeholder"), "got: {err}");
    }
}

/// Validate that no profile name has its `extends:` declared in both
/// overlays, and return the union of profile names across the two maps.
///
/// "Declared" is presence-based: omitted `extends:` in one overlay and
/// explicit `extends:` in the other is also a conflict. Per spec §3 this
/// eliminates the implicit-vs-explicit `default` edge case.
pub fn check_and_merge_profile_names(
    global: &Profiles,
    project: &Profiles,
) -> Result<std::collections::BTreeSet<String>, String> {
    let mut names = std::collections::BTreeSet::new();
    for (name, g_entry) in global {
        names.insert(name.clone());
        if let Some(p_entry) = project.get(name) {
            if g_entry.extends.is_some() && p_entry.extends.is_some() {
                return Err(format!(
                    "profile '{name}' has conflicting extends: across overlays\n\
                     global: extends '{}'\n\
                     project: extends '{}'\n\
                     Profile inheritance edges may not be redeclared across overlays; \
                     if this project needs a different parent, use a new profile name.",
                    g_entry.extends.as_deref().unwrap(),
                    p_entry.extends.as_deref().unwrap(),
                ));
            }
            if g_entry.extends.is_some() || p_entry.extends.is_some() {
                // One side omitted → implicit default. Other side declared explicitly.
                let (decl_overlay, decl_target, omit_overlay) = if g_entry.extends.is_some() {
                    ("global", g_entry.extends.as_deref().unwrap(), "project")
                } else {
                    ("project", p_entry.extends.as_deref().unwrap(), "global")
                };
                return Err(format!(
                    "profile '{name}' has conflicting extends: across overlays\n\
                     {decl_overlay}: extends '{decl_target}'\n\
                     {omit_overlay}: extends 'default' (implicit)\n\
                     Profile inheritance edges may not be redeclared across overlays; \
                     if this project needs a different parent, use a new profile name."
                ));
            }
        }
    }
    for name in project.keys() {
        names.insert(name.clone());
    }
    Ok(names)
}

/// Validate profile map content:
/// - Rejects the reserved name `UNRESOLVED_SENTINEL`.
/// - Validates `ai_judge.prompt` placeholders for each profile entry.
/// - Ensures `defaults.<runtime>` targets exist in the map (or equal `DEFAULT_NAME`).
pub fn validate_profiles(profiles: &Profiles, defaults: Option<&Defaults>) -> Result<(), String> {
    if profiles.contains_key(UNRESOLVED_SENTINEL) {
        return Err(format!(
            "profile name '{UNRESOLVED_SENTINEL}' is reserved (used in audit log fail-open entries)"
        ));
    }
    for (name, entry) in profiles {
        if let Some(aj) = entry.ai_judge.as_ref() {
            if let Some(prompt) = aj.prompt.as_deref() {
                if !prompt.trim().is_empty() {
                    let label =
                        std::path::PathBuf::from(format!("profiles.{name}.ai_judge.prompt"));
                    crate::config::prompt::validate_ai_judge_prompt(prompt, &label)?;
                }
            }
        }
    }
    if let Some(d) = defaults {
        for (runtime, target) in [
            ("claude", d.claude.as_deref()),
            ("codex", d.codex.as_deref()),
        ] {
            if let Some(t) = target {
                if t != DEFAULT_NAME && !profiles.contains_key(t) {
                    return Err(format!(
                        "defaults.{runtime} references profile '{t}' which is not defined"
                    ));
                }
            }
        }
    }
    Ok(())
}
