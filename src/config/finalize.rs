use std::path::Path;

use crate::config::discovery::{load_global_config, load_project_config};
use crate::config::overlays::{merge_overlay_config, RuleSource};
use crate::config::profiles::{
    apply_profile_overlay_full, check_and_merge_profile_names, resolve_profile_name,
    validate_profiles, walk_extends_chain, DEFAULT_NAME,
};
use crate::config::rules::{RulesConfig, SafetyLevel, TrustLevel};

#[derive(Debug)]
pub struct FinalConfig {
    pub rules: RulesConfig,
    pub project_ai_prompt: Option<String>,
    pub resolved_profile: String,
    /// (rule_id, prior_source) for every same-id rule that a profile-layer
    /// rule replaced during application. Consumed by `longline rules
    /// --profile <name>` to annotate weakening overrides; ignored by hook
    /// hot paths.
    pub replaced_ids: Vec<(String, RuleSource)>,
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_config(
    mut config: RulesConfig,
    home: &Path,
    project_dir: Option<&Path>,
    cli_trust_level: Option<TrustLevel>,
    cli_safety_level: Option<SafetyLevel>,
    runtime: &str,
    profile_override: Option<&str>,
) -> Result<FinalConfig, String> {
    let global_config = load_global_config(home)?;
    let project_config = match project_dir {
        Some(dir) => load_project_config(dir)?,
        None => None,
    };

    // Detach profile-related fields from each overlay BEFORE moving the
    // overlay into merge_overlay_config (which consumes ProjectConfig).
    let (global_defaults, global_profiles) = global_config
        .as_ref()
        .map(|g| (g.defaults.clone(), g.profiles.clone().unwrap_or_default()))
        .unwrap_or_default();
    let (project_defaults, project_profiles) = project_config
        .as_ref()
        .map(|p| (p.defaults.clone(), p.profiles.clone().unwrap_or_default()))
        .unwrap_or_default();

    if let Some(g) = global_config {
        merge_overlay_config(&mut config, g, RuleSource::Global);
    }

    let mut project_ai_prompt: Option<String> = None;
    if let Some(p) = project_config {
        project_ai_prompt = p
            .ai_judge
            .as_ref()
            .and_then(|a| a.prompt.as_ref())
            .filter(|s| !s.trim().is_empty())
            .cloned();
        merge_overlay_config(&mut config, p, RuleSource::Project);
    }

    // Cross-overlay validation: extends-redeclaration + per-overlay content checks.
    let merged_names = check_and_merge_profile_names(&global_profiles, &project_profiles)?;

    // Build the union so the defaults-target check resolves against the
    // merged name space (a defaults entry in one overlay may target a
    // profile declared in the other overlay).
    let mut union = global_profiles.clone();
    for (k, v) in &project_profiles {
        union.entry(k.clone()).or_insert_with(|| v.clone());
    }

    // Content checks per overlay (reserved names, ai_judge prompts) and
    // defaults-target checks against the union of profile names. The
    // cartesian (global/project profiles × global/project defaults)
    // ensures every overlay's defaults entry is validated even when the
    // referenced profile lives in the other overlay.
    validate_profiles(&union, project_defaults.as_ref())?;
    validate_profiles(&union, global_defaults.as_ref())?;
    validate_profiles(&global_profiles, None)?;
    validate_profiles(&project_profiles, None)?;

    // Eager extends-chain validation for every merged profile.
    for name in &merged_names {
        walk_extends_chain(name, &union)?;
    }

    let resolved = resolve_profile_name(
        runtime,
        profile_override,
        project_defaults.as_ref(),
        global_defaults.as_ref(),
    );
    if resolved != DEFAULT_NAME && !merged_names.contains(&resolved) {
        return Err(format!("unknown profile: '{resolved}'"));
    }

    // Walk and apply: two calls per chain step (global, then project).
    let mut replaced_ids: Vec<(String, RuleSource)> = Vec::new();
    let chain = walk_extends_chain(&resolved, &union)?;
    for (name, _entry_from_union) in &chain {
        if let Some(g_entry) = global_profiles.get(name) {
            let r = apply_profile_overlay_full(
                &mut config,
                g_entry,
                RuleSource::Global,
                &mut project_ai_prompt,
            );
            replaced_ids.extend(r);
        }
        if let Some(p_entry) = project_profiles.get(name) {
            let r = apply_profile_overlay_full(
                &mut config,
                p_entry,
                RuleSource::Project,
                &mut project_ai_prompt,
            );
            replaced_ids.extend(r);
        }
    }

    // CLI flags apply LAST per the field-precedence ladder.
    if let Some(level) = cli_trust_level {
        config.trust_level = level;
    }
    if let Some(level) = cli_safety_level {
        config.safety_level = level;
    }

    Ok(FinalConfig {
        rules: config,
        project_ai_prompt,
        resolved_profile: resolved,
        replaced_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::{self, Allowlists};
    use crate::domain::Decision;

    use SafetyLevel::*;
    use TrustLevel::*;

    #[test]
    fn test_finalize_config_no_overlays() {
        let home = tempfile::TempDir::new().unwrap();
        let config = config::load_embedded_rules().unwrap();
        let original_trust = config.trust_level;
        let original_safety = config.safety_level;

        let result =
            finalize_config(config, home.path(), None, None, None, "claude", None).unwrap();

        assert_eq!(result.rules.trust_level, original_trust);
        assert_eq!(result.rules.safety_level, original_safety);
    }

    #[test]
    fn test_finalize_config_global_overrides_base() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "override_trust_level: full\n",
        )
        .unwrap();

        let config = config::load_embedded_rules().unwrap();
        let result =
            finalize_config(config, home.path(), None, None, None, "claude", None).unwrap();

        assert_eq!(result.rules.trust_level, Full);
    }

    #[test]
    fn test_finalize_config_project_overrides_global() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "override_trust_level: full\n",
        )
        .unwrap();

        let project_dir = tempfile::TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(project_dir.path())
            .output()
            .unwrap();
        let claude_dir = project_dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("longline.yaml"),
            "override_trust_level: minimal\n",
        )
        .unwrap();

        let config = config::load_embedded_rules().unwrap();
        let result = finalize_config(
            config,
            home.path(),
            Some(project_dir.path()),
            None,
            None,
            "claude",
            None,
        )
        .unwrap();

        assert_eq!(
            result.rules.trust_level, Minimal,
            "Project config should override global config"
        );
    }

    #[test]
    fn test_finalize_config_cli_overrides_project_and_global() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "override_trust_level: full\n",
        )
        .unwrap();

        let project_dir = tempfile::TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(project_dir.path())
            .output()
            .unwrap();
        let claude_dir = project_dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("longline.yaml"),
            "override_trust_level: full\n",
        )
        .unwrap();

        let config = config::load_embedded_rules().unwrap();
        let result = finalize_config(
            config,
            home.path(),
            Some(project_dir.path()),
            Some(Standard),
            None,
            "claude",
            None,
        )
        .unwrap();

        assert_eq!(
            result.rules.trust_level, Standard,
            "CLI --trust-level should override both global and project config"
        );
    }

    #[test]
    fn test_finalize_config_cli_safety_overrides_all() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "override_safety_level: strict\n",
        )
        .unwrap();

        let config = config::load_embedded_rules().unwrap();
        let result = finalize_config(
            config,
            home.path(),
            None,
            None,
            Some(Critical),
            "claude",
            None,
        )
        .unwrap();

        assert_eq!(
            result.rules.safety_level, Critical,
            "CLI --safety-level should override global config"
        );
    }

    #[test]
    fn test_finalize_config_invalid_global_config_errors() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "not_a_valid_field: oops\n",
        )
        .unwrap();

        let config = config::load_embedded_rules().unwrap();
        let result = finalize_config(config, home.path(), None, None, None, "claude", None);
        assert!(result.is_err(), "Invalid global config should return error");
    }

    #[test]
    fn test_finalize_config_invalid_project_config_errors() {
        let home = tempfile::TempDir::new().unwrap();
        let project_dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(project_dir.path().join(".git")).unwrap();
        std::fs::create_dir(project_dir.path().join(".claude")).unwrap();
        std::fs::write(
            project_dir.path().join(".claude").join("longline.yaml"),
            "not_a_valid_field: true\n",
        )
        .unwrap();

        let config = config::load_embedded_rules().unwrap();
        let result = finalize_config(
            config,
            home.path(),
            Some(project_dir.path()),
            None,
            None,
            "claude",
            None,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown field"));
    }

    #[test]
    fn test_finalize_config_global_allowlist_not_duplicated() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "allowlists:\n  commands:\n    - { command: my-custom-tool, trust: minimal }\n",
        )
        .unwrap();

        let config = config::load_embedded_rules().unwrap();
        let base_count = config.allowlists.commands.len();

        let result =
            finalize_config(config, home.path(), None, None, None, "claude", None).unwrap();

        assert_eq!(
            result.rules.allowlists.commands.len(),
            base_count + 1,
            "Global config allowlist should be merged exactly once"
        );
    }

    #[test]
    fn test_finalize_config_extracts_project_ai_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let repo = project_dir.path();
        std::fs::create_dir(repo.join(".git")).unwrap();
        std::fs::create_dir(repo.join(".claude")).unwrap();
        std::fs::write(
            repo.join(".claude").join("longline.yaml"),
            "ai_judge:\n  prompt: |\n    {language} {code} {cwd}\n",
        )
        .unwrap();
        let base = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: High,
            trust_level: Standard,
            allowlists: Allowlists {
                commands: vec![],
                paths: vec![],
            },
            rules: vec![],
        };
        let result =
            finalize_config(base, tmp.path(), Some(repo), None, None, "claude", None).unwrap();
        let prompt = result.project_ai_prompt.expect("prompt should be Some");
        assert!(prompt.contains("{code}"), "got: {prompt}");
    }

    #[test]
    fn test_finalize_config_no_project_ai_prompt_when_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path();
        std::fs::create_dir(repo.join(".git")).unwrap();

        let base = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: High,
            trust_level: Standard,
            allowlists: Allowlists {
                commands: vec![],
                paths: vec![],
            },
            rules: vec![],
        };
        let result = finalize_config(base, tmp.path(), Some(repo), None, None, "claude", None)
            .expect("finalize_config should succeed");
        assert!(result.project_ai_prompt.is_none());
    }

    #[test]
    fn test_finalize_config_empty_project_ai_prompt_is_none() {
        use std::fs;

        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path();
        fs::create_dir(repo.join(".claude")).unwrap();
        fs::write(
            repo.join(".claude").join("longline.yaml"),
            "ai_judge:\n  prompt: \"   \"\n",
        )
        .unwrap();
        fs::create_dir(repo.join(".git")).unwrap();

        let base = RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: High,
            trust_level: Standard,
            allowlists: Allowlists {
                commands: vec![],
                paths: vec![],
            },
            rules: vec![],
        };
        let result = finalize_config(base, tmp.path(), Some(repo), None, None, "claude", None)
            .expect("finalize_config should succeed");
        assert!(
            result.project_ai_prompt.is_none(),
            "all-whitespace prompt must be filtered to None"
        );
    }

    #[test]
    fn test_finalize_applies_profile_rules() {
        use crate::config;
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            r#"
defaults:
  codex: strict

profiles:
  strict:
    extends: default
    safety_level: strict
    rules:
      - id: codex-deny-curl
        level: high
        match: { command: curl }
        decision: deny
        reason: "strict denies curl"
"#,
        )
        .unwrap();

        let result = finalize_config(
            config::load_embedded_rules().unwrap(),
            home.path(),
            None,
            None,
            None,
            "codex",
            None,
        )
        .unwrap();

        assert_eq!(result.resolved_profile, "strict");
        assert_eq!(result.rules.safety_level, SafetyLevel::Strict);
        assert!(result.rules.rules.iter().any(|r| r.id == "codex-deny-curl"));
    }

    #[test]
    fn test_finalize_cli_safety_level_beats_profile_safety_level() {
        // Spec §4 field-precedence ladder: CLI flag > profile contribution.
        use crate::config;
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            r#"
profiles:
  lenient:
    safety_level: high
"#,
        )
        .unwrap();

        let result = finalize_config(
            config::load_embedded_rules().unwrap(),
            home.path(),
            None,
            None,
            Some(SafetyLevel::Critical),
            "claude",
            Some("lenient"),
        )
        .unwrap();

        assert_eq!(
            result.rules.safety_level,
            SafetyLevel::Critical,
            "CLI --safety-level critical must beat profile safety_level: high"
        );
    }

    #[test]
    fn test_finalize_unknown_cli_profile_errors() {
        use crate::config;
        let home = tempfile::TempDir::new().unwrap();
        let result = finalize_config(
            config::load_embedded_rules().unwrap(),
            home.path(),
            None,
            None,
            None,
            "codex",
            Some("ghost"),
        );
        let err = result.unwrap_err();
        assert!(err.contains("ghost"), "got: {err}");
    }

    #[test]
    fn test_finalize_default_resolved_when_no_config() {
        use crate::config;
        let home = tempfile::TempDir::new().unwrap();
        let result = finalize_config(
            config::load_embedded_rules().unwrap(),
            home.path(),
            None,
            None,
            None,
            "claude",
            None,
        )
        .unwrap();
        assert_eq!(result.resolved_profile, "default");
    }
}
