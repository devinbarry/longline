use std::fs;
use std::path::{Path, PathBuf};

use crate::config::overlays::ProjectConfig;
use crate::config::prompt::validate_project_ai_judge_prompt;

pub fn default_rules_path(home: &Path) -> PathBuf {
    home.join(".config").join("longline").join("rules.yaml")
}

pub fn global_config_path(home: &Path) -> PathBuf {
    home.join(".config").join("longline").join("longline.yaml")
}

pub fn project_config_path(project_root: &Path) -> PathBuf {
    project_root.join(".claude").join("longline.yaml")
}

pub fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    let mut current = cwd.to_path_buf();
    loop {
        if current.join(".git").exists()
            || current.join(".claude").is_dir()
            || current.join(".codex").is_dir()
        {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

pub fn existing_project_config_path(cwd: &Path) -> Option<PathBuf> {
    find_project_root(cwd)
        .map(|root| project_config_path(&root))
        .filter(|path| path.exists())
}

/// Load project config from `.claude/longline.yaml` if it exists.
/// Walks up from `cwd` to find the project root first.
/// Returns Ok(None) if no project config file exists, Err on parse failure.
pub fn load_project_config(cwd: &Path) -> Result<Option<ProjectConfig>, String> {
    let root = match find_project_root(cwd) {
        Some(r) => r,
        None => return Ok(None),
    };
    let config_path = project_config_path(&root);
    let content = match fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let config: ProjectConfig = serde_norway::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", config_path.display()))?;
    validate_project_ai_judge_prompt(&config, &config_path)?;
    Ok(Some(config))
}

/// Load global config from `~/.config/longline/longline.yaml` if it exists.
/// Returns Ok(None) if no global config file exists, Err on parse failure.
pub fn load_global_config(home: &Path) -> Result<Option<ProjectConfig>, String> {
    let config_path = global_config_path(home);
    let content = match fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let config: ProjectConfig = serde_norway::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", config_path.display()))?;
    if config
        .ai_judge
        .as_ref()
        .and_then(|a| a.prompt.as_ref())
        .is_some()
    {
        return Err(format!(
            "ai_judge.prompt is not allowed in global config ({}); set it in <repo>/.claude/longline.yaml instead",
            config_path.display()
        ));
    }
    Ok(Some(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::rules::SafetyLevel;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("longline-{name}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn default_rules_path_uses_config_longline_rules_yaml() {
        assert_eq!(
            default_rules_path(Path::new("/tmp/home")),
            PathBuf::from("/tmp/home/.config/longline/rules.yaml")
        );
    }

    #[test]
    fn global_config_path_uses_config_longline_yaml() {
        assert_eq!(
            global_config_path(Path::new("/tmp/home")),
            PathBuf::from("/tmp/home/.config/longline/longline.yaml")
        );
    }

    #[test]
    fn project_config_path_uses_claude_longline_yaml() {
        assert_eq!(
            project_config_path(Path::new("/repo")),
            PathBuf::from("/repo/.claude/longline.yaml")
        );
    }

    #[test]
    fn find_project_root_with_git_directory() {
        let root = temp_dir("git-dir");
        fs::create_dir(root.join(".git")).expect("create .git dir");
        let cwd = root.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(root));
    }

    #[test]
    fn find_project_root_with_git_worktree_file() {
        let root = temp_dir("git-file");
        fs::write(root.join(".git"), "gitdir: /tmp/worktrees/repo\n").expect("write .git file");
        let cwd = root.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(root));
    }

    #[test]
    fn find_project_root_with_claude_directory() {
        let root = temp_dir("claude-dir");
        fs::create_dir(root.join(".claude")).expect("create .claude dir");
        let cwd = root.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(root));
    }

    #[test]
    fn closest_marker_wins_when_outer_has_git_and_inner_has_claude() {
        let root = temp_dir("closest-marker");
        fs::create_dir(root.join(".git")).expect("create .git dir");
        let inner = root.join("packages").join("tool");
        fs::create_dir_all(inner.join(".claude")).expect("create .claude dir");
        let cwd = inner.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(inner));
    }

    #[test]
    fn no_root_when_markers_absent() {
        let root = temp_dir("no-markers");
        let cwd = root.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), None);
    }

    #[test]
    fn find_project_root_with_codex_directory() {
        let root = temp_dir("codex-dir");
        fs::create_dir(root.join(".codex")).expect("create .codex dir");
        let cwd = root.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(root));
    }

    #[test]
    fn closest_marker_wins_outer_git_inner_codex() {
        let root = temp_dir("outer-git-inner-codex");
        fs::create_dir(root.join(".git")).expect("create outer .git");
        let inner = root.join("packages").join("tool");
        fs::create_dir_all(inner.join(".codex")).expect("create inner .codex");
        let cwd = inner.join("src");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(inner));
    }

    #[test]
    fn closest_marker_wins_outer_claude_inner_codex() {
        let root = temp_dir("outer-claude-inner-codex");
        fs::create_dir(root.join(".claude")).expect("create outer .claude");
        let inner = root.join("packages").join("tool");
        fs::create_dir_all(inner.join(".codex")).expect("create inner .codex");
        let cwd = inner.join("src");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(inner));
    }

    #[test]
    fn closest_marker_wins_outer_codex_inner_git() {
        let root = temp_dir("outer-codex-inner-git");
        fs::create_dir(root.join(".codex")).expect("create outer .codex");
        let inner = root.join("packages").join("tool");
        fs::create_dir_all(inner.join(".git")).expect("create inner .git");
        let cwd = inner.join("src");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(inner));
    }

    #[test]
    fn closest_marker_wins_outer_codex_inner_claude() {
        let root = temp_dir("outer-codex-inner-claude");
        fs::create_dir(root.join(".codex")).expect("create outer .codex");
        let inner = root.join("packages").join("tool");
        fs::create_dir_all(inner.join(".claude")).expect("create inner .claude");
        let cwd = inner.join("src");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(inner));
    }

    #[test]
    fn find_project_root_with_both_claude_and_codex_at_same_root() {
        let root = temp_dir("claude-and-codex");
        fs::create_dir(root.join(".claude")).expect("create .claude");
        fs::create_dir(root.join(".codex")).expect("create .codex");
        let cwd = root.join("src");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(root));
    }

    #[test]
    fn test_load_project_config_found() {
        let dir = temp_dir("project-config-found");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("longline.yaml"),
            "override_safety_level: strict\n",
        )
        .unwrap();

        let result = load_project_config(&dir).unwrap();
        assert!(result.is_some());
        let config = result.unwrap();
        assert_eq!(config.override_safety_level, Some(SafetyLevel::Strict));
    }

    #[test]
    fn test_load_project_config_not_found() {
        let dir = temp_dir("project-config-not-found");
        fs::create_dir_all(dir.join(".git")).unwrap();

        let result = load_project_config(&dir).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_project_config_read_error_returns_none() {
        let dir = temp_dir("project-config-read-error");
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::create_dir_all(dir.join(".claude").join("longline.yaml")).unwrap();

        let result = load_project_config(&dir).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_project_config_walks_up() {
        let dir = temp_dir("project-config-walks-up");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("longline.yaml"),
            "override_safety_level: critical\n",
        )
        .unwrap();

        let sub = dir.join("src").join("deep");
        fs::create_dir_all(&sub).unwrap();

        let result = load_project_config(&sub).unwrap();
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().override_safety_level,
            Some(SafetyLevel::Critical)
        );
    }

    #[test]
    fn test_load_project_config_rejects_unknown_fields() {
        let dir = temp_dir("project-config-unknown-fields");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("longline.yaml"),
            "allowlist:\n  commands:\n    - docker\n",
        )
        .unwrap();

        let result = load_project_config(&dir);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("unknown field"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_load_global_config_found() {
        let home = temp_dir("global-config-found");
        let config_dir = home.join(".config").join("longline");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join("longline.yaml"),
            "override_safety_level: strict\n",
        )
        .unwrap();

        let result = load_global_config(&home).unwrap();
        assert!(result.is_some());
        let config = result.unwrap();
        assert_eq!(config.override_safety_level, Some(SafetyLevel::Strict));
    }

    #[test]
    fn test_load_global_config_not_found() {
        let home = temp_dir("global-config-not-found");
        let result = load_global_config(&home).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_global_config_read_error_returns_none() {
        let home = temp_dir("global-config-read-error");
        fs::create_dir_all(home.join(".config").join("longline").join("longline.yaml")).unwrap();

        let result = load_global_config(&home).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_global_config_rejects_unknown_fields() {
        let home = temp_dir("global-config-unknown-fields");
        let config_dir = home.join(".config").join("longline");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join("longline.yaml"), "unknown_field: true\n").unwrap();

        let result = load_global_config(&home);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_project_config_rejects_prompt_missing_placeholder_code() {
        let repo = temp_dir("project-prompt-missing-code");
        fs::create_dir(repo.join(".git")).unwrap();
        fs::create_dir(repo.join(".claude")).unwrap();
        let yaml = "ai_judge:\n  prompt: |\n    has {language} and {cwd} but missing\n";
        fs::write(repo.join(".claude").join("longline.yaml"), yaml).unwrap();
        let err = load_project_config(&repo).unwrap_err();
        assert!(
            err.contains("missing required placeholder: {code}"),
            "got: {err}"
        );
        assert!(err.contains("{language}, {code}, {cwd}"), "got: {err}");
    }

    #[test]
    fn test_load_project_config_rejects_prompt_missing_placeholder_cwd() {
        let repo = temp_dir("project-prompt-missing-cwd");
        fs::create_dir(repo.join(".git")).unwrap();
        fs::create_dir(repo.join(".claude")).unwrap();
        let yaml = "ai_judge:\n  prompt: |\n    has {language} and {code} but missing\n";
        fs::write(repo.join(".claude").join("longline.yaml"), yaml).unwrap();
        let err = load_project_config(&repo).unwrap_err();
        assert!(
            err.contains("missing required placeholder: {cwd}"),
            "got: {err}"
        );
    }

    #[test]
    fn test_load_project_config_accepts_prompt_with_all_required_placeholders() {
        let repo = temp_dir("project-prompt-valid");
        fs::create_dir(repo.join(".git")).unwrap();
        fs::create_dir(repo.join(".claude")).unwrap();
        let yaml = "ai_judge:\n  prompt: |\n    {language} {code} {cwd}\n";
        fs::write(repo.join(".claude").join("longline.yaml"), yaml).unwrap();
        let config = load_project_config(&repo).unwrap().unwrap();
        assert!(config.ai_judge.unwrap().prompt.unwrap().contains("{code}"));
    }

    #[test]
    fn test_load_project_config_accepts_whitespace_only_prompt_without_validation() {
        // Whitespace-only prompts are coerced to None in finalize_config, not the loader.
        // The loader skips placeholder validation for whitespace-only input.
        let repo = temp_dir("project-prompt-whitespace");
        fs::create_dir(repo.join(".git")).unwrap();
        fs::create_dir(repo.join(".claude")).unwrap();
        let yaml = "ai_judge:\n  prompt: \"   \\n  \"\n";
        fs::write(repo.join(".claude").join("longline.yaml"), yaml).unwrap();
        let result = load_project_config(&repo);
        assert!(
            result.is_ok(),
            "whitespace-only prompt should not fail loader: {:?}",
            result
        );
    }

    #[test]
    fn test_load_global_config_rejects_ai_judge_prompt() {
        let home = temp_dir("global-prompt-rejected");
        let config_dir = home.join(".config").join("longline");
        fs::create_dir_all(&config_dir).unwrap();
        let yaml = "ai_judge:\n  prompt: |\n    {language} {code} {cwd}\n";
        fs::write(config_dir.join("longline.yaml"), yaml).unwrap();
        let err = load_global_config(&home).unwrap_err();
        assert!(
            err.contains("ai_judge.prompt is not allowed in global config"),
            "expected global-rejection error, got: {err}"
        );
    }
}
