use std::path::Path;

use crate::config::overlays::ProjectConfig;

pub fn validate_ai_judge_prompt(prompt: &str, config_path: &Path) -> Result<(), String> {
    if prompt.trim().is_empty() {
        return Ok(());
    }
    const REQUIRED: &[&str] = &["{language}", "{code}", "{cwd}"];
    for placeholder in REQUIRED {
        if !prompt.contains(placeholder) {
            return Err(format!(
                "ai_judge.prompt at {} is missing required placeholder: {} (required placeholders: {{language}}, {{code}}, {{cwd}})",
                config_path.display(),
                placeholder
            ));
        }
    }
    Ok(())
}

pub fn validate_project_ai_judge_prompt(
    config: &ProjectConfig,
    config_path: &Path,
) -> Result<(), String> {
    if let Some(prompt) = config.ai_judge.as_ref().and_then(|a| a.prompt.as_deref()) {
        validate_ai_judge_prompt(prompt, config_path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ai_judge_prompt_rejects_missing_placeholder_code() {
        let path = Path::new("/repo/.claude/longline.yaml");
        let err =
            validate_ai_judge_prompt("has {language} and {cwd} but missing", path).unwrap_err();
        assert!(
            err.contains("missing required placeholder: {code}"),
            "got: {err}"
        );
        assert!(err.contains("{language}, {code}, {cwd}"), "got: {err}");
    }

    #[test]
    fn test_validate_ai_judge_prompt_rejects_missing_placeholder_cwd() {
        let path = Path::new("/repo/.claude/longline.yaml");
        let err =
            validate_ai_judge_prompt("has {language} and {code} but missing", path).unwrap_err();
        assert!(
            err.contains("missing required placeholder: {cwd}"),
            "got: {err}"
        );
    }

    #[test]
    fn test_validate_ai_judge_prompt_accepts_all_required_placeholders() {
        let path = Path::new("/repo/.claude/longline.yaml");
        validate_ai_judge_prompt("{language} {code} {cwd}", path).unwrap();
    }

    #[test]
    fn test_validate_ai_judge_prompt_accepts_whitespace_only_prompt() {
        let path = Path::new("/repo/.claude/longline.yaml");
        validate_ai_judge_prompt("   \n  ", path).unwrap();
    }

    #[test]
    fn test_validate_project_ai_judge_prompt_validates_prompt() {
        let yaml = "ai_judge:\n  prompt: |\n    has {language} and {cwd} but missing\n";
        let config: ProjectConfig = serde_norway::from_str(yaml).unwrap();
        let err =
            validate_project_ai_judge_prompt(&config, Path::new("/repo/.claude/longline.yaml"))
                .unwrap_err();
        assert!(
            err.contains("missing required placeholder: {code}"),
            "got: {err}"
        );
    }
}
