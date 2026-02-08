//! Configuration types for policy rules.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::types::Decision;

/// Manifest configuration that lists files to include.
#[derive(Debug, Deserialize)]
pub struct ManifestConfig {
    pub version: u32,
    #[serde(default = "default_decision")]
    pub default_decision: Decision,
    #[serde(default = "default_safety_level")]
    pub safety_level: SafetyLevel,
    pub include: Vec<String>,
}

/// Partial rules config for individual files (no version/default_decision/safety_level).
#[derive(Debug, Deserialize)]
pub struct PartialRulesConfig {
    #[serde(default)]
    pub allowlists: Allowlists,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Information about a loaded rule file.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Will be exported in Task 8
pub struct LoadedFileInfo {
    pub name: String,
    pub allowlist_count: usize,
    pub rule_count: usize,
}

/// Extended config with loading metadata.
#[derive(Debug)]
#[allow(dead_code)] // Will be exported in Task 8
pub struct LoadedConfig {
    pub config: RulesConfig,
    pub is_manifest: bool,
    pub manifest_path: Option<PathBuf>,
    pub files: Vec<LoadedFileInfo>,
}

/// Check if YAML content is a manifest (has `include:` key).
fn is_manifest(content: &str) -> bool {
    // Quick check without full parse - look for include: at start of line
    content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "include:" || trimmed.starts_with("include:")
    })
}

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

pub(crate) fn default_decision() -> Decision {
    Decision::Ask
}

pub(crate) fn default_safety_level() -> SafetyLevel {
    SafetyLevel::High
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafetyLevel {
    Critical,
    High,
    Strict,
}

impl std::fmt::Display for SafetyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            SafetyLevel::Critical => "critical",
            SafetyLevel::High => "high",
            SafetyLevel::Strict => "strict",
        })
    }
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
    Pipeline {
        pipeline: PipelineMatcher,
    },
    Redirect {
        redirect: RedirectMatcher,
    },
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
    #[serde(default)]
    pub none_of: Vec<String>,
    /// Match if any argument starts with any of these prefixes.
    /// Useful for combined short flags like -xf, -xvf matching "-x".
    #[serde(default)]
    pub starts_with: Vec<String>,
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

/// Per-project config loaded from `.claude/longline.yaml`.
/// All fields are optional; only specified fields override the global config.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Used in later tasks when wired into CLI
pub struct ProjectConfig {
    pub override_safety_level: Option<SafetyLevel>,
    pub allowlists: Option<Allowlists>,
    pub rules: Option<Vec<Rule>>,
    pub disable_rules: Option<Vec<String>>,
}

/// Walk up from `cwd` to find the project root.
/// Looks for `.git` or `.claude` directory.
#[allow(dead_code)] // Used in later tasks when wired into CLI
pub fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    let mut current = cwd.to_path_buf();
    loop {
        if current.join(".git").is_dir() || current.join(".claude").is_dir() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Load rules from a YAML file (manifest or monolithic).
pub fn load_rules(path: &Path) -> Result<RulesConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules file {}: {e}", path.display()))?;

    if is_manifest(&content) {
        load_manifest(path, &content)
    } else {
        let config: RulesConfig = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse rules file {}: {e}", path.display()))?;
        Ok(config)
    }
}

/// Load a manifest file and merge all included files.
fn load_manifest(manifest_path: &Path, content: &str) -> Result<RulesConfig, String> {
    let manifest: ManifestConfig = serde_yaml::from_str(content)
        .map_err(|e| format!("Failed to parse manifest {}: {e}", manifest_path.display()))?;

    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));

    let mut merged_allowlists: Vec<String> = Vec::new();
    let mut merged_rules: Vec<Rule> = Vec::new();

    for file_name in &manifest.include {
        let file_path = manifest_dir.join(file_name);
        let file_content = fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read included file {}: {e}", file_path.display()))?;

        let partial: PartialRulesConfig = serde_yaml::from_str(&file_content)
            .map_err(|e| format!("Failed to parse included file {}: {e}", file_path.display()))?;

        merged_allowlists.extend(partial.allowlists.commands);
        merged_rules.extend(partial.rules);
    }

    Ok(RulesConfig {
        version: manifest.version,
        default_decision: manifest.default_decision,
        safety_level: manifest.safety_level,
        allowlists: Allowlists {
            commands: merged_allowlists,
            paths: Vec::new(),
        },
        rules: merged_rules,
    })
}

/// Load rules with additional metadata about source files.
#[allow(dead_code)] // Will be exported in Task 8
pub fn load_rules_with_info(path: &Path) -> Result<LoadedConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules file {}: {e}", path.display()))?;

    if is_manifest(&content) {
        load_manifest_with_info(path, &content)
    } else {
        let config: RulesConfig = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse rules file {}: {e}", path.display()))?;
        Ok(LoadedConfig {
            is_manifest: false,
            manifest_path: None,
            files: vec![LoadedFileInfo {
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                allowlist_count: config.allowlists.commands.len(),
                rule_count: config.rules.len(),
            }],
            config,
        })
    }
}

#[allow(dead_code)] // Used by load_rules_with_info
fn load_manifest_with_info(manifest_path: &Path, content: &str) -> Result<LoadedConfig, String> {
    let manifest: ManifestConfig = serde_yaml::from_str(content)
        .map_err(|e| format!("Failed to parse manifest {}: {e}", manifest_path.display()))?;

    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));

    let mut merged_allowlists: Vec<String> = Vec::new();
    let mut merged_rules: Vec<Rule> = Vec::new();
    let mut files: Vec<LoadedFileInfo> = Vec::new();

    for file_name in &manifest.include {
        let file_path = manifest_dir.join(file_name);
        let file_content = fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read included file {}: {e}", file_path.display()))?;

        let partial: PartialRulesConfig = serde_yaml::from_str(&file_content)
            .map_err(|e| format!("Failed to parse included file {}: {e}", file_path.display()))?;

        files.push(LoadedFileInfo {
            name: file_name.clone(),
            allowlist_count: partial.allowlists.commands.len(),
            rule_count: partial.rules.len(),
        });

        merged_allowlists.extend(partial.allowlists.commands);
        merged_rules.extend(partial.rules);
    }

    Ok(LoadedConfig {
        config: RulesConfig {
            version: manifest.version,
            default_decision: manifest.default_decision,
            safety_level: manifest.safety_level,
            allowlists: Allowlists {
                commands: merged_allowlists,
                paths: Vec::new(),
            },
            rules: merged_rules,
        },
        is_manifest: true,
        manifest_path: Some(manifest_path.to_path_buf()),
        files,
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

    #[test]
    fn test_load_default_rules_file() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("rules")
            .join("manifest.yaml");
        let config = load_rules(&path).expect("Default rules should parse");
        assert!(
            config.rules.len() > 30,
            "Should have many rules, got {}",
            config.rules.len()
        );
        assert_eq!(config.version, 1);
        assert_eq!(config.default_decision, Decision::Ask);
    }

    #[test]
    fn test_detect_manifest_has_include() {
        let yaml = r#"
version: 1
default_decision: ask
safety_level: high
include:
  - core.yaml
  - git.yaml
"#;
        let config: ManifestConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.include.len(), 2);
        assert_eq!(config.include[0], "core.yaml");
    }

    #[test]
    fn test_partial_rules_config_no_version() {
        let yaml = r#"
allowlists:
  commands:
    - ls
    - cat
rules:
  - id: test-rule
    level: high
    match:
      command: rm
    decision: ask
    reason: "Test rule"
"#;
        let config: PartialRulesConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.allowlists.commands.len(), 2);
        assert_eq!(config.rules.len(), 1);
    }

    #[test]
    fn test_is_manifest_true_when_has_include() {
        let yaml = r#"
version: 1
include:
  - core.yaml
"#;
        assert!(is_manifest(yaml));
    }

    #[test]
    fn test_is_manifest_false_when_no_include() {
        let yaml = r#"
version: 1
rules: []
"#;
        assert!(!is_manifest(yaml));
    }

    #[test]
    fn test_load_manifest_merges_files() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();

        // Create manifest
        let manifest_path = dir.path().join("manifest.yaml");
        std::fs::write(
            &manifest_path,
            r#"
version: 1
default_decision: ask
safety_level: high
include:
  - core.yaml
  - git.yaml
"#,
        )
        .unwrap();

        // Create core.yaml
        std::fs::write(
            dir.path().join("core.yaml"),
            r#"
allowlists:
  commands:
    - ls
    - cat
rules: []
"#,
        )
        .unwrap();

        // Create git.yaml
        std::fs::write(
            dir.path().join("git.yaml"),
            r#"
allowlists:
  commands:
    - "git status"
rules:
  - id: git-force-push
    level: high
    match:
      command: git
      flags:
        any_of: ["--force"]
    decision: ask
    reason: "Force push"
"#,
        )
        .unwrap();

        let config = load_rules(&manifest_path).unwrap();
        assert_eq!(config.allowlists.commands.len(), 3); // ls, cat, git status
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "git-force-push");
    }

    #[test]
    fn test_load_manifest_error_on_missing_file() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();

        let manifest_path = dir.path().join("manifest.yaml");
        std::fs::write(
            &manifest_path,
            r#"
version: 1
include:
  - nonexistent.yaml
"#,
        )
        .unwrap();

        let result = load_rules(&manifest_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nonexistent.yaml"));
    }

    #[test]
    fn test_load_rules_backwards_compat_monolithic() {
        // Ensure existing monolithic files still work
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("rules")
            .join("manifest.yaml");
        let config = load_rules(&path).expect("Monolithic rules should still load");
        assert!(config.rules.len() > 100, "Should have many rules");
        assert!(
            config.allowlists.commands.len() > 100,
            "Should have many allowlist entries"
        );
    }

    #[test]
    fn test_loaded_config_tracks_files() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();

        let manifest_path = dir.path().join("manifest.yaml");
        std::fs::write(
            &manifest_path,
            r#"
version: 1
default_decision: ask
safety_level: high
include:
  - core.yaml
"#,
        )
        .unwrap();

        std::fs::write(
            dir.path().join("core.yaml"),
            r#"
allowlists:
  commands: [ls]
rules: []
"#,
        )
        .unwrap();

        let loaded = load_rules_with_info(&manifest_path).unwrap();
        assert!(loaded.is_manifest);
        assert_eq!(loaded.files.len(), 1);
        assert_eq!(loaded.files[0].name, "core.yaml");
        assert_eq!(loaded.files[0].allowlist_count, 1);
        assert_eq!(loaded.files[0].rule_count, 0);
    }

    #[test]
    fn test_project_config_all_fields() {
        let yaml = r#"
override_safety_level: strict

allowlists:
  commands:
    - "docker compose"

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
        let config: ProjectConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.override_safety_level, Some(SafetyLevel::Strict));
        assert_eq!(config.allowlists.as_ref().unwrap().commands.len(), 1);
        assert_eq!(config.rules.as_ref().unwrap().len(), 1);
        assert_eq!(config.disable_rules.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_project_config_empty() {
        let yaml = "{}";
        let config: ProjectConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.override_safety_level.is_none());
        assert!(config.allowlists.is_none());
        assert!(config.rules.is_none());
        assert!(config.disable_rules.is_none());
    }

    #[test]
    fn test_project_config_partial() {
        let yaml = "override_safety_level: critical\n";
        let config: ProjectConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.override_safety_level, Some(SafetyLevel::Critical));
        assert!(config.allowlists.is_none());
    }

    #[test]
    fn test_find_project_root_with_git() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();

        let result = find_project_root(&sub);
        assert_eq!(result, Some(dir.path().to_path_buf()));
    }

    #[test]
    fn test_find_project_root_with_claude_dir() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("src").join("deep");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        let result = find_project_root(&sub);
        assert_eq!(result, Some(dir.path().to_path_buf()));
    }

    #[test]
    fn test_find_project_root_none_when_missing() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let result = find_project_root(dir.path());
        assert!(result.is_none());
    }
}
