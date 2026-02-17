//! Configuration types for policy rules.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::types::Decision;

/// Tracks whether a rule/entry came from built-in defaults, global config, or project config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleSource {
    #[default]
    BuiltIn,
    Global,
    Project,
}

/// Rules manifest configuration that lists files to include.
#[derive(Debug, Deserialize)]
pub struct RulesManifestConfig {
    pub version: u32,
    #[serde(default = "default_decision")]
    pub default_decision: Decision,
    #[serde(default = "default_safety_level")]
    pub safety_level: SafetyLevel,
    #[serde(default)]
    pub trust_level: TrustLevel,
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
pub struct LoadedFileInfo {
    pub name: String,
    pub allowlist_count: usize,
    pub rule_count: usize,
    /// Trust tier breakdown: [minimal, standard, full]
    pub trust_counts: [usize; 3],
}

/// Extended config with loading metadata.
#[derive(Debug)]
pub struct LoadedConfig {
    pub config: RulesConfig,
    pub is_rules_manifest: bool,
    pub rules_manifest_path: Option<PathBuf>,
    pub files: Vec<LoadedFileInfo>,
}

/// Check if YAML content is a rules manifest (has `include:` key).
fn is_rules_manifest(content: &str) -> bool {
    // Quick check without full parse - look for include: at start of line
    content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "include:" || trimmed.starts_with("include:")
    })
}

/// Top-level rules configuration loaded from YAML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesConfig {
    #[allow(dead_code)]
    pub version: u32,
    #[serde(default = "default_decision")]
    pub default_decision: Decision,
    #[serde(default = "default_safety_level")]
    pub safety_level: SafetyLevel,
    #[serde(default)]
    pub trust_level: TrustLevel,
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    Minimal,
    #[default]
    Standard,
    Full,
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            TrustLevel::Minimal => "minimal",
            TrustLevel::Standard => "standard",
            TrustLevel::Full => "full",
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistEntry {
    pub command: String,
    pub trust: TrustLevel,
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

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub level: SafetyLevel,
    #[serde(rename = "match")]
    pub matcher: Matcher,
    pub decision: Decision,
    pub reason: String,
    #[serde(skip)]
    pub source: RuleSource,
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
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub override_safety_level: Option<SafetyLevel>,
    pub override_trust_level: Option<TrustLevel>,
    pub allowlists: Option<Allowlists>,
    pub rules: Option<Vec<Rule>>,
    pub disable_rules: Option<Vec<String>>,
}

/// Walk up from `cwd` to find the project root.
/// Looks for `.git` (directory or worktree file) or `.claude` directory.
pub fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    let mut current = cwd.to_path_buf();
    loop {
        // .git can be a directory (normal repo) or a file (worktree)
        if current.join(".git").exists() || current.join(".claude").is_dir() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Load project config from `.claude/longline.yaml` if it exists.
/// Walks up from `cwd` to find the project root first.
/// Returns Ok(None) if no project config file exists, Err on parse failure.
pub fn load_project_config(cwd: &Path) -> Result<Option<ProjectConfig>, String> {
    let root = match find_project_root(cwd) {
        Some(r) => r,
        None => return Ok(None),
    };
    let config_path = root.join(".claude").join("longline.yaml");
    let content = match fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Ok(None), // File doesn't exist
    };
    let config: ProjectConfig = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", config_path.display()))?;
    Ok(Some(config))
}

/// Load global config from `~/.config/longline/longline.yaml` if it exists.
/// Returns Ok(None) if no global config file exists, Err on parse failure.
pub fn load_global_config(home: &Path) -> Result<Option<ProjectConfig>, String> {
    let config_path = home.join(".config").join("longline").join("longline.yaml");
    let content = match fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let config: ProjectConfig = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", config_path.display()))?;
    Ok(Some(config))
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

/// Load rules from a YAML file (manifest or monolithic).
pub fn load_rules(path: &Path) -> Result<RulesConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules file {}: {e}", path.display()))?;

    if is_rules_manifest(&content) {
        load_rules_manifest(path, &content)
    } else {
        let config: RulesConfig = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse rules file {}: {e}", path.display()))?;
        Ok(config)
    }
}

/// Load a rules manifest file and merge all included files.
fn load_rules_manifest(manifest_path: &Path, content: &str) -> Result<RulesConfig, String> {
    let manifest: RulesManifestConfig = serde_yaml::from_str(content)
        .map_err(|e| format!("Failed to parse manifest {}: {e}", manifest_path.display()))?;

    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));

    let mut merged_allowlists: Vec<AllowlistEntry> = Vec::new();
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
        trust_level: manifest.trust_level,
        allowlists: Allowlists {
            commands: merged_allowlists,
            paths: Vec::new(),
        },
        rules: merged_rules,
    })
}

/// Load rules from embedded defaults (compiled into the binary).
pub fn load_embedded_rules() -> Result<RulesConfig, String> {
    let content = crate::embedded_rules::get("rules.yaml")
        .ok_or_else(|| "Embedded rules.yaml not found".to_string())?;

    let manifest: RulesManifestConfig = serde_yaml::from_str(content)
        .map_err(|e| format!("Failed to parse embedded rules.yaml: {e}"))?;

    let mut merged_allowlists: Vec<AllowlistEntry> = Vec::new();
    let mut merged_rules: Vec<Rule> = Vec::new();

    for file_name in &manifest.include {
        let file_content = crate::embedded_rules::get(file_name)
            .ok_or_else(|| format!("Embedded file '{}' not found", file_name))?;

        let partial: PartialRulesConfig = serde_yaml::from_str(file_content)
            .map_err(|e| format!("Failed to parse embedded file {}: {e}", file_name))?;

        merged_allowlists.extend(partial.allowlists.commands);
        merged_rules.extend(partial.rules);
    }

    Ok(RulesConfig {
        version: manifest.version,
        default_decision: manifest.default_decision,
        safety_level: manifest.safety_level,
        trust_level: manifest.trust_level,
        allowlists: Allowlists {
            commands: merged_allowlists,
            paths: Vec::new(),
        },
        rules: merged_rules,
    })
}

/// Load embedded rules with file metadata.
pub fn load_embedded_rules_with_info() -> Result<LoadedConfig, String> {
    let content = crate::embedded_rules::get("rules.yaml")
        .ok_or_else(|| "Embedded rules.yaml not found".to_string())?;

    let manifest: RulesManifestConfig = serde_yaml::from_str(content)
        .map_err(|e| format!("Failed to parse embedded rules.yaml: {e}"))?;

    let mut merged_allowlists: Vec<AllowlistEntry> = Vec::new();
    let mut merged_rules: Vec<Rule> = Vec::new();
    let mut files: Vec<LoadedFileInfo> = Vec::new();

    for file_name in &manifest.include {
        let file_content = crate::embedded_rules::get(file_name)
            .ok_or_else(|| format!("Embedded file '{}' not found", file_name))?;

        let partial: PartialRulesConfig = serde_yaml::from_str(file_content)
            .map_err(|e| format!("Failed to parse embedded file {}: {e}", file_name))?;

        let trust_counts = compute_trust_counts(&partial.allowlists.commands);
        files.push(LoadedFileInfo {
            name: file_name.clone(),
            allowlist_count: partial.allowlists.commands.len(),
            rule_count: partial.rules.len(),
            trust_counts,
        });

        merged_allowlists.extend(partial.allowlists.commands);
        merged_rules.extend(partial.rules);
    }

    Ok(LoadedConfig {
        config: RulesConfig {
            version: manifest.version,
            default_decision: manifest.default_decision,
            safety_level: manifest.safety_level,
            trust_level: manifest.trust_level,
            allowlists: Allowlists {
                commands: merged_allowlists,
                paths: Vec::new(),
            },
            rules: merged_rules,
        },
        is_rules_manifest: true,
        rules_manifest_path: None,
        files,
    })
}

/// Compute trust tier counts from a list of allowlist entries: [minimal, standard, full].
fn compute_trust_counts(commands: &[AllowlistEntry]) -> [usize; 3] {
    [
        commands
            .iter()
            .filter(|e| e.trust == TrustLevel::Minimal)
            .count(),
        commands
            .iter()
            .filter(|e| e.trust == TrustLevel::Standard)
            .count(),
        commands
            .iter()
            .filter(|e| e.trust == TrustLevel::Full)
            .count(),
    ]
}

/// Load rules with additional metadata about source files.
pub fn load_rules_with_info(path: &Path) -> Result<LoadedConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules file {}: {e}", path.display()))?;

    if is_rules_manifest(&content) {
        load_rules_manifest_with_info(path, &content)
    } else {
        let config: RulesConfig = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse rules file {}: {e}", path.display()))?;
        let trust_counts = compute_trust_counts(&config.allowlists.commands);
        Ok(LoadedConfig {
            is_rules_manifest: false,
            rules_manifest_path: None,
            files: vec![LoadedFileInfo {
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                allowlist_count: config.allowlists.commands.len(),
                rule_count: config.rules.len(),
                trust_counts,
            }],
            config,
        })
    }
}

fn load_rules_manifest_with_info(
    manifest_path: &Path,
    content: &str,
) -> Result<LoadedConfig, String> {
    let manifest: RulesManifestConfig = serde_yaml::from_str(content)
        .map_err(|e| format!("Failed to parse manifest {}: {e}", manifest_path.display()))?;

    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));

    let mut merged_allowlists: Vec<AllowlistEntry> = Vec::new();
    let mut merged_rules: Vec<Rule> = Vec::new();
    let mut files: Vec<LoadedFileInfo> = Vec::new();

    for file_name in &manifest.include {
        let file_path = manifest_dir.join(file_name);
        let file_content = fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read included file {}: {e}", file_path.display()))?;

        let partial: PartialRulesConfig = serde_yaml::from_str(&file_content)
            .map_err(|e| format!("Failed to parse included file {}: {e}", file_path.display()))?;

        let trust_counts = compute_trust_counts(&partial.allowlists.commands);
        files.push(LoadedFileInfo {
            name: file_name.clone(),
            allowlist_count: partial.allowlists.commands.len(),
            rule_count: partial.rules.len(),
            trust_counts,
        });

        merged_allowlists.extend(partial.allowlists.commands);
        merged_rules.extend(partial.rules);
    }

    Ok(LoadedConfig {
        config: RulesConfig {
            version: manifest.version,
            default_decision: manifest.default_decision,
            safety_level: manifest.safety_level,
            trust_level: manifest.trust_level,
            allowlists: Allowlists {
                commands: merged_allowlists,
                paths: Vec::new(),
            },
            rules: merged_rules,
        },
        is_rules_manifest: true,
        rules_manifest_path: Some(manifest_path.to_path_buf()),
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
    - { command: "git status", trust: standard }
    - { command: "git diff", trust: standard }
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
            .join("rules.yaml");
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
    fn test_detect_rules_manifest_has_include() {
        let yaml = r#"
version: 1
default_decision: ask
safety_level: high
include:
  - core.yaml
  - git.yaml
"#;
        let config: RulesManifestConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.include.len(), 2);
        assert_eq!(config.include[0], "core.yaml");
    }

    #[test]
    fn test_partial_rules_config_no_version() {
        let yaml = r#"
allowlists:
  commands:
    - { command: ls, trust: minimal }
    - { command: cat, trust: minimal }
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
    fn test_is_rules_manifest_true_when_has_include() {
        let yaml = r#"
version: 1
include:
  - core.yaml
"#;
        assert!(is_rules_manifest(yaml));
    }

    #[test]
    fn test_is_rules_manifest_false_when_no_include() {
        let yaml = r#"
version: 1
rules: []
"#;
        assert!(!is_rules_manifest(yaml));
    }

    #[test]
    fn test_load_rules_manifest_merges_files() {
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
    - { command: ls, trust: minimal }
    - { command: cat, trust: minimal }
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
    - { command: "git status", trust: standard }
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
    fn test_load_rules_manifest_error_on_missing_file() {
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
            .join("rules.yaml");
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
  commands:
    - { command: ls, trust: minimal }
rules: []
"#,
        )
        .unwrap();

        let loaded = load_rules_with_info(&manifest_path).unwrap();
        assert!(loaded.is_rules_manifest);
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
    fn test_find_project_root_with_git_worktree_file() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("src");
        std::fs::create_dir_all(&sub).unwrap();
        // In a worktree, .git is a file, not a directory
        std::fs::write(
            dir.path().join(".git"),
            "gitdir: /some/main/repo/.git/worktrees/branch",
        )
        .unwrap();

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

    #[test]
    fn test_load_project_config_found() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("longline.yaml"),
            "override_safety_level: strict\n",
        )
        .unwrap();

        let result = load_project_config(dir.path()).unwrap();
        assert!(result.is_some());
        let config = result.unwrap();
        assert_eq!(config.override_safety_level, Some(SafetyLevel::Strict));
    }

    #[test]
    fn test_load_project_config_not_found() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();

        let result = load_project_config(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_project_config_walks_up() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("longline.yaml"),
            "override_safety_level: critical\n",
        )
        .unwrap();

        let sub = dir.path().join("src").join("deep");
        std::fs::create_dir_all(&sub).unwrap();

        let result = load_project_config(&sub).unwrap();
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().override_safety_level,
            Some(SafetyLevel::Critical)
        );
    }

    #[test]
    fn test_load_project_config_rejects_unknown_fields() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        // "allowlist" is a typo for "allowlists"
        std::fs::write(
            claude_dir.join("longline.yaml"),
            "allowlist:\n  commands:\n    - docker\n",
        )
        .unwrap();

        let result = load_project_config(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("unknown field"),
            "Error should mention unknown field: {err}"
        );
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
                    source: RuleSource::default(),
                }],
                paths: vec![],
            }),
            rules: None,
            disable_rules: None,
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
        let project: ProjectConfig = serde_yaml::from_str(project_yaml).unwrap();
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
        };
        merge_project_config(&mut config, project);
        assert_eq!(config.safety_level, SafetyLevel::High);
        assert_eq!(config.allowlists.commands.len(), 1);
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Minimal < TrustLevel::Standard);
        assert!(TrustLevel::Standard < TrustLevel::Full);
        assert!(TrustLevel::Minimal < TrustLevel::Full);
    }

    #[test]
    fn test_trust_level_deserialize() {
        let level: TrustLevel = serde_yaml::from_str("minimal").unwrap();
        assert_eq!(level, TrustLevel::Minimal);
        let level: TrustLevel = serde_yaml::from_str("standard").unwrap();
        assert_eq!(level, TrustLevel::Standard);
        let level: TrustLevel = serde_yaml::from_str("full").unwrap();
        assert_eq!(level, TrustLevel::Full);
    }

    #[test]
    fn test_allowlist_entry_deserialize_tagged() {
        let yaml = "command: \"git status\"\ntrust: minimal\n";
        let entry: AllowlistEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.command, "git status");
        assert_eq!(entry.trust, TrustLevel::Minimal);
    }

    #[test]
    fn test_allowlist_entry_rejects_bare_string() {
        let result: Result<AllowlistEntry, _> = serde_yaml::from_str("ls");
        assert!(result.is_err(), "Bare strings should be rejected");
    }

    #[test]
    fn test_allowlist_entry_requires_trust_field() {
        let yaml = "command: \"ls\"\n";
        let result: Result<AllowlistEntry, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "Missing trust field should be rejected");
    }

    #[test]
    fn test_rules_config_trust_level_default() {
        let yaml = "version: 1\nallowlists:\n  commands: []\nrules: []\n";
        let config: RulesConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.trust_level, TrustLevel::Standard);
    }

    #[test]
    fn test_rules_config_trust_level_explicit() {
        let yaml = "version: 1\ntrust_level: minimal\nallowlists:\n  commands: []\nrules: []\n";
        let config: RulesConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.trust_level, TrustLevel::Minimal);
    }

    #[test]
    fn test_load_embedded_rules_matches_disk() {
        let disk_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("rules")
            .join("rules.yaml");
        let disk_config = load_rules(&disk_path).expect("Disk rules should load");
        let embedded_config = load_embedded_rules().expect("Embedded rules should load");

        assert_eq!(disk_config.version, embedded_config.version);
        assert_eq!(
            disk_config.default_decision,
            embedded_config.default_decision
        );
        assert_eq!(disk_config.safety_level, embedded_config.safety_level);
        assert_eq!(disk_config.trust_level, embedded_config.trust_level);
        assert_eq!(
            disk_config.allowlists.commands.len(),
            embedded_config.allowlists.commands.len(),
            "Allowlist count should match"
        );
        assert_eq!(
            disk_config.rules.len(),
            embedded_config.rules.len(),
            "Rule count should match"
        );
    }

    #[test]
    fn test_load_embedded_rules_with_info() {
        let loaded = load_embedded_rules_with_info().expect("Embedded rules with info should load");
        assert!(loaded.is_rules_manifest);
        assert!(
            loaded.rules_manifest_path.is_none(),
            "Embedded rules have no disk path"
        );
        assert!(
            loaded.files.len() >= 11,
            "Should have at least 11 included files"
        );
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
        let config: RulesConfig = serde_yaml::from_str(yaml).unwrap();
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
        let project: ProjectConfig = serde_yaml::from_str(project_yaml).unwrap();
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
                    source: RuleSource::default(),
                }],
                paths: vec![],
            }),
            rules: None,
            disable_rules: None,
        };
        merge_project_config(&mut config, project);
        assert_eq!(config.allowlists.commands[0].source, RuleSource::BuiltIn);
        assert_eq!(config.allowlists.commands[1].source, RuleSource::Project);
    }

    #[test]
    fn test_load_global_config_found() {
        use tempfile::TempDir;

        let home = TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "override_safety_level: strict\n",
        )
        .unwrap();

        let result = load_global_config(home.path()).unwrap();
        assert!(result.is_some());
        let config = result.unwrap();
        assert_eq!(config.override_safety_level, Some(SafetyLevel::Strict));
    }

    #[test]
    fn test_load_global_config_not_found() {
        use tempfile::TempDir;

        let home = TempDir::new().unwrap();
        let result = load_global_config(home.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_global_config_rejects_unknown_fields() {
        use tempfile::TempDir;

        let home = TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("longline.yaml"), "unknown_field: true\n").unwrap();

        let result = load_global_config(home.path());
        assert!(result.is_err());
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
        let overlay: ProjectConfig = serde_yaml::from_str(overlay_yaml).unwrap();
        merge_overlay_config(&mut config, overlay, RuleSource::Global);
        assert_eq!(config.allowlists.commands[0].source, RuleSource::Global);
        assert_eq!(config.rules[0].source, RuleSource::Global);
    }
}
