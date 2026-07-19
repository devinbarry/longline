use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::overlays::{AllowlistEntry, Allowlists, RuleSource};
use crate::domain::Decision;

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

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
// Matchers are constructed at rules-load time and live for the life of the
// process; the size difference between the Command variant (with its
// `Option<ArgsMatcher>` containing several Vec<String>) and the smaller
// Pipeline/Redirect variants is not a hot-path concern.
#[allow(clippy::large_enum_variant)]
pub enum Matcher {
    Pipeline {
        pipeline: PipelineMatcher,
    },
    Redirect {
        redirect: RedirectMatcher,
    },
    GitConfig {
        git_config: GitConfigMatcher,
    },
    Command {
        command: StringOrList,
        #[serde(default)]
        flags: Option<FlagsMatcher>,
        #[serde(default)]
        args: Option<ArgsMatcher>,
        /// Match against environment-variable assignments on the command
        /// (`VAR=val cmd …`). Used by rules that deny RCE-channel git env
        /// vars (`GIT_SSH_COMMAND`, `GIT_EDITOR`, `GIT_CONFIG_KEY_n`, …).
        #[serde(default)]
        env: Option<EnvMatcher>,
    },
}

/// Structural matcher for Git's command-line config override records.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitConfigMatcher {
    pub command: StringOrList,
    pub source: GitConfigSource,
    pub keys: Vec<String>,
    #[serde(default)]
    pub key_case_insensitive: bool,
    pub except_value_class: EnvValueClass,
}

/// Canonical source of Git config overrides understood by policy matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitConfigSource {
    CliC,
}

impl std::fmt::Display for GitConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            GitConfigSource::CliC => "cli-c",
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineMatcher {
    pub stages: Vec<StageMatcher>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StageMatcher {
    pub command: StringOrList,
    #[serde(default)]
    pub flags: Option<FlagsMatcher>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedirectMatcher {
    #[serde(default)]
    pub op: Option<StringOrList>,
    #[serde(default)]
    pub target: Option<StringOrList>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvMatcher {
    /// Match if any env-var assignment's name matches one of these glob
    /// patterns. Useful for blocking RCE-channel env vars like
    /// `GIT_SSH_COMMAND`, `GIT_EDITOR`, `GIT_CONFIG_KEY_*`.
    #[serde(default)]
    pub any_of: Vec<String>,
    /// When true, lowercase both pattern and env-var name before matching.
    /// Defaults to false. Most env var names are conventionally uppercase
    /// but some tools/users use mixed case so case-insensitive is usually
    /// what you want.
    #[serde(default)]
    pub case_insensitive: bool,
    /// Candidate assignments that are safe for a narrowly defined value
    /// class. Exceptions are evaluated against the same assignment that
    /// matched `any_of`; they cannot suppress a dangerous sibling.
    #[serde(default)]
    pub except: Vec<EnvException>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvException {
    /// Env-var name patterns eligible for this exception.
    pub names: Vec<String>,
    /// Case sensitivity for `names`, independent of the parent matcher's
    /// `case_insensitive` setting.
    #[serde(default)]
    pub name_case_insensitive: bool,
    pub value_class: EnvValueClass,
}

/// Serde-facing safe-value classes supported by environment exceptions.
/// Policy matching maps these exhaustively to its private predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvValueClass {
    ShellNoop,
}

impl std::fmt::Display for EnvValueClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            EnvValueClass::ShellNoop => "shell-noop",
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgsMatcher {
    #[serde(default)]
    pub any_of: Vec<String>,
    /// All of these patterns must match some argument. Useful for scoping
    /// a rule to a specific subcommand alongside `any_of` value patterns,
    /// e.g. require `config` AND any of the corrupting flag names.
    #[serde(default)]
    pub all_of: Vec<String>,
    /// None of these patterns may match any argument. Used to exclude a
    /// rule from firing in unrelated contexts — e.g. the `-c` RCE rules
    /// should NOT fire on `git config <key>` invocations (the persistent
    /// form has its own spaceform/joinedform rules with proper read
    /// carve-outs).
    #[serde(default)]
    pub none_of: Vec<String>,
    /// Like `none_of` but checks ONLY the first argv token (the
    /// subcommand position for `<wrapper> <subcommand> <args...>`
    /// invocations). Use this when you want to scope a rule away from a
    /// specific subcommand without accidentally suppressing the rule on
    /// invocations where the same word appears as a positional argument
    /// later in argv. Patterns are literal exact-match (no glob).
    ///
    /// NOTE: `argv_first_not` matches the RAW `argv.first()`, whereas
    /// `subcommand` (below) matches the GLOBAL-STRIPPED effective
    /// subcommand. They intentionally diverge on `git -C x checkout`:
    /// `argv_first_not` sees `-C`, `subcommand` sees `checkout`. This is
    /// deliberate — `argv_first_not` only excludes a known-leading token
    /// (its callers never pass globaled forms), while `subcommand`
    /// positively pins a gate that must survive git global options.
    #[serde(default)]
    pub argv_first_not: Vec<String>,
    /// Positively pin the rule to the command's *effective subcommand* —
    /// the first positional after stripping leading global value-flag
    /// pairs (git's `-C`/`-c`/`--git-dir`/…, codex's `--profile`/…, known
    /// wrapper value-flags). Unlike `any_of`/`all_of` (bag-of-words over
    /// ALL argv tokens), this matches ONLY the resolved subcommand, so a
    /// rule pinned to `subcommand: [push]` does not false-fire on
    /// `git log --grep push`. Literal exact-match (no glob); honors
    /// `case_insensitive`.
    ///
    /// Gate-biased on ambiguity (`SubcommandResolution`, see
    /// `policy::matching::resolve_subcommand`): when a global value-flag's
    /// value is a shell expansion (`git -C "$REPO" …`) the subcommand is
    /// `Ambiguous` and MATCHES ANY pin, but only when the rule has another
    /// discriminator that also matched (a `flags` or `args` any_of/all_of/
    /// none_of constraint) — over-ask for destructive-flag gates. When there
    /// is no positional subcommand at all (`git --version`) it is `Absent`
    /// and matches NO pin.
    #[serde(default)]
    pub subcommand: Vec<String>,
    /// When true, lowercase both pattern and argument before matching.
    /// Used for git config keys whose section / variable names are
    /// case-insensitive (e.g. `core.sshCommand` ≡ `CORE.SSHCOMMAND`).
    /// Defaults to false to preserve existing case-sensitive semantics.
    #[serde(default)]
    pub case_insensitive: bool,
    /// If set, the rule only matches when the argv length **from the effective
    /// subcommand onward** is `>= min_args` — leading global value-flag pairs
    /// (`git -C <path>` / `--git-dir <path>`) and boolean globals are stripped
    /// first (via `subcommand_start_index`) so they don't inflate the count.
    /// Used to distinguish `git config <key>` (a read, effective len 2) from
    /// `git config <key> <value>` (a set, effective len 3) — including under
    /// `git -C <path> config <key>`, which raw `argv.len()` would over-count.
    #[serde(default)]
    pub min_args: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
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

/// Load rules from a YAML file (manifest or monolithic).
pub fn load_rules(path: &Path) -> Result<RulesConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules file {}: {e}", path.display()))?;

    if is_rules_manifest(&content) {
        load_rules_manifest(path, &content)
    } else {
        let config: RulesConfig = serde_norway::from_str(&content)
            .map_err(|e| format!("Failed to parse rules file {}: {e}", path.display()))?;
        Ok(config)
    }
}

/// Load a rules manifest file and merge all included files.
fn load_rules_manifest(manifest_path: &Path, content: &str) -> Result<RulesConfig, String> {
    let manifest: RulesManifestConfig = serde_norway::from_str(content)
        .map_err(|e| format!("Failed to parse manifest {}: {e}", manifest_path.display()))?;

    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));

    let mut merged_allowlists: Vec<AllowlistEntry> = Vec::new();
    let mut merged_rules: Vec<Rule> = Vec::new();

    for file_name in &manifest.include {
        let file_path = manifest_dir.join(file_name);
        let file_content = fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read included file {}: {e}", file_path.display()))?;

        let partial: PartialRulesConfig = serde_norway::from_str(&file_content)
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

    let manifest: RulesManifestConfig = serde_norway::from_str(content)
        .map_err(|e| format!("Failed to parse embedded rules.yaml: {e}"))?;

    let mut merged_allowlists: Vec<AllowlistEntry> = Vec::new();
    let mut merged_rules: Vec<Rule> = Vec::new();

    for file_name in &manifest.include {
        let file_content = crate::embedded_rules::get(file_name)
            .ok_or_else(|| format!("Embedded file '{}' not found", file_name))?;

        let partial: PartialRulesConfig = serde_norway::from_str(file_content)
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

    let manifest: RulesManifestConfig = serde_norway::from_str(content)
        .map_err(|e| format!("Failed to parse embedded rules.yaml: {e}"))?;

    let mut merged_allowlists: Vec<AllowlistEntry> = Vec::new();
    let mut merged_rules: Vec<Rule> = Vec::new();
    let mut files: Vec<LoadedFileInfo> = Vec::new();

    for file_name in &manifest.include {
        let file_content = crate::embedded_rules::get(file_name)
            .ok_or_else(|| format!("Embedded file '{}' not found", file_name))?;

        let partial: PartialRulesConfig = serde_norway::from_str(file_content)
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
        let config: RulesConfig = serde_norway::from_str(&content)
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
    let manifest: RulesManifestConfig = serde_norway::from_str(content)
        .map_err(|e| format!("Failed to parse manifest {}: {e}", manifest_path.display()))?;

    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));

    let mut merged_allowlists: Vec<AllowlistEntry> = Vec::new();
    let mut merged_rules: Vec<Rule> = Vec::new();
    let mut files: Vec<LoadedFileInfo> = Vec::new();

    for file_name in &manifest.include {
        let file_path = manifest_dir.join(file_name);
        let file_content = fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read included file {}: {e}", file_path.display()))?;

        let partial: PartialRulesConfig = serde_norway::from_str(&file_content)
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
        let config: RulesConfig = serde_norway::from_str(yaml).unwrap();
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
        let config: RulesConfig = serde_norway::from_str(yaml).unwrap();
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
        let config: RulesConfig = serde_norway::from_str(yaml).unwrap();
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
        let config: RulesManifestConfig = serde_norway::from_str(yaml).unwrap();
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
        let config: PartialRulesConfig = serde_norway::from_str(yaml).unwrap();
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
        assert_eq!(config.allowlists.commands.len(), 3);
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
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Minimal < TrustLevel::Standard);
        assert!(TrustLevel::Standard < TrustLevel::Full);
        assert!(TrustLevel::Minimal < TrustLevel::Full);
    }

    #[test]
    fn test_trust_level_deserialize() {
        let level: TrustLevel = serde_norway::from_str("minimal").unwrap();
        assert_eq!(level, TrustLevel::Minimal);
        let level: TrustLevel = serde_norway::from_str("standard").unwrap();
        assert_eq!(level, TrustLevel::Standard);
        let level: TrustLevel = serde_norway::from_str("full").unwrap();
        assert_eq!(level, TrustLevel::Full);
    }

    #[test]
    fn test_rules_config_trust_level_default() {
        let yaml = "version: 1\nallowlists:\n  commands: []\nrules: []\n";
        let config: RulesConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.trust_level, TrustLevel::Standard);
    }

    #[test]
    fn test_rules_config_trust_level_explicit() {
        let yaml = "version: 1\ntrust_level: minimal\nallowlists:\n  commands: []\nrules: []\n";
        let config: RulesConfig = serde_norway::from_str(yaml).unwrap();
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
    fn test_stage_matcher_with_flags_deserialization() {
        let yaml = r#"
version: 1
rules:
  - id: pipe-with-flags
    level: critical
    match:
      pipeline:
        stages:
          - command:
              any_of: [curl, wget]
          - command:
              any_of: [python, python3]
            flags:
              none_of: ["-m", "-c"]
    decision: deny
    reason: "Test rule"
"#;
        let config: RulesConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "pipe-with-flags");
        if let Matcher::Pipeline { ref pipeline } = config.rules[0].matcher {
            assert!(pipeline.stages[0].flags.is_none());
            let flags = pipeline.stages[1]
                .flags
                .as_ref()
                .expect("second stage should have flags");
            assert_eq!(flags.none_of, vec!["-m", "-c"]);
        } else {
            panic!("Expected pipeline matcher");
        }
    }

    #[test]
    fn test_stage_matcher_without_flags_still_works() {
        let yaml = r#"
version: 1
rules:
  - id: pipe-no-flags
    level: critical
    match:
      pipeline:
        stages:
          - command:
              any_of: [curl, wget]
          - command:
              any_of: [sh, bash]
    decision: deny
    reason: "Test rule"
"#;
        let config: RulesConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.rules.len(), 1);
    }

    #[test]
    fn env_matcher_deserializes_value_aware_exceptions_and_defaults_empty() {
        let with_exception: EnvMatcher = serde_norway::from_str(
            r#"
case_insensitive: true
any_of: [GIT_SSH_COMMAND, GIT_EDITOR, GIT_SEQUENCE_EDITOR, EDITOR, VISUAL]
except:
  - names: [GIT_EDITOR, GIT_SEQUENCE_EDITOR, EDITOR, VISUAL]
    name_case_insensitive: false
    value_class: shell-noop
"#,
        )
        .unwrap();

        assert!(with_exception.case_insensitive);
        assert_eq!(with_exception.except.len(), 1);
        assert_eq!(
            with_exception.except[0].names,
            ["GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "EDITOR", "VISUAL"]
        );
        assert!(!with_exception.except[0].name_case_insensitive);
        assert_eq!(
            with_exception.except[0].value_class,
            EnvValueClass::ShellNoop
        );

        let without_exception: EnvMatcher =
            serde_norway::from_str("any_of: [GIT_EDITOR]\n").unwrap();
        assert!(without_exception.except.is_empty());

        let default_exception_case: EnvMatcher = serde_norway::from_str(
            r#"
any_of: [GIT_EDITOR]
except:
  - names: [GIT_EDITOR]
    value_class: shell-noop
"#,
        )
        .unwrap();
        assert!(!default_exception_case.except[0].name_case_insensitive);
    }

    #[test]
    fn env_matcher_rejects_unknown_schema_fields_and_value_classes() {
        let unknown_matcher_field = r#"
any_of: [GIT_EDITOR]
unexpected: true
"#;
        assert!(serde_norway::from_str::<EnvMatcher>(unknown_matcher_field).is_err());

        let unknown_exception_field = r#"
any_of: [GIT_EDITOR]
except:
  - names: [GIT_EDITOR]
    value_class: shell-noop
    unexpected: true
"#;
        assert!(serde_norway::from_str::<EnvMatcher>(unknown_exception_field).is_err());

        let unknown_value_class = r#"
any_of: [GIT_EDITOR]
except:
  - names: [GIT_EDITOR]
    value_class: arbitrary-program
"#;
        assert!(serde_norway::from_str::<EnvMatcher>(unknown_value_class).is_err());
    }

    #[test]
    fn git_config_matcher_is_a_unique_untagged_variant_and_preserves_old_variants() {
        let yaml = r#"
version: 1
rules:
  - id: structural-git-config
    level: critical
    match:
      git_config:
        command: git
        source: cli-c
        keys: [core.editor, sequence.editor]
        key_case_insensitive: true
        except_value_class: shell-noop
    decision: deny
    reason: "Test structural matcher"
  - id: legacy-command
    level: high
    match:
      command: git
      args:
        any_of: [push]
    decision: ask
    reason: "Test command matcher"
  - id: legacy-redirect
    level: high
    match:
      redirect:
        target: /etc/hosts
    decision: ask
    reason: "Test redirect matcher"
"#;

        let config: RulesConfig = serde_norway::from_str(yaml).unwrap();
        let Matcher::GitConfig { git_config } = &config.rules[0].matcher else {
            panic!("expected structural git-config matcher");
        };
        assert!(git_config.command.matches("git"));
        assert_eq!(git_config.source, GitConfigSource::CliC);
        assert_eq!(git_config.keys, ["core.editor", "sequence.editor"]);
        assert!(git_config.key_case_insensitive);
        assert_eq!(git_config.except_value_class, EnvValueClass::ShellNoop);
        assert!(matches!(config.rules[1].matcher, Matcher::Command { .. }));
        assert!(matches!(config.rules[2].matcher, Matcher::Redirect { .. }));
    }

    #[test]
    fn git_config_matcher_defaults_key_case_and_rejects_schema_typos() {
        let minimal = r#"
git_config:
  command: git
  source: cli-c
  keys: [core.editor]
  except_value_class: shell-noop
"#;
        let matcher: Matcher = serde_norway::from_str(minimal).unwrap();
        let Matcher::GitConfig { git_config } = matcher else {
            panic!("git_config key must select only the structural variant");
        };
        assert!(!git_config.key_case_insensitive);

        for invalid in [
            r#"
git_config:
  command: git
  source: cli-c
  keys: [core.editor]
  except_value_class: shell-noop
  unexpected: true
"#,
            r#"
git_config:
  command: git
  source: persistent
  keys: [core.editor]
  except_value_class: shell-noop
"#,
            r#"
git_config:
  command: git
  source: cli-c
  keys: [core.editor]
  except_value_class: executable
"#,
        ] {
            assert!(
                serde_norway::from_str::<Matcher>(invalid).is_err(),
                "{invalid}"
            );
        }

        assert!(serde_norway::from_str::<Matcher>(minimal)
            .is_ok_and(|matcher| !matches!(matcher, Matcher::Command { .. })));

        let malformed_git_config_with_command_fallback = r#"
git_config:
  command: git
  source: persistent
  keys: [core.editor]
  except_value_class: shell-noop
command: rm
"#;
        assert!(
            serde_norway::from_str::<Matcher>(malformed_git_config_with_command_fallback).is_err(),
            "a malformed git_config block must not fall through to Command"
        );
    }
}
