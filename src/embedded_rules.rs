//! Embedded default rules, compiled into the binary via include_str!().

const RULES_YAML: &str = include_str!("../rules/rules.yaml");
const CORE_ALLOWLIST: &str = include_str!("../rules/core-allowlist.yaml");
const GIT: &str = include_str!("../rules/git.yaml");
const CLI_TOOLS: &str = include_str!("../rules/cli-tools.yaml");
const CODEX: &str = include_str!("../rules/codex.yaml");
const FILESYSTEM: &str = include_str!("../rules/filesystem.yaml");
const SECRETS: &str = include_str!("../rules/secrets.yaml");
const DJANGO: &str = include_str!("../rules/django.yaml");
const PACKAGE_MANAGERS: &str = include_str!("../rules/package-managers.yaml");
const NETWORK: &str = include_str!("../rules/network.yaml");
const DOCKER: &str = include_str!("../rules/docker.yaml");
const SYSTEM: &str = include_str!("../rules/system.yaml");
const INTERPRETERS: &str = include_str!("../rules/interpreters.yaml");
const PYTHON: &str = include_str!("../rules/python.yaml");
const RUST: &str = include_str!("../rules/rust.yaml");
const NODE: &str = include_str!("../rules/node.yaml");
const JUST: &str = include_str!("../rules/just.yaml");

/// Look up an embedded rule file by name.
pub fn get(name: &str) -> Option<&'static str> {
    match name {
        "rules.yaml" => Some(RULES_YAML),
        "core-allowlist.yaml" => Some(CORE_ALLOWLIST),
        "git.yaml" => Some(GIT),
        "cli-tools.yaml" => Some(CLI_TOOLS),
        "codex.yaml" => Some(CODEX),
        "filesystem.yaml" => Some(FILESYSTEM),
        "secrets.yaml" => Some(SECRETS),
        "django.yaml" => Some(DJANGO),
        "package-managers.yaml" => Some(PACKAGE_MANAGERS),
        "network.yaml" => Some(NETWORK),
        "docker.yaml" => Some(DOCKER),
        "system.yaml" => Some(SYSTEM),
        "interpreters.yaml" => Some(INTERPRETERS),
        "python.yaml" => Some(PYTHON),
        "rust.yaml" => Some(RUST),
        "node.yaml" => Some(NODE),
        "just.yaml" => Some(JUST),
        _ => None,
    }
}

/// Return all embedded files as (name, content) pairs.
pub fn all_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("rules.yaml", RULES_YAML),
        ("core-allowlist.yaml", CORE_ALLOWLIST),
        ("git.yaml", GIT),
        ("cli-tools.yaml", CLI_TOOLS),
        ("codex.yaml", CODEX),
        ("filesystem.yaml", FILESYSTEM),
        ("secrets.yaml", SECRETS),
        ("django.yaml", DJANGO),
        ("package-managers.yaml", PACKAGE_MANAGERS),
        ("network.yaml", NETWORK),
        ("docker.yaml", DOCKER),
        ("system.yaml", SYSTEM),
        ("interpreters.yaml", INTERPRETERS),
        ("python.yaml", PYTHON),
        ("rust.yaml", RUST),
        ("node.yaml", NODE),
        ("just.yaml", JUST),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_rules_yaml() {
        let content = get("rules.yaml");
        assert!(content.is_some(), "rules.yaml must be embedded");
        assert!(content.unwrap().contains("include:"));
    }

    #[test]
    fn test_get_all_included_files() {
        let rules_yaml = get("rules.yaml").unwrap();
        for line in rules_yaml.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("- ") && trimmed.ends_with(".yaml") {
                let filename = trimmed.trim_start_matches("- ").trim();
                assert!(
                    get(filename).is_some(),
                    "Included file '{}' must be embedded",
                    filename
                );
            }
        }
    }

    #[test]
    fn test_get_nonexistent_returns_none() {
        assert!(get("nonexistent.yaml").is_none());
    }

    #[test]
    fn test_all_files_returns_all() {
        let files = all_files();
        assert!(
            files.len() >= 16,
            "Should have at least 16 files (rules.yaml + 15 includes)"
        );
        assert!(files.iter().any(|(name, _)| *name == "rules.yaml"));
    }
}
