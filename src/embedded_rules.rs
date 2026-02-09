//! Embedded default rules, compiled into the binary via include_str!().

const RULES_YAML: &str = include_str!("../rules/rules.yaml");
const CORE_ALLOWLIST: &str = include_str!("../rules/core-allowlist.yaml");
const GIT: &str = include_str!("../rules/git.yaml");
const CLI_TOOLS: &str = include_str!("../rules/cli-tools.yaml");
const FILESYSTEM: &str = include_str!("../rules/filesystem.yaml");
const SECRETS: &str = include_str!("../rules/secrets.yaml");
const DJANGO: &str = include_str!("../rules/django.yaml");
const PACKAGE_MANAGERS: &str = include_str!("../rules/package-managers.yaml");
const NETWORK: &str = include_str!("../rules/network.yaml");
const DOCKER: &str = include_str!("../rules/docker.yaml");
const SYSTEM: &str = include_str!("../rules/system.yaml");
const INTERPRETERS: &str = include_str!("../rules/interpreters.yaml");

/// Look up an embedded rule file by name.
pub fn get(name: &str) -> Option<&'static str> {
    match name {
        "rules.yaml" => Some(RULES_YAML),
        "core-allowlist.yaml" => Some(CORE_ALLOWLIST),
        "git.yaml" => Some(GIT),
        "cli-tools.yaml" => Some(CLI_TOOLS),
        "filesystem.yaml" => Some(FILESYSTEM),
        "secrets.yaml" => Some(SECRETS),
        "django.yaml" => Some(DJANGO),
        "package-managers.yaml" => Some(PACKAGE_MANAGERS),
        "network.yaml" => Some(NETWORK),
        "docker.yaml" => Some(DOCKER),
        "system.yaml" => Some(SYSTEM),
        "interpreters.yaml" => Some(INTERPRETERS),
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
        ("filesystem.yaml", FILESYSTEM),
        ("secrets.yaml", SECRETS),
        ("django.yaml", DJANGO),
        ("package-managers.yaml", PACKAGE_MANAGERS),
        ("network.yaml", NETWORK),
        ("docker.yaml", DOCKER),
        ("system.yaml", SYSTEM),
        ("interpreters.yaml", INTERPRETERS),
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
            files.len() >= 12,
            "Should have at least 12 files (rules.yaml + 11 includes)"
        );
        assert!(files.iter().any(|(name, _)| *name == "rules.yaml"));
    }
}
