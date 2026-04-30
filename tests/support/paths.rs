use std::path::PathBuf;

/// Path to the rules/rules.yaml file in the repo.
pub fn rules_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("rules")
        .join("rules.yaml")
        .to_string_lossy()
        .to_string()
}
