use std::path::Path;

pub fn last_audit_entry(home: &Path, runtime: &str) -> serde_json::Value {
    let path = home
        .join(format!(".{runtime}"))
        .join("hooks-logs")
        .join("longline.jsonl");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let last = content
        .lines()
        .rfind(|line| !line.is_empty())
        .unwrap_or_else(|| panic!("no audit entries in {}", path.display()));
    serde_json::from_str(last)
        .unwrap_or_else(|error| panic!("invalid JSONL in {}: {error}", path.display()))
}

pub fn assert_audit_rule(entry: &serde_json::Value, expected_rule: Option<&str>, command: &str) {
    if let Some(rule) = expected_rule {
        assert!(
            entry["matched_rules"]
                .as_array()
                .is_some_and(|rules| rules.iter().any(|value| value == rule)),
            "expected audit entry to name {rule} for {command}: {entry}"
        );
    }
}
