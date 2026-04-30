use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub(crate) fn audit_log_dir(home: &Path) -> PathBuf {
    home.join(".claude").join("hooks-logs")
}

#[allow(dead_code)]
pub(crate) fn audit_log_path(home: &Path) -> PathBuf {
    audit_log_dir(home).join("longline.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_path_uses_existing_claude_location() {
        assert_eq!(
            audit_log_path(Path::new("/tmp/home")),
            PathBuf::from("/tmp/home/.claude/hooks-logs/longline.jsonl")
        );
    }
}
