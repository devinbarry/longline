use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub(crate) fn audit_log_dir(home: &Path) -> PathBuf {
    home.join(".codex").join("hooks-logs")
}

#[allow(dead_code)]
pub(crate) fn audit_log_path(home: &Path) -> PathBuf {
    audit_log_dir(home).join("longline.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_path_uses_codex_hooks_logs_location() {
        assert_eq!(
            audit_log_path(Path::new("/tmp/home")),
            PathBuf::from("/tmp/home/.codex/hooks-logs/longline.jsonl")
        );
    }
}
