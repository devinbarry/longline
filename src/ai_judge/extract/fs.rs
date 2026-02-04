use super::MAX_EXTRACTED_CODE_BYTES;

pub(super) fn read_safe_code_file(path: &str, cwd: &str) -> Option<String> {
    let path = expand_tilde(path)?;

    let cwd_root = std::fs::canonicalize(cwd).ok()?;
    let candidate = if std::path::Path::new(&path).is_absolute() {
        std::path::PathBuf::from(path)
    } else {
        cwd_root.join(path)
    };

    let candidate = std::fs::canonicalize(candidate).ok()?;
    if !is_under_allowed_root(&candidate, &cwd_root) && !is_under_temp_root(&candidate) {
        return None;
    }

    let meta = std::fs::metadata(&candidate).ok()?;
    if !meta.is_file() || meta.len() as usize > MAX_EXTRACTED_CODE_BYTES {
        return None;
    }
    let bytes = std::fs::read(&candidate).ok()?;
    if bytes.len() > MAX_EXTRACTED_CODE_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn is_under_allowed_root(path: &std::path::Path, root: &std::path::Path) -> bool {
    path.starts_with(root)
}

fn is_under_temp_root(path: &std::path::Path) -> bool {
    if path.starts_with(std::path::Path::new("/tmp")) {
        return true;
    }
    if let Ok(tmp) = std::fs::canonicalize("/tmp") {
        if path.starts_with(&tmp) {
            return true;
        }
    }
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        if let Ok(tmpdir) = std::fs::canonicalize(tmpdir) {
            if path.starts_with(&tmpdir) {
                return true;
            }
        }
    }
    false
}

fn expand_tilde(path: &str) -> Option<String> {
    if path == "~" {
        return std::env::var("HOME").ok();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").ok()?;
        return Some(
            std::path::Path::new(&home)
                .join(rest)
                .to_string_lossy()
                .to_string(),
        );
    }
    Some(path.to_string())
}
