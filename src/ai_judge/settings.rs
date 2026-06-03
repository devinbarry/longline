pub const EMBEDDED: &str = include_str!("judge-claude-settings.json");

#[derive(Debug, PartialEq, Eq)]
pub enum SettingsOutcome {
    /// A validated file is present at `path`; spawn claude with `--settings <path>`.
    Ready,
    /// Could not place a valid file; caller must drop `--settings` + its path token
    /// and run with `--setting-sources ""` alone (records `settings_unavailable`).
    Unavailable,
}

/// HARD SAFETY RULE: content is safe iff it parses, `cleanupPeriodDays` is
/// present and >= 3650, and it carries no retention/cleanup/history key (other
/// than the pinned `cleanupPeriodDays`) and no write/delete-style key.
pub fn content_is_safe(s: &str) -> bool {
    let v: serde_json::Value = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let cleanup = v.get("cleanupPeriodDays").and_then(|x| x.as_i64());
    match cleanup {
        Some(n) if n >= 3650 => {}
        _ => return false,
    }
    is_inert_and_safe(&v)
}

pub fn is_inert_and_safe(v: &serde_json::Value) -> bool {
    let obj = match v.as_object() {
        Some(o) => o,
        None => return false,
    };
    // Allowlist the known-inert top-level keys; reject anything else.
    // Conservative: an unknown key -> reject.
    const ALLOWED: &[&str] = &[
        "includeCoAuthoredBy",
        "cleanupPeriodDays",
        "enableAllProjectMcpServers",
        "enabledPlugins",
        "env",
    ];
    obj.keys().all(|k| ALLOWED.contains(&k.as_str()))
}

/// Validate the on-disk file; atomically repair from EMBEDDED if missing/unsafe.
/// Atomic = write unique temp in the SAME dir, fsync, rename over target, fsync dir.
pub fn ensure_settings_file(path: &std::path::Path) -> SettingsOutcome {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if content_is_safe(&existing) {
            return SettingsOutcome::Ready;
        }
    }
    match atomic_write(path, EMBEDDED) {
        Ok(()) => SettingsOutcome::Ready,
        Err(_) => SettingsOutcome::Unavailable,
    }
}

fn atomic_write(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".judge-settings.{}.{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_pins_cleanup_3650_and_judge_active() {
        let v: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
        assert_eq!(v["cleanupPeriodDays"], 3650);
        assert_eq!(v["env"]["LONGLINE_JUDGE_ACTIVE"], "1");
        assert!(is_inert_and_safe(&v));
    }

    #[test]
    fn validate_rejects_missing_or_low_cleanup() {
        assert!(!content_is_safe("{}"));
        assert!(!content_is_safe(r#"{"cleanupPeriodDays": 1}"#));
        assert!(!content_is_safe(r#"{"cleanupPeriodDays": 3649}"#));
        assert!(content_is_safe(EMBEDDED));
    }

    #[test]
    fn validate_rejects_destructive_keys() {
        assert!(!content_is_safe(
            r#"{"cleanupPeriodDays":3650,"history":{"delete":true}}"#
        ));
    }

    #[test]
    fn ensure_repairs_a_tampered_file_by_atomic_replacement() {
        let dir = unique_tmp();
        let path = dir.join("judge-claude-settings.json");
        std::fs::write(&path, r#"{"cleanupPeriodDays":1}"#).unwrap();
        let outcome = ensure_settings_file(&path);
        assert!(matches!(outcome, SettingsOutcome::Ready));
        assert!(content_is_safe(&std::fs::read_to_string(&path).unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_writes_when_missing() {
        let dir = unique_tmp();
        let path = dir.join("nested/judge-claude-settings.json");
        let outcome = ensure_settings_file(&path);
        assert!(matches!(outcome, SettingsOutcome::Ready));
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_reports_unavailable_when_dir_unwritable() {
        let path = std::path::Path::new("/proc/longline-cannot-write/x.json");
        assert!(matches!(
            ensure_settings_file(path),
            SettingsOutcome::Unavailable
        ));
    }

    #[test]
    fn concurrent_repairs_both_leave_a_valid_file() {
        let dir = unique_tmp();
        let path = dir.join("judge-claude-settings.json");
        std::fs::write(&path, "garbage").unwrap();
        let p2 = path.clone();
        let h = std::thread::spawn(move || ensure_settings_file(&p2));
        let r1 = ensure_settings_file(&path);
        let r2 = h.join().unwrap();
        assert!(matches!(r1, SettingsOutcome::Ready));
        assert!(matches!(r2, SettingsOutcome::Ready));
        assert!(content_is_safe(&std::fs::read_to_string(&path).unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn unique_tmp() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join(format!("judge-settings-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
