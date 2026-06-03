#[test]
fn init_writes_judge_claude_settings_file() {
    let home = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_longline"))
        .arg("init")
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "init should exit 0: {:?}", out);
    let settings = home
        .path()
        .join(".config/longline/judge-claude-settings.json");
    assert!(
        settings.exists(),
        "init must write judge-claude-settings.json"
    );
    let content = std::fs::read_to_string(&settings).unwrap();
    // Safety-critical pin (kept verbatim from the embedded file).
    assert!(
        content.contains("\"cleanupPeriodDays\": 3650"),
        "settings must pin cleanupPeriodDays: 3650, got: {content}"
    );
}
