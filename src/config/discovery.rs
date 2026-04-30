use std::path::{Path, PathBuf};

pub fn default_rules_path(home: &Path) -> PathBuf {
    home.join(".config").join("longline").join("rules.yaml")
}

pub fn global_config_path(home: &Path) -> PathBuf {
    home.join(".config").join("longline").join("longline.yaml")
}

pub fn project_config_path(project_root: &Path) -> PathBuf {
    project_root.join(".claude").join("longline.yaml")
}

pub fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    let mut current = cwd.to_path_buf();
    loop {
        if current.join(".git").exists() || current.join(".claude").is_dir() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

pub fn existing_project_config_path(cwd: &Path) -> Option<PathBuf> {
    find_project_root(cwd)
        .map(|root| project_config_path(&root))
        .filter(|path| path.exists())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("longline-{name}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn default_rules_path_uses_config_longline_rules_yaml() {
        assert_eq!(
            default_rules_path(Path::new("/tmp/home")),
            PathBuf::from("/tmp/home/.config/longline/rules.yaml")
        );
    }

    #[test]
    fn global_config_path_uses_config_longline_yaml() {
        assert_eq!(
            global_config_path(Path::new("/tmp/home")),
            PathBuf::from("/tmp/home/.config/longline/longline.yaml")
        );
    }

    #[test]
    fn project_config_path_uses_claude_longline_yaml() {
        assert_eq!(
            project_config_path(Path::new("/repo")),
            PathBuf::from("/repo/.claude/longline.yaml")
        );
    }

    #[test]
    fn find_project_root_with_git_directory() {
        let root = temp_dir("git-dir");
        fs::create_dir(root.join(".git")).expect("create .git dir");
        let cwd = root.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(root));
    }

    #[test]
    fn find_project_root_with_git_worktree_file() {
        let root = temp_dir("git-file");
        fs::write(root.join(".git"), "gitdir: /tmp/worktrees/repo\n").expect("write .git file");
        let cwd = root.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(root));
    }

    #[test]
    fn find_project_root_with_claude_directory() {
        let root = temp_dir("claude-dir");
        fs::create_dir(root.join(".claude")).expect("create .claude dir");
        let cwd = root.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(root));
    }

    #[test]
    fn closest_marker_wins_when_outer_has_git_and_inner_has_claude() {
        let root = temp_dir("closest-marker");
        fs::create_dir(root.join(".git")).expect("create .git dir");
        let inner = root.join("packages").join("tool");
        fs::create_dir_all(inner.join(".claude")).expect("create .claude dir");
        let cwd = inner.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), Some(inner));
    }

    #[test]
    fn no_root_when_markers_absent() {
        let root = temp_dir("no-markers");
        let cwd = root.join("src").join("nested");
        fs::create_dir_all(&cwd).expect("create cwd");

        assert_eq!(find_project_root(&cwd), None);
    }
}
