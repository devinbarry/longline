//! Single shared home resolver. `HOME` unset AND `HOME=""` both fall back to
//! `/tmp` (the historical config fallback). Used by config-path lookup and by
//! `~`-expansion of provider argv tokens, so the two can never diverge.

use std::path::PathBuf;

/// Resolve `$HOME`, treating unset and empty identically. Fallback `/tmp`.
pub fn home_dir() -> PathBuf {
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => PathBuf::from(h),
        _ => PathBuf::from("/tmp"),
    }
}

/// Expand a single argv token: `~` → home, `~/x` → home/x. No other token form
/// is touched (no `$VAR`, globs, braces) — shlex output is otherwise verbatim.
pub fn expand_tilde_token(token: &str) -> String {
    if token == "~" {
        return home_dir().to_string_lossy().into_owned();
    }
    if let Some(rest) = token.strip_prefix("~/") {
        return home_dir().join(rest).to_string_lossy().into_owned();
    }
    token.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn home_unset_falls_back_to_tmp() {
        let _g = env_lock().lock().unwrap();
        let prev = std::env::var_os("HOME");
        std::env::remove_var("HOME");
        assert_eq!(home_dir(), std::path::PathBuf::from("/tmp"));
        if let Some(p) = prev {
            std::env::set_var("HOME", p);
        }
    }

    #[test]
    fn home_empty_falls_back_to_tmp() {
        let _g = env_lock().lock().unwrap();
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", "");
        assert_eq!(home_dir(), std::path::PathBuf::from("/tmp"));
        match prev {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn expands_tilde_slash_against_home() {
        let _g = env_lock().lock().unwrap();
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", "/home/u");
        assert_eq!(expand_tilde_token("~/.config/x"), "/home/u/.config/x");
        assert_eq!(expand_tilde_token("~"), "/home/u");
        assert_eq!(expand_tilde_token("/abs/path"), "/abs/path");
        assert_eq!(expand_tilde_token("nottilde~"), "nottilde~");
        match prev {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
    }
}
