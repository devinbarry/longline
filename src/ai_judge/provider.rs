use crate::ai_judge::home::expand_tilde_token;

/// A provider = display name + parsed argv template. The prompt is appended as
/// the final arg at launch time (not stored here).
#[derive(Debug, Clone)]
pub struct Provider {
    pub name: String, // "codex" | "claude"
    pub argv: Vec<String>,
}

impl Provider {
    /// Parse a command string with shell quoting (shlex), then `~`-expand every
    /// token. Returns None when the string is empty/whitespace (absent) or
    /// shlex-unparseable (caller emits a config warning).
    pub fn parse(name: &str, command: &str) -> Option<Provider> {
        if command.trim().is_empty() {
            return None;
        }
        let parts = shlex::split(command)?; // None on unmatched quote
        if parts.is_empty() {
            return None;
        }
        let argv = parts.into_iter().map(|t| expand_tilde_token(&t)).collect();
        Some(Provider {
            name: name.to_string(),
            argv,
        })
    }
}

pub struct ProviderSet {
    pub providers: Vec<Provider>,
    pub warnings: Vec<String>,
    pub empty: bool,
}

/// Resolve the ordered provider set from the two config command strings.
/// codex is primary (index 0), claude the hedge. Empty string → absent (no
/// warning). Non-empty but malformed → absent + one warning. Empty resulting
/// set → `empty = true` (drives `no_providers`).
pub fn resolve_provider_set(command: &str, fallback_command: &str) -> ProviderSet {
    let mut providers = Vec::new();
    let mut warnings = Vec::new();
    for (name, cmd) in [("codex", command), ("claude", fallback_command)] {
        if cmd.trim().is_empty() {
            continue; // documented disable; absent, no warning
        }
        match Provider::parse(name, cmd) {
            Some(p) => providers.push(p),
            None => warnings.push(format!(
                "longline: ai-judge {name} command is malformed (unparseable shell quoting); provider disabled"
            )),
        }
    }
    let empty = providers.is_empty();
    ProviderSet {
        providers,
        warnings,
        empty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shlex_parses_empty_setting_sources_as_genuine_empty_arg() {
        // The load-bearing case split_whitespace cannot represent.
        let p =
            Provider::parse("claude", "claude -p --setting-sources \"\" --model haiku").unwrap();
        let i = p
            .argv
            .iter()
            .position(|a| a == "--setting-sources")
            .unwrap();
        assert_eq!(p.argv[i + 1], "", "empty arg must survive as \"\"");
    }

    #[test]
    fn tilde_in_settings_path_is_expanded() {
        std::env::set_var("HOME", "/home/u");
        let p = Provider::parse("claude", "claude --settings ~/.config/longline/x.json").unwrap();
        assert!(p
            .argv
            .iter()
            .any(|a| a == "/home/u/.config/longline/x.json"));
    }

    #[test]
    fn empty_or_whitespace_command_is_absent() {
        assert!(Provider::parse("claude", "").is_none());
        assert!(Provider::parse("claude", "   ").is_none());
    }

    #[test]
    fn malformed_shlex_is_absent() {
        // unmatched quote -> shlex::split returns None
        assert!(Provider::parse("claude", "claude --settings \"unterminated").is_none());
    }

    #[test]
    fn resolve_set_both_present() {
        let r = resolve_provider_set("codex exec -m x", "claude -p");
        assert_eq!(r.providers.len(), 2);
        assert!(r.warnings.is_empty());
        assert!(!r.empty);
    }

    #[test]
    fn resolve_set_codex_only_when_fallback_empty() {
        let r = resolve_provider_set("codex exec", "");
        assert_eq!(r.providers.len(), 1);
        assert_eq!(r.providers[0].name, "codex");
        assert!(!r.empty);
    }

    #[test]
    fn resolve_set_both_malformed_is_no_providers_with_warnings() {
        let r = resolve_provider_set("codex \"bad", "claude \"bad");
        assert!(r.empty);
        assert_eq!(r.warnings.len(), 2);
    }
}
