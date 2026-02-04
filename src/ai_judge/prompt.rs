const PROMPT_TEMPLATE: &str = r#"Security evaluation of {language} code to be executed on a developer's machine.

Working directory: {cwd}
{context_block}

```{language}
{code}
```

Evaluate safety. Respond with EXACTLY one line, no other output:

ALLOW: <brief reason>
— Code only does: computation, data formatting, printing output, reading/writing
  files in the working directory or temp directories (/tmp, $TMPDIR, tempfile
  module), string/regex operations, JSON/YAML/CSV parsing, encoding, hashing,
  math, type checking, or version queries.

ASK: <brief reason>
— Code does ANY of: write/delete/move/rename files outside temp dirs or the
  working directory, network requests, subprocess or shell execution (os.system,
  subprocess), access secrets or credentials (.env, SSH keys, tokens), modify
  system configuration, install packages, or access sensitive paths outside the
  working directory."#;

pub fn build_prompt(language: &str, code: &str, cwd: &str, context: Option<&str>) -> String {
    let context_block = match context {
        Some(c) if !c.trim().is_empty() => format!("\n{c}\n"),
        _ => String::new(),
    };
    PROMPT_TEMPLATE
        .replace("{language}", language)
        .replace("{code}", code)
        .replace("{cwd}", cwd)
        .replace("{context_block}", &context_block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_prompt() {
        let prompt = build_prompt(
            "python3",
            "print(1)",
            "/home/user/project",
            Some("Execution context: Django shell"),
        );
        assert!(prompt.contains("python3"));
        assert!(prompt.contains("print(1)"));
        assert!(prompt.contains("/home/user/project"));
        assert!(prompt.contains("Execution context"));
        assert!(prompt.contains("ALLOW:"));
        assert!(prompt.contains("ASK:"));
    }
}
