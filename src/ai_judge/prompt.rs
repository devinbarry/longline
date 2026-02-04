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

const LENIENT_PROMPT_TEMPLATE: &str = r#"Security evaluation of {language} code to be executed on a developer's machine.

Mode: lenient

Working directory: {cwd}
{context_block}

```{language}
{code}
```

Evaluate safety. Respond with EXACTLY one line, no other output:

ALLOW: <brief reason>
— Prefer ALLOW for normal developer tasks: imports, computation, formatting,
  parsing, printing, and read-only operations.
— Do NOT respond ASK just because code may read files outside the working
  directory. Read-only file reads are allowed, including Django template
  loading from installed apps/site-packages.

ASK: <brief reason>
— Respond ASK only when the code is explicitly and clearly doing something
  dangerous. Do NOT ASK based on "could/may" capability.
— ASK if the code does ANY of:
  - Network access (requests/urllib/httpx/sockets), downloading/uploading data
  - Subprocess/shell execution (os.system, subprocess, shell=True)
  - Accessing secrets/credentials (reading .env, ~/.ssh, ~/.aws, tokens, keys)
  - Writing/deleting/moving/renaming files outside the working directory or
    temp dirs (/tmp, $TMPDIR, tempfile module)
  - Installing packages or changing system configuration
  - In Django contexts: any database writes/deletes or migrations (save(),
    delete(), update(), migrate)

If uncertain, choose ALLOW."#;

pub fn build_prompt(language: &str, code: &str, cwd: &str, context: Option<&str>) -> String {
    build_prompt_from_template(PROMPT_TEMPLATE, language, code, cwd, context)
}

pub fn build_prompt_lenient(
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
) -> String {
    build_prompt_from_template(LENIENT_PROMPT_TEMPLATE, language, code, cwd, context)
}

fn build_prompt_from_template(
    template: &str,
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
) -> String {
    let context_block = match context {
        Some(c) if !c.trim().is_empty() => format!("\n{c}\n"),
        _ => String::new(),
    };
    template
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

    #[test]
    fn test_build_prompt_lenient() {
        let prompt = build_prompt_lenient(
            "python3",
            "print(1)",
            "/home/user/project",
            Some("Execution context: Django shell"),
        );
        assert!(prompt.contains("Mode: lenient"));
        assert!(prompt.contains("ALLOW:"));
        assert!(prompt.contains("ASK:"));
        assert!(
            prompt.contains("template") && prompt.contains("site-packages"),
            "Lenient prompt should explicitly allow Django template loading/site-packages reads"
        );
    }
}
