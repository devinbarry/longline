const PROMPT_TEMPLATE: &str = r#"Security evaluation of {language} code to be executed on a developer's machine.

Working directory: {cwd}
{extractor_context}
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
{extractor_context}
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

/// Response-format directive longline always appends to a project-supplied
/// prompt (Path A). The parser at `src/ai_judge/response.rs` looks for the
/// first `ALLOW:` or `ASK:` line; this directive elicits that shape.
const RESPONSE_FORMAT_SUFFIX: &str =
    "\n\nRespond with EXACTLY one line, no other output:\nALLOW: <brief reason>\nASK: <brief reason>";

/// Single-pass placeholder substitution. Walks the template once, emitting
/// replacement values for placeholder tokens encountered. Replacement values
/// are NOT re-scanned for placeholder tokens — this is the regression-safe
/// alternative to chained `.replace()`.
///
/// `vars` is a slice of (placeholder, value) pairs. Placeholders must include
/// the surrounding `{}` braces. Unknown placeholders in the template are left
/// untouched.
pub(crate) fn substitute(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut i = 0;
    let bytes = template.as_bytes();
    'outer: while i < bytes.len() {
        if bytes[i] == b'{' {
            for (placeholder, value) in vars {
                let p = placeholder.as_bytes();
                if i + p.len() <= bytes.len() && &bytes[i..i + p.len()] == p {
                    out.push_str(value);
                    i += p.len();
                    continue 'outer;
                }
            }
        }
        // UTF-8-safe advance to next char boundary.
        let ch_start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
            i += 1;
        }
        out.push_str(&template[ch_start..i]);
    }
    out
}

pub fn build_prompt(
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
    project_prompt: Option<&str>,
) -> String {
    build_prompt_from_template(
        PROMPT_TEMPLATE,
        language,
        code,
        cwd,
        context,
        project_prompt,
    )
}

pub fn build_prompt_lenient(
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
    project_prompt: Option<&str>,
) -> String {
    build_prompt_from_template(
        LENIENT_PROMPT_TEMPLATE,
        language,
        code,
        cwd,
        context,
        project_prompt,
    )
}

/// Build the prompt sent to the AI judge.
///
/// Two paths:
/// - **Path A** (`project_prompt` is `Some` and non-whitespace): the user's
///   prompt is treated as the entire reasoning prompt. Placeholders are
///   substituted single-pass, and `RESPONSE_FORMAT_SUFFIX` is appended (the
///   user's prompt does not contain the response-format directive — longline
///   appends it as the parser contract).
/// - **Path B** (`project_prompt` is `None` or whitespace-only): the chosen
///   built-in template is used. The built-in template already contains the
///   response-format directive, so no suffix is appended here.
///
/// Extractor-context wrapping differs between paths: Path A passes it raw
/// because the user's prompt template controls layout; Path B wraps with
/// surrounding newlines to preserve byte-identical output for repos that
/// have not customized `ai_judge.prompt`.
fn build_prompt_from_template(
    template: &str,
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
    project_prompt: Option<&str>,
) -> String {
    // Path A: project supplied a full prompt. Substitute the four placeholders
    // single-pass and append the fixed response-format suffix. Built-in
    // template is not used.
    if let Some(user_prompt) = project_prompt.filter(|p| !p.trim().is_empty()) {
        let extractor_context = context.unwrap_or("");
        let body = substitute(
            user_prompt,
            &[
                ("{language}", language),
                ("{code}", code),
                ("{cwd}", cwd),
                ("{extractor_context}", extractor_context),
            ],
        );
        return format!("{body}{RESPONSE_FORMAT_SUFFIX}");
    }

    let extractor_context = match context {
        Some(c) if !c.trim().is_empty() => format!("\n{c}\n"),
        _ => String::new(),
    };
    substitute(
        template,
        &[
            ("{language}", language),
            ("{code}", code),
            ("{cwd}", cwd),
            ("{extractor_context}", &extractor_context),
        ],
    )
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
            None, // project_context
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
            None, // project_context
        );
        assert!(prompt.contains("Mode: lenient"));
        assert!(prompt.contains("ALLOW:"));
        assert!(prompt.contains("ASK:"));
        assert!(
            prompt.contains("template") && prompt.contains("site-packages"),
            "Lenient prompt should explicitly allow Django template loading/site-packages reads"
        );
    }

    #[test]
    fn test_build_prompt_no_project_prompt_matches_current() {
        // Guards byte-identical output for repos without ai_judge.prompt.
        // The expected value is constructed from the post-simplification template
        // (no {project_context_block} slot).
        let with = build_prompt(
            "python3",
            "print(1)",
            "/tmp",
            Some("Execution context: Django shell"),
            None, // project_prompt
        );
        let expected = PROMPT_TEMPLATE
            .replace("{language}", "python3")
            .replace("{code}", "print(1)")
            .replace("{cwd}", "/tmp")
            .replace("{extractor_context}", "\nExecution context: Django shell\n");
        assert_eq!(with, expected);
    }

    #[test]
    fn test_substitute_replaces_known_placeholders() {
        let template = "Lang: {language}, Cwd: {cwd}";
        let out = substitute(template, &[("{language}", "python"), ("{cwd}", "/tmp")]);
        assert_eq!(out, "Lang: python, Cwd: /tmp");
    }

    #[test]
    fn test_substitute_leaves_unknown_placeholders_untouched() {
        let template = "Lang: {language}, Mystery: {mystery}";
        let out = substitute(template, &[("{language}", "python")]);
        assert_eq!(out, "Lang: python, Mystery: {mystery}");
    }

    #[test]
    fn test_substitute_is_single_pass_does_not_recurse_into_values() {
        // Regression: chained `.replace()` would substitute {cwd} inside the {code} value.
        // Single-pass must emit the replacement value verbatim.
        let template = "Code: {code}\nCwd: {cwd}";
        let out = substitute(
            template,
            &[("{code}", "print(\"{cwd}\")"), ("{cwd}", "/tmp")],
        );
        assert_eq!(out, "Code: print(\"{cwd}\")\nCwd: /tmp");
    }

    #[test]
    fn test_substitute_handles_value_containing_other_placeholder_token() {
        // {extractor_context} value happens to contain `{language}` — must NOT re-substitute.
        let template = "{language} {extractor_context}";
        let out = substitute(
            template,
            &[
                ("{language}", "python"),
                ("{extractor_context}", "Note about {language}"),
            ],
        );
        assert_eq!(out, "python Note about {language}");
    }

    #[test]
    fn test_substitute_empty_template_is_empty() {
        assert_eq!(substitute("", &[("{x}", "y")]), "");
    }

    #[test]
    fn test_substitute_no_placeholders_returns_template() {
        assert_eq!(substitute("plain text", &[("{x}", "y")]), "plain text");
    }

    #[test]
    fn test_build_prompt_uses_project_prompt_when_set() {
        let user_prompt = "Project says: evaluate {code} written in {language} at {cwd}";
        let out = build_prompt("python", "print(1)", "/tmp", None, Some(user_prompt));
        assert!(out.starts_with("Project says: evaluate print(1) written in python at /tmp"));
        assert!(out.contains("Respond with EXACTLY one line"));
        assert!(out.contains("ALLOW: <brief reason>"));
        assert!(out.contains("ASK: <brief reason>"));
    }

    #[test]
    fn test_build_prompt_path_a_does_not_include_builtin_template_text() {
        // Path A must NOT bring in built-in text like "Mode: lenient" or the
        // built-in ALLOW/ASK rule lists.
        let user_prompt = "{language} {code} {cwd}";
        let strict = build_prompt("python", "x", "/tmp", None, Some(user_prompt));
        let lenient = build_prompt_lenient("python", "x", "/tmp", None, Some(user_prompt));
        assert!(!strict.contains("Mode: lenient"));
        assert!(!strict.contains("Security evaluation"));
        assert!(!lenient.contains("Security evaluation"));
    }

    #[test]
    fn test_build_prompt_path_a_substitutes_extractor_context_unconditionally() {
        // Even if the user prompt doesn't reference {extractor_context}, longline
        // still substitutes; the unused slot is a harmless no-op.
        let user_prompt = "{language} {code} {cwd}";
        let out = build_prompt(
            "python",
            "x",
            "/tmp",
            Some("Django shell"),
            Some(user_prompt),
        );
        assert_eq!(
            out.trim_end_matches(RESPONSE_FORMAT_SUFFIX),
            "python x /tmp"
        );
    }

    #[test]
    fn test_build_prompt_path_a_single_pass_preserves_code_with_cwd_token() {
        // Regression: {code} value contains "{cwd}". Must not be re-substituted.
        let user_prompt = "Code:\n{code}\nCwd: {cwd}";
        let out = build_prompt(
            "python",
            "print(\"{cwd}\")",
            "/the/real/cwd",
            None,
            Some(user_prompt),
        );
        assert!(out.contains("print(\"{cwd}\")"));
        assert!(out.contains("Cwd: /the/real/cwd"));
    }

    #[test]
    fn test_build_prompt_lenient_uses_project_prompt_when_set() {
        let user_prompt = "{language} / {code} / {cwd}";
        let out = build_prompt_lenient("ruby", "puts 1", "/r", None, Some(user_prompt));
        assert!(out.starts_with("ruby / puts 1 / /r"));
        assert!(out.contains("ALLOW: <brief reason>"));
    }
}
