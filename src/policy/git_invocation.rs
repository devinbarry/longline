//! Canonical structural view of Git's leading global options.

use std::borrow::Cow;

use crate::parser::{Arg, ArgMeta};

const SEPARATE_VALUE_FLAGS: &[&str] = &[
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
];

const JOINED_VALUE_FLAGS: &[&str] = &["--git-dir", "--work-tree", "--namespace", "--super-prefix"];

// Exact no-operand globals accepted by Git 2.47. Keeping this list explicit is
// important: treating every leading dash token as a boolean would make an
// invalid joined `-c...` disappear from the policy view.
const BOOLEAN_FLAGS: &[&str] = &[
    "-v",
    "--version",
    "-h",
    "--help",
    "--html-path",
    "--man-path",
    "--info-path",
    "-p",
    "--paginate",
    "-P",
    "--no-pager",
    "--no-replace-objects",
    "--no-lazy-fetch",
    "--no-optional-locks",
    "--no-advice",
    "--bare",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubcommandResolution {
    Resolved(String),
    Ambiguous,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitInvocation<'a> {
    pub globals: Vec<GitGlobalOption<'a>>,
    pub subcommand: SubcommandResolution,
    pub subcommand_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GitGlobalOption<'a> {
    Config {
        operand: Option<GitOptionOperand<'a>>,
    },
    ConfigEnv {
        operand: Option<GitOptionOperand<'a>>,
    },
    ValueFlag {
        name: &'a str,
        operand: Option<GitOptionOperand<'a>>,
    },
    BooleanFlag(&'a Arg),
    Ambiguous(&'a Arg),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitOptionForm {
    Separate,
    Joined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitOptionOperand<'a> {
    pub text: Cow<'a, str>,
    pub meta: ArgMeta,
    pub form: GitOptionForm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Consumed by the structural GitConfig matcher added next.
pub(crate) enum GitConfigValue<'a> {
    Explicit(Cow<'a, str>),
    ImplicitEmpty,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Consumed by the structural GitConfig matcher added next.
pub(crate) struct GitConfigOverride<'a> {
    pub key: Option<Cow<'a, str>>,
    pub value: GitConfigValue<'a>,
    pub value_meta: ArgMeta,
}

impl<'a> GitInvocation<'a> {
    pub(crate) fn new(argv: &'a [Arg]) -> Self {
        let mut globals = Vec::new();
        let mut index = 0;
        let mut ambiguous = false;

        while index < argv.len() {
            let arg = &argv[index];
            let text = arg.text.as_str();

            if text == "--" {
                index += 1;
                let subcommand = if ambiguous {
                    SubcommandResolution::Ambiguous
                } else {
                    argv.get(index)
                        .map(|next| SubcommandResolution::Resolved(next.text.clone()))
                        .unwrap_or(SubcommandResolution::Absent)
                };
                return Self {
                    globals,
                    subcommand,
                    subcommand_index: index.min(argv.len()),
                };
            }

            if text == "-c" {
                let operand = separate_operand(argv.get(index + 1));
                ambiguous |= operand.as_ref().is_none_or(config_operand_is_ambiguous);
                globals.push(GitGlobalOption::Config { operand });
                index = (index + 2).min(argv.len());
                continue;
            }

            if text == "--config-env" {
                let operand = separate_operand(argv.get(index + 1));
                ambiguous |= operand.as_ref().is_none_or(config_env_operand_is_ambiguous);
                globals.push(GitGlobalOption::ConfigEnv { operand });
                index = (index + 2).min(argv.len());
                continue;
            }

            if SEPARATE_VALUE_FLAGS.contains(&text) {
                let operand = separate_operand(argv.get(index + 1));
                ambiguous |= operand
                    .as_ref()
                    .is_none_or(|value| value.meta == ArgMeta::UnsafeString);
                globals.push(GitGlobalOption::ValueFlag {
                    name: text,
                    operand,
                });
                index = (index + 2).min(argv.len());
                continue;
            }

            if let Some(value) = text.strip_prefix("--config-env=") {
                let operand = joined_operand(value, arg.meta);
                ambiguous |= config_env_operand_is_ambiguous(&operand);
                globals.push(GitGlobalOption::ConfigEnv {
                    operand: Some(operand),
                });
                index += 1;
                continue;
            }

            if let Some((name, value)) = split_joined_value_flag(text) {
                let operand = joined_operand(value, arg.meta);
                ambiguous |= operand.meta == ArgMeta::UnsafeString;
                globals.push(GitGlobalOption::ValueFlag {
                    name,
                    operand: Some(operand),
                });
                index += 1;
                continue;
            }

            if BOOLEAN_FLAGS.contains(&text) {
                globals.push(GitGlobalOption::BooleanFlag(arg));
                index += 1;
                continue;
            }

            if text.starts_with('-') {
                globals.push(GitGlobalOption::Ambiguous(arg));
                ambiguous = true;
                index += 1;
                continue;
            }

            return Self {
                globals,
                subcommand: if ambiguous {
                    SubcommandResolution::Ambiguous
                } else {
                    SubcommandResolution::Resolved(arg.text.clone())
                },
                subcommand_index: index,
            };
        }

        Self {
            globals,
            subcommand: if ambiguous {
                SubcommandResolution::Ambiguous
            } else {
                SubcommandResolution::Absent
            },
            subcommand_index: index.min(argv.len()),
        }
    }

    /// Whether the allowlist may safely discard the recorded global prefix.
    /// Unsafe/dangling operands and unknown option shapes deliberately keep the
    /// invocation out of the allowlist even when a later token looks safe.
    pub(crate) fn is_allowlist_safe(&self) -> bool {
        !matches!(self.subcommand, SubcommandResolution::Ambiguous)
            && self.globals.iter().all(|global| match global {
                GitGlobalOption::Config {
                    operand: Some(operand),
                }
                | GitGlobalOption::ConfigEnv {
                    operand: Some(operand),
                }
                | GitGlobalOption::ValueFlag {
                    operand: Some(operand),
                    ..
                } => operand.meta != ArgMeta::UnsafeString,
                GitGlobalOption::BooleanFlag(_) => true,
                GitGlobalOption::Config { operand: None }
                | GitGlobalOption::ConfigEnv { operand: None }
                | GitGlobalOption::ValueFlag { operand: None, .. }
                | GitGlobalOption::Ambiguous(_) => false,
            })
    }
}

impl<'a> GitGlobalOption<'a> {
    #[allow(dead_code)] // Public-within-policy API for the next matcher task.
    pub(crate) fn config_override(&self) -> Option<GitConfigOverride<'_>> {
        let GitGlobalOption::Config {
            operand: Some(operand),
        } = self
        else {
            return None;
        };

        let text = operand.text.as_ref();
        let (key_text, value) = match text.split_once('=') {
            Some((key, value)) => (key, GitConfigValue::Explicit(Cow::Borrowed(value))),
            None if text.is_empty() => (text, GitConfigValue::Unknown),
            None => (text, GitConfigValue::ImplicitEmpty),
        };
        let key = recognizable_key(key_text, operand.meta).then_some(Cow::Borrowed(key_text));

        Some(GitConfigOverride {
            key,
            value,
            value_meta: operand.meta,
        })
    }
}

fn separate_operand(arg: Option<&Arg>) -> Option<GitOptionOperand<'_>> {
    arg.map(|value| GitOptionOperand {
        text: Cow::Borrowed(value.text.as_str()),
        meta: value.meta,
        form: GitOptionForm::Separate,
    })
}

fn joined_operand(text: &str, meta: ArgMeta) -> GitOptionOperand<'_> {
    GitOptionOperand {
        text: Cow::Borrowed(text),
        meta,
        form: GitOptionForm::Joined,
    }
}

fn split_joined_value_flag(text: &str) -> Option<(&str, &str)> {
    JOINED_VALUE_FLAGS.iter().find_map(|name| {
        text.strip_prefix(name)
            .and_then(|suffix| suffix.strip_prefix('='))
            .map(|value| (*name, value))
    })
}

fn config_operand_is_ambiguous(operand: &GitOptionOperand<'_>) -> bool {
    operand.meta == ArgMeta::UnsafeString
        || !is_well_formed_config_key(config_key(operand.text.as_ref()))
}

fn config_env_operand_is_ambiguous(operand: &GitOptionOperand<'_>) -> bool {
    if operand.meta == ArgMeta::UnsafeString {
        return true;
    }
    operand
        .text
        .split_once('=')
        .is_none_or(|(key, envvar)| !is_well_formed_config_key(key) || envvar.is_empty())
}

fn config_key(operand: &str) -> &str {
    operand.split_once('=').map_or(operand, |(key, _value)| key)
}

/// Validate the structural portion of Git's `section[.subsection].variable`
/// key grammar. Git permits broad subsection text (including URL punctuation),
/// so only the required outer boundaries are constrained here.
fn is_well_formed_config_key(key: &str) -> bool {
    let Some(first_dot) = key.find('.') else {
        return false;
    };
    first_dot > 0
        && key
            .rsplit_once('.')
            .is_some_and(|(_prefix, variable)| !variable.is_empty())
}

#[allow(dead_code)] // Used through the next task's structural override consumer.
fn recognizable_key(key: &str, meta: ArgMeta) -> bool {
    if !is_well_formed_config_key(key) {
        return false;
    }
    if meta != ArgMeta::UnsafeString {
        return true;
    }

    // Unsafe provenance can come from either dynamic shell syntax or a
    // conservatively-classified static concatenation. Preserve the latter's
    // useful key while refusing to claim that dynamic key material is known.
    !key.chars().any(|character| {
        matches!(
            character,
            '$' | '`' | '\\' | '*' | '?' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>'
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{SimpleCommand, Statement};

    fn parse_cmd(source: &str) -> SimpleCommand {
        match crate::parser::parse(source).unwrap() {
            Statement::SimpleCommand(cmd) => cmd,
            other => panic!("expected simple command, got {other:?}"),
        }
    }

    fn scan(source: &str) -> GitInvocation<'_> {
        let cmd = Box::leak(Box::new(parse_cmd(source)));
        GitInvocation::new(&cmd.argv)
    }

    fn resolved(name: &str) -> SubcommandResolution {
        SubcommandResolution::Resolved(name.to_string())
    }

    #[test]
    fn git_invocation_config_override_result_table() {
        let invocation = scan("git -c core.editor=true status");
        assert_eq!(invocation.subcommand, resolved("status"));
        assert_eq!(invocation.subcommand_index, 2);
        assert_eq!(invocation.globals.len(), 1);
        assert!(matches!(
            invocation.globals[0],
            GitGlobalOption::Config {
                operand: Some(GitOptionOperand {
                    form: GitOptionForm::Separate,
                    meta: ArgMeta::PlainWord,
                    ..
                })
            }
        ));
        assert_eq!(
            invocation.globals[0].config_override(),
            Some(GitConfigOverride {
                key: Some(Cow::Borrowed("core.editor")),
                value: GitConfigValue::Explicit(Cow::Borrowed("true")),
                value_meta: ArgMeta::PlainWord,
            })
        );

        let invocation = scan("git -c core.editor status");
        assert_eq!(invocation.subcommand, resolved("status"));
        assert_eq!(invocation.subcommand_index, 2);
        assert_eq!(
            invocation.globals[0].config_override(),
            Some(GitConfigOverride {
                key: Some(Cow::Borrowed("core.editor")),
                value: GitConfigValue::ImplicitEmpty,
                value_meta: ArgMeta::PlainWord,
            })
        );

        let invocation = scan("git -c http.https://example.com/.proxy=value status");
        assert_eq!(invocation.subcommand, resolved("status"));
        assert_eq!(
            invocation.globals[0].config_override(),
            Some(GitConfigOverride {
                key: Some(Cow::Borrowed("http.https://example.com/.proxy")),
                value: GitConfigValue::Explicit(Cow::Borrowed("value")),
                value_meta: ArgMeta::PlainWord,
            })
        );
    }

    #[test]
    fn git_invocation_unsafe_config_keeps_recognizable_key() {
        let invocation = scan("git -c \"core.editor=$EDITOR\" status");
        assert_eq!(invocation.subcommand, SubcommandResolution::Ambiguous);
        assert_eq!(invocation.subcommand_index, 2);
        assert_eq!(
            invocation.globals[0].config_override(),
            Some(GitConfigOverride {
                key: Some(Cow::Borrowed("core.editor")),
                value: GitConfigValue::Explicit(Cow::Borrowed("$EDITOR")),
                value_meta: ArgMeta::UnsafeString,
            })
        );

        let invocation = scan("git -c \"$KEY=true\" status");
        assert_eq!(invocation.subcommand, SubcommandResolution::Ambiguous);
        assert_eq!(
            invocation.globals[0].config_override(),
            Some(GitConfigOverride {
                key: None,
                value: GitConfigValue::Explicit(Cow::Borrowed("true")),
                value_meta: ArgMeta::UnsafeString,
            })
        );

        let invocation = scan("git -c core.''editor=true status");
        assert_eq!(invocation.subcommand, SubcommandResolution::Ambiguous);
        assert_eq!(
            invocation.globals[0].config_override(),
            Some(GitConfigOverride {
                key: Some(Cow::Borrowed("core.editor")),
                value: GitConfigValue::Explicit(Cow::Borrowed("true")),
                value_meta: ArgMeta::UnsafeString,
            })
        );
    }

    #[test]
    fn git_invocation_malformed_config_operands_are_ambiguous() {
        for (source, expected_value) in [
            ("git -c '' status", GitConfigValue::Unknown),
            (
                "git -c =true status",
                GitConfigValue::Explicit(Cow::Borrowed("true")),
            ),
            ("git -c foo status", GitConfigValue::ImplicitEmpty),
            (
                "git -c .foo=true status",
                GitConfigValue::Explicit(Cow::Borrowed("true")),
            ),
            (
                "git -c foo.=true status",
                GitConfigValue::Explicit(Cow::Borrowed("true")),
            ),
        ] {
            let invocation = scan(source);
            assert_eq!(
                invocation.subcommand,
                SubcommandResolution::Ambiguous,
                "{source}"
            );
            assert_eq!(invocation.subcommand_index, 2, "{source}");
            let override_value = invocation.globals[0]
                .config_override()
                .expect("Config operand must retain a structural candidate");
            assert_eq!(override_value.key, None, "{source}");
            assert_eq!(override_value.value, expected_value, "{source}");
        }
    }

    #[test]
    fn git_invocation_rejects_invalid_joined_short_config() {
        let invocation = scan("git -ccore.editor=true status");
        assert_eq!(invocation.subcommand, SubcommandResolution::Ambiguous);
        assert_eq!(invocation.subcommand_index, 1);
        assert!(matches!(
            invocation.globals.as_slice(),
            [GitGlobalOption::Ambiguous(arg)] if arg.text == "-ccore.editor=true"
        ));
        assert!(invocation
            .globals
            .iter()
            .all(|global| global.config_override().is_none()));
    }

    #[test]
    fn git_invocation_preserves_dangling_config() {
        let invocation = scan("git -c");
        assert_eq!(invocation.subcommand, SubcommandResolution::Ambiguous);
        assert_eq!(invocation.subcommand_index, 1);
        assert!(matches!(
            invocation.globals.as_slice(),
            [GitGlobalOption::Config { operand: None }]
        ));
    }

    #[test]
    fn git_invocation_distinguishes_config_env_forms() {
        for (source, expected_form) in [
            (
                "git --config-env core.editor=EDITOR status",
                GitOptionForm::Separate,
            ),
            (
                "git --config-env=core.editor=EDITOR status",
                GitOptionForm::Joined,
            ),
            (
                "git --config-env=http.https://example.com/.proxy=PROXY status",
                GitOptionForm::Joined,
            ),
        ] {
            let invocation = scan(source);
            assert_eq!(invocation.subcommand, resolved("status"), "{source}");
            assert!(matches!(
                invocation.globals.as_slice(),
                [GitGlobalOption::ConfigEnv {
                    operand: Some(GitOptionOperand { form, .. })
                }] if *form == expected_form
            ));
            assert!(invocation.globals[0].config_override().is_none());
        }
    }

    #[test]
    fn git_invocation_rejects_malformed_config_env_operands() {
        for source in [
            "git --config-env= status",
            "git --config-env=foo status",
            "git --config-env foo status",
            "git --config-env =true status",
            "git --config-env foo= status",
            "git --config-env foo=ENV status",
            "git --config-env=.foo=ENV status",
            "git --config-env=foo.=ENV status",
        ] {
            let invocation = scan(source);
            assert_eq!(
                invocation.subcommand,
                SubcommandResolution::Ambiguous,
                "{source}"
            );
            assert!(matches!(
                invocation.globals.as_slice(),
                [GitGlobalOption::ConfigEnv { operand: Some(_) }]
            ));
        }
    }

    #[test]
    fn git_invocation_preserves_repeated_config_overrides_in_order() {
        let invocation = scan("git -c core.one=first -c core.two=second status");
        assert_eq!(invocation.subcommand, resolved("status"));
        assert_eq!(invocation.subcommand_index, 4);
        assert_eq!(invocation.globals.len(), 2);
        assert!(invocation
            .globals
            .iter()
            .all(|global| matches!(global, GitGlobalOption::Config { .. })));
        assert_eq!(
            invocation
                .globals
                .iter()
                .filter_map(GitGlobalOption::config_override)
                .collect::<Vec<_>>(),
            vec![
                GitConfigOverride {
                    key: Some(Cow::Borrowed("core.one")),
                    value: GitConfigValue::Explicit(Cow::Borrowed("first")),
                    value_meta: ArgMeta::PlainWord,
                },
                GitConfigOverride {
                    key: Some(Cow::Borrowed("core.two")),
                    value: GitConfigValue::Explicit(Cow::Borrowed("second")),
                    value_meta: ArgMeta::PlainWord,
                },
            ]
        );
    }

    #[test]
    fn git_invocation_recognizes_all_separate_value_globals() {
        for flag in [
            "-C",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--super-prefix",
        ] {
            let source = format!("git {flag} value status");
            let invocation = scan(&source);
            assert_eq!(invocation.subcommand, resolved("status"), "{source}");
            assert_eq!(invocation.subcommand_index, 2, "{source}");
            assert!(matches!(
                invocation.globals.as_slice(),
                [GitGlobalOption::ValueFlag {
                    name,
                    operand: Some(GitOptionOperand {
                        text,
                        meta: ArgMeta::PlainWord,
                        form: GitOptionForm::Separate,
                    })
                }] if *name == flag && text == "value"
            ));
        }
    }

    #[test]
    fn git_invocation_recognizes_supported_joined_value_globals() {
        for flag in ["--git-dir", "--work-tree", "--namespace", "--super-prefix"] {
            let source = format!("git {flag}=value status");
            let invocation = scan(&source);
            assert_eq!(invocation.subcommand, resolved("status"), "{source}");
            assert_eq!(invocation.subcommand_index, 1, "{source}");
            assert!(matches!(
                invocation.globals.as_slice(),
                [GitGlobalOption::ValueFlag {
                    name,
                    operand: Some(GitOptionOperand {
                        text,
                        meta: ArgMeta::PlainWord,
                        form: GitOptionForm::Joined,
                    })
                }] if *name == flag && text == "value"
            ));
        }
    }

    #[test]
    fn git_invocation_recognizes_every_boolean_global() {
        for flag in BOOLEAN_FLAGS {
            let source = format!("git {flag} status");
            let invocation = scan(&source);
            assert_eq!(invocation.subcommand, resolved("status"), "{source}");
            assert_eq!(invocation.subcommand_index, 1, "{source}");
            assert!(matches!(
                invocation.globals.as_slice(),
                [GitGlobalOption::BooleanFlag(arg)] if arg.text == *flag
            ));
        }
    }

    #[test]
    fn git_invocation_recognizes_repeated_globals_for_absolute_git() {
        let invocation = scan("/usr/bin/git --paginate -C one -C two status");
        assert_eq!(invocation.subcommand, resolved("status"));
        assert_eq!(invocation.subcommand_index, 5);
        assert_eq!(invocation.globals.len(), 3);
        assert!(matches!(
            invocation.globals[0],
            GitGlobalOption::BooleanFlag(_)
        ));
        assert!(matches!(
            invocation.globals[1],
            GitGlobalOption::ValueFlag { name: "-C", .. }
        ));
        assert!(matches!(
            invocation.globals[2],
            GitGlobalOption::ValueFlag { name: "-C", .. }
        ));
    }

    #[test]
    fn git_invocation_double_dash_terminates_global_scan() {
        let invocation = scan("git -- -c core.editor=true");
        assert!(invocation.globals.is_empty());
        assert_eq!(invocation.subcommand, resolved("-c"));
        assert_eq!(invocation.subcommand_index, 1);
    }

    #[test]
    fn git_invocation_unsafe_and_dangling_values_are_ambiguous_but_clamped() {
        for source in [
            "git -C \"$REPO\" status",
            "git --git-dir \"$(pwd)\" status",
            "git --git-dir=\"$REPO\" status",
            "git --work-tree",
            "git --config-env",
        ] {
            let invocation = scan(source);
            assert_eq!(
                invocation.subcommand,
                SubcommandResolution::Ambiguous,
                "{source}"
            );
            assert!(invocation.subcommand_index <= parse_cmd(source).argv.len());
        }
    }

    #[test]
    fn git_invocation_unknown_or_malformed_leading_flags_are_ambiguous() {
        for source in [
            "git --git-directory=/tmp status",
            "git --git-dirx=/tmp status",
            "git -C/tmp status",
            "git --unknown status",
        ] {
            let invocation = scan(source);
            assert_eq!(
                invocation.subcommand,
                SubcommandResolution::Ambiguous,
                "{source}"
            );
            assert!(matches!(
                invocation.globals.first(),
                Some(GitGlobalOption::Ambiguous(_))
            ));
        }
    }
}
