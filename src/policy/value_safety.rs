use crate::parser::ArgMeta;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SafeProgramClass {
    ShellNoop,
}

pub(crate) fn is_safe_program_value(class: SafeProgramClass, value: &str, meta: ArgMeta) -> bool {
    match class {
        SafeProgramClass::ShellNoop => {
            value == "true"
                && matches!(
                    meta,
                    ArgMeta::PlainWord | ArgMeta::RawString | ArgMeta::SafeString
                )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_safe_program_value, SafeProgramClass};
    use crate::parser::ArgMeta;

    #[test]
    fn shell_noop_accepts_only_exact_true_with_static_metadata() {
        let cases = [
            (ArgMeta::PlainWord, true),
            (ArgMeta::RawString, true),
            (ArgMeta::SafeString, true),
            (ArgMeta::UnsafeString, false),
        ];

        for (meta, expected) in cases {
            assert_eq!(
                is_safe_program_value(SafeProgramClass::ShellNoop, "true", meta),
                expected,
                "unexpected result for exact `true` with {meta:?}"
            );
        }
    }

    #[test]
    fn shell_noop_rejects_every_non_exact_value_even_with_static_metadata() {
        let rejected = [
            "",
            "TRUE",
            "/bin/true",
            "/usr/bin/true",
            ":",
            "true --help",
            "sh -c true",
            " true",
            "true ",
            "\ttrue",
            "true\t",
            "true\n",
            "true\nfalse",
            "true; false",
            "true && false",
            "true | false",
            "true > /dev/null",
            "true 2>/dev/null",
            "$(true)",
            "atrue",
            "truex",
        ];
        let static_metadata = [ArgMeta::PlainWord, ArgMeta::RawString, ArgMeta::SafeString];

        for value in rejected {
            for meta in static_metadata {
                assert!(
                    !is_safe_program_value(SafeProgramClass::ShellNoop, value, meta),
                    "unexpectedly accepted {value:?} with {meta:?}"
                );
            }
        }
    }
}
