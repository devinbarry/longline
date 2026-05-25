use crate::parser::{Redirect, RedirectOp};

pub(super) fn is_stderr_devnull(r: &Redirect) -> bool {
    r.fd == Some(2) && r.op == RedirectOp::Write && r.target == "/dev/null"
}

#[allow(dead_code)] // wired in Task 3
pub(super) fn is_devnull_target(r: &Redirect) -> bool {
    matches!(
        r.op,
        RedirectOp::Write | RedirectOp::Append | RedirectOp::Clobber | RedirectOp::DupOutput
    ) && r.target == "/dev/null"
}

/// Returns true iff the redirect list, applied in order, routes at
/// least one of stdout (fd 1) / stderr (fd 2) to /dev/null AND every
/// other redirect is either a /dev/null write or a fd-dup to an
/// already-/dev/nulled fd. Single-fd discard (just `2>/dev/null`) is
/// accepted because it cannot exfiltrate data to a sensitive file
/// path; the worst case is information leaking to the controlling
/// terminal. Empty list returns true (no redirects = nothing to leak).
#[allow(dead_code)] // wired in Task 3
pub(super) fn redirects_discard_all_output(redirs: &[Redirect]) -> bool {
    if redirs.is_empty() {
        return true;
    }
    let mut fd_devnull = [false; 3];
    for r in redirs {
        let fd = r.fd.unwrap_or_else(|| default_fd_for_op(r.op));
        if fd > 2 {
            return false;
        }
        match (r.op, r.target.as_str()) {
            (
                RedirectOp::Write
                | RedirectOp::Append
                | RedirectOp::Clobber
                | RedirectOp::DupOutput,
                "/dev/null",
            ) => {
                fd_devnull[fd as usize] = true;
            }
            (RedirectOp::DupOutput, target) => {
                let Ok(dst) = target.parse::<u32>() else {
                    return false;
                };
                if dst > 2 || !fd_devnull[dst as usize] {
                    return false;
                }
                fd_devnull[fd as usize] = true;
            }
            _ => return false,
        }
    }
    fd_devnull[1] || fd_devnull[2]
}

fn default_fd_for_op(op: RedirectOp) -> u32 {
    match op {
        RedirectOp::Write | RedirectOp::Append | RedirectOp::Clobber | RedirectOp::DupOutput => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(fd: Option<u32>, target: &str) -> Redirect {
        Redirect {
            fd,
            op: RedirectOp::Write,
            target: target.to_string(),
        }
    }
    fn dup(fd: Option<u32>, target: &str) -> Redirect {
        Redirect {
            fd,
            op: RedirectOp::DupOutput,
            target: target.to_string(),
        }
    }
    fn append(fd: Option<u32>, target: &str) -> Redirect {
        Redirect {
            fd,
            op: RedirectOp::Append,
            target: target.to_string(),
        }
    }

    #[test]
    fn empty_list_is_discard() {
        assert!(redirects_discard_all_output(&[]));
    }

    #[test]
    fn stdout_only_devnull_is_discard() {
        assert!(redirects_discard_all_output(&[w(Some(1), "/dev/null")]));
    }

    #[test]
    fn stderr_only_devnull_is_discard() {
        assert!(redirects_discard_all_output(&[w(Some(2), "/dev/null")]));
    }

    #[test]
    fn bare_write_defaults_to_stdout_devnull() {
        // `> /dev/null` parses with fd=None; helper must default to fd 1.
        assert!(redirects_discard_all_output(&[w(None, "/dev/null")]));
    }

    #[test]
    fn canonical_full_discard_devnull_then_2to1() {
        // `> /dev/null 2>&1`
        let redirs = vec![w(Some(1), "/dev/null"), dup(Some(2), "1")];
        assert!(redirects_discard_all_output(&redirs));
    }

    #[test]
    fn reversed_dup_then_devnull_leaks_stderr() {
        // `2>&1 > /dev/null` — stderr dup'd to original stdout (terminal)
        // BEFORE stdout reassigned. Must reject.
        let redirs = vec![dup(Some(2), "1"), w(Some(1), "/dev/null")];
        assert!(!redirects_discard_all_output(&redirs));
    }

    #[test]
    fn non_devnull_target_rejected() {
        assert!(!redirects_discard_all_output(&[w(Some(1), "/tmp/foo")]));
    }

    #[test]
    fn mixed_devnull_and_file_rejected() {
        let redirs = vec![w(Some(1), "/dev/null"), w(Some(2), "/tmp/log")];
        assert!(!redirects_discard_all_output(&redirs));
    }

    #[test]
    fn fd_gt_2_source_rejected() {
        assert!(!redirects_discard_all_output(&[w(Some(3), "/dev/null")]));
    }

    #[test]
    fn dup_to_fd_gt_2_rejected() {
        assert!(!redirects_discard_all_output(&[dup(Some(1), "3")]));
    }

    #[test]
    fn fd_close_dash_rejected() {
        // `>&-` target is "-", not parseable as fd number; conservative reject.
        assert!(!redirects_discard_all_output(&[dup(Some(1), "-")]));
    }

    #[test]
    fn file_target_dupoutput_to_devnull_is_discard() {
        // `>& /dev/null` — DupOutput with file target /dev/null.
        assert!(redirects_discard_all_output(&[dup(Some(1), "/dev/null")]));
    }

    #[test]
    fn append_to_devnull_is_discard() {
        assert!(redirects_discard_all_output(&[append(
            Some(1),
            "/dev/null"
        )]));
    }

    #[test]
    fn is_devnull_target_basic() {
        assert!(is_devnull_target(&w(Some(1), "/dev/null")));
        assert!(is_devnull_target(&w(Some(2), "/dev/null")));
        assert!(is_devnull_target(&dup(Some(1), "/dev/null")));
        assert!(!is_devnull_target(&w(Some(1), "/tmp/foo")));
        assert!(!is_devnull_target(&dup(Some(2), "1"))); // digit target, not file
    }

    #[test]
    fn is_stderr_devnull_basic() {
        assert!(is_stderr_devnull(&w(Some(2), "/dev/null")));
        assert!(!is_stderr_devnull(&w(Some(1), "/dev/null")));
        assert!(!is_stderr_devnull(&w(Some(2), "/tmp/foo")));
    }
}
