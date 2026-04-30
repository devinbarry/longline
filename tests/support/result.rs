/// Captures exit code, stdout, and stderr from a longline invocation.
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl RunResult {
    pub fn assert_success(&self) {
        assert_eq!(
            self.exit_code, 0,
            "expected success\nstdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
    }

    pub fn assert_stdout_contains(&self, expected: &str) {
        assert!(
            self.stdout.contains(expected),
            "expected stdout to contain '{}'\nstdout: {}\nstderr: {}",
            expected,
            self.stdout,
            self.stderr
        );
    }
}
