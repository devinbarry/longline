use super::bin::run_longline;
use super::config::static_test_home;
use super::result::RunResult;

/// Run a longline subcommand with the shared static HOME.
pub fn run_subcommand(args: &[&str]) -> RunResult {
    run_longline(args, static_test_home(), None)
}

/// Run a longline subcommand with a specific HOME directory.
pub fn run_subcommand_with_home(args: &[&str], home: &str) -> RunResult {
    run_longline(args, std::path::Path::new(home), None)
}
