use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct TestSuite {
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    id: String,
    command: String,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    decision: String,
    #[serde(default)]
    rule_id: Option<String>,
}

fn rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("rules")
        .join("default-rules.yaml")
}

fn load_golden_tests(filename: &str) -> TestSuite {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(filename);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    serde_yaml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {e}", path.display()))
}

fn run_golden_suite(filename: &str) {
    let suite = load_golden_tests(filename);
    let config = longline::policy::load_rules(&rules_path()).expect("Failed to load default rules");

    let mut failures = Vec::new();

    for case in &suite.tests {
        let stmt = match longline::parser::parse(&case.command) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!(
                    "  PARSE ERROR [{}]: command='{}', error='{e}'",
                    case.id, case.command
                ));
                continue;
            }
        };

        let result = longline::policy::evaluate(&config, &stmt);
        let actual_decision = format!("{:?}", result.decision).to_lowercase();
        let expected_decision = case.expected.decision.to_lowercase();

        if actual_decision != expected_decision {
            failures.push(format!(
                "  DECISION MISMATCH [{}]: command='{}', expected={}, actual={}, rule={:?}",
                case.id, case.command, expected_decision, actual_decision, result.rule_id
            ));
            continue;
        }

        if let Some(expected_rule) = &case.expected.rule_id {
            if result.rule_id.as_deref() != Some(expected_rule.as_str()) {
                failures.push(format!(
                    "  RULE_ID MISMATCH [{}]: command='{}', expected_rule={}, actual_rule={:?}",
                    case.id, case.command, expected_rule, result.rule_id
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "\n{} golden test failure(s) in {}:\n{}\n",
            failures.len(),
            filename,
            failures.join("\n")
        );
    }
}

#[test]
fn golden_rm() {
    run_golden_suite("rm.yaml");
}

#[test]
fn golden_pipeline() {
    run_golden_suite("pipeline.yaml");
}

#[test]
fn golden_git() {
    run_golden_suite("git.yaml");
}

#[test]
fn golden_safe_commands_shell() {
    run_golden_suite("safe-commands-shell.yaml");
}

#[test]
fn golden_safe_commands_rust() {
    run_golden_suite("safe-commands-rust.yaml");
}

#[test]
fn golden_safe_commands_node() {
    run_golden_suite("safe-commands-node.yaml");
}

#[test]
fn golden_safe_commands_python() {
    run_golden_suite("safe-commands-python.yaml");
}

#[test]
fn golden_safe_commands_go() {
    run_golden_suite("safe-commands-go.yaml");
}

#[test]
fn golden_safe_commands_other() {
    run_golden_suite("safe-commands-other.yaml");
}

#[test]
fn golden_secrets() {
    run_golden_suite("secrets.yaml");
}

#[test]
fn golden_redirects() {
    run_golden_suite("redirects.yaml");
}

#[test]
fn golden_compound() {
    run_golden_suite("compound.yaml");
}

#[test]
fn golden_system() {
    run_golden_suite("system.yaml");
}

#[test]
fn golden_exfiltration() {
    run_golden_suite("exfiltration.yaml");
}

#[test]
fn golden_network() {
    run_golden_suite("network.yaml");
}

#[test]
fn golden_docker() {
    run_golden_suite("docker.yaml");
}

#[test]
fn golden_build_tools() {
    run_golden_suite("build-tools.yaml");
}

#[test]
fn golden_interpreters() {
    run_golden_suite("interpreters.yaml");
}

#[test]
fn golden_bypass_attempts() {
    run_golden_suite("bypass-attempts.yaml");
}

#[test]
fn golden_command_substitution() {
    run_golden_suite("command-substitution.yaml");
}

#[test]
fn golden_find_xargs() {
    run_golden_suite("find-xargs.yaml");
}

#[test]
fn golden_ai_judge_extraction() {
    run_golden_suite("ai-judge-extraction.yaml");
}

#[test]
fn golden_missing_allowlist() {
    run_golden_suite("missing-allowlist.yaml");
}

#[test]
fn golden_allowlist_bypass_filesystem() {
    run_golden_suite("allowlist-bypass-filesystem.yaml");
}

#[test]
fn golden_allowlist_bypass_git() {
    run_golden_suite("allowlist-bypass-git.yaml");
}

#[test]
fn golden_allowlist_bypass_package_managers() {
    run_golden_suite("allowlist-bypass-package-managers.yaml");
}

#[test]
fn golden_dev_tools_misc() {
    run_golden_suite("dev-tools-misc.yaml");
}

#[test]
fn golden_dev_tools_gitlab() {
    run_golden_suite("dev-tools-gitlab.yaml");
}

#[test]
fn golden_dev_tools_github() {
    run_golden_suite("dev-tools-github.yaml");
}

#[test]
fn golden_dev_tools_cargo() {
    run_golden_suite("dev-tools-cargo.yaml");
}

#[test]
fn golden_dev_tools_python() {
    run_golden_suite("dev-tools-python.yaml");
}

#[test]
fn golden_django() {
    run_golden_suite("django.yaml");
}
