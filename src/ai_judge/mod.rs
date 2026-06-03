mod config;
mod extract;
mod home;
mod invoke;
mod orchestrator;
mod outcome;
mod prompt;
mod provider;
mod response;
mod settings;

pub use config::load_config;
#[allow(unused_imports)]
pub use config::{AiJudgeConfig, InterpreterTrigger, TriggersConfig};
#[allow(unused_imports)]
pub use extract::{extract_code, ExtractedCode};
pub use home::{expand_tilde_token, home_dir};
pub use invoke::{evaluate, evaluate_lenient, JudgeVerdict};
#[allow(unused_imports)] // consumed by invoke.rs in Task 11
pub use orchestrator::{orchestrate, OrchestrateParams, OrchestrateResult};
#[allow(unused_imports)]
pub use orchestrator::{AttemptHandle, AttemptId, Clock, Event, Runner, Xorshift};
#[allow(unused_imports)]
pub use outcome::{
    classify, derive_failure_mode, outcome_tag, AttemptOutcome, AttemptRecord, JudgeReport, Phase,
    ReportOutcome,
};
#[allow(unused_imports)]
pub use prompt::{build_prompt, build_prompt_lenient};
#[allow(unused_imports)]
pub use provider::{resolve_provider_set, Provider, ProviderSet};
#[allow(unused_imports)] // RealClock/RealRunner consumed by tests + invoke.rs (Task 11)
pub use provider::{RealClock, RealHandle, RealRunner};
#[allow(unused_imports)]
pub use response::{parse_output, ParsedOutput, Verdict};
#[allow(unused_imports)] // consumed by invoke.rs in Task 11 / cli.rs in Task 14
pub use settings::{
    content_is_safe, ensure_settings_file, is_inert_and_safe, SettingsOutcome,
    EMBEDDED as JUDGE_CLAUDE_SETTINGS,
};
