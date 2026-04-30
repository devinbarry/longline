pub mod discovery;
pub mod overlays;
pub mod prompt;
pub mod rules;

pub use discovery::{
    default_rules_path, existing_project_config_path, find_project_root, global_config_path,
    load_global_config, load_project_config, project_config_path,
};
pub use overlays::{
    merge_overlay_config, merge_project_config, AllowlistEntry, Allowlists, ProjectAiJudgeConfig,
    ProjectConfig, RuleSource,
};
pub use prompt::{validate_ai_judge_prompt, validate_project_ai_judge_prompt};
pub use rules::{
    load_embedded_rules, load_embedded_rules_with_info, load_rules, load_rules_with_info,
    ArgsMatcher, FlagsMatcher, LoadedConfig, LoadedFileInfo, Matcher, PartialRulesConfig,
    PipelineMatcher, RedirectMatcher, Rule, RulesConfig, RulesManifestConfig, SafetyLevel,
    StageMatcher, StringOrList, TrustLevel,
};
