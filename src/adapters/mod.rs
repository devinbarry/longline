pub(crate) mod claude;
pub(crate) mod codex;

/// Describe a `catch_unwind` panic payload for fail-open logging. Runtime-neutral
/// — shared by both adapters' panic backstops.
pub(crate) fn describe_panic(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}
