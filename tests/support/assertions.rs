pub fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected output to contain '{}'\noutput: {}",
        needle,
        haystack
    );
}
