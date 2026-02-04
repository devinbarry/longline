use crate::types::Decision;

/// Parse the AI judge response, returning both the decision and the full reason line.
pub fn parse_response_with_reason(output: &str) -> (Decision, String) {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ALLOW:") {
            return (Decision::Allow, trimmed.to_string());
        }
        if trimmed.starts_with("ASK:") {
            return (Decision::Ask, trimmed.to_string());
        }
    }
    (Decision::Ask, "AI judge: unparseable response".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response_with_reason_allow() {
        let (decision, reason) = parse_response_with_reason("ALLOW: safe computation only");
        assert_eq!(decision, Decision::Allow);
        assert_eq!(reason, "ALLOW: safe computation only");
    }

    #[test]
    fn test_parse_response_with_reason_ask() {
        let (decision, reason) = parse_response_with_reason("ASK: accesses files outside cwd");
        assert_eq!(decision, Decision::Ask);
        assert_eq!(reason, "ASK: accesses files outside cwd");
    }

    #[test]
    fn test_parse_response_with_noise_before() {
        let output = "Loading model...\nALLOW: safe computation";
        let (decision, reason) = parse_response_with_reason(output);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(reason, "ALLOW: safe computation");
    }

    #[test]
    fn test_parse_response_with_noise_after() {
        let output = "ASK: network access\nTokens used: 150";
        let (decision, reason) = parse_response_with_reason(output);
        assert_eq!(decision, Decision::Ask);
        assert_eq!(reason, "ASK: network access");
    }

    #[test]
    fn test_parse_response_with_reason_unparseable() {
        let (decision, reason) = parse_response_with_reason("something random");
        assert_eq!(decision, Decision::Ask);
        assert!(
            reason.contains("unparseable"),
            "Reason should indicate unparseable: {}",
            reason
        );
    }

    #[test]
    fn test_parse_response_with_reason_empty() {
        let (decision, reason) = parse_response_with_reason("");
        assert_eq!(decision, Decision::Ask);
        assert!(reason.contains("unparseable") || reason.contains("AI judge"));
    }

    #[test]
    fn test_parse_response_allow() {
        let (decision, _) = parse_response_with_reason("ALLOW: safe computation");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_parse_response_ask() {
        let (decision, _) = parse_response_with_reason("ASK: network access detected");
        assert_eq!(decision, Decision::Ask);
    }

    #[test]
    fn test_parse_response_with_noise() {
        let output = "OpenAI Codex v0.84.0\n--------\nALLOW: safe computation\ntokens used\n";
        let (decision, _) = parse_response_with_reason(output);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_parse_response_unparseable() {
        let (decision, _) = parse_response_with_reason("something unexpected");
        assert_eq!(decision, Decision::Ask);
    }

    #[test]
    fn test_parse_response_empty() {
        let (decision, _) = parse_response_with_reason("");
        assert_eq!(decision, Decision::Ask);
    }
}
