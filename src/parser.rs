use std::fmt;

/// Top-level parsed representation of a bash command string.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    SimpleCommand(SimpleCommand),
    Pipeline(Pipeline),
    List(List),
    Subshell(Box<Statement>),
    CommandSubstitution(Box<Statement>),
    Opaque(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleCommand {
    pub name: Option<String>,
    pub argv: Vec<String>,
    pub redirects: Vec<Redirect>,
    pub assignments: Vec<Assignment>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pipeline {
    pub stages: Vec<Statement>,
    pub negated: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct List {
    pub first: Box<Statement>,
    pub rest: Vec<(ListOp, Statement)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListOp {
    Semi,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Redirect {
    pub fd: Option<u32>,
    pub op: RedirectOp,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectOp {
    Write,      // >
    Append,     // >>
    Read,       // <
    ReadWrite,  // <>
    DupOutput,  // >&
    DupInput,   // <&
    Clobber,    // >|
}

impl fmt::Display for RedirectOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedirectOp::Write => write!(f, ">"),
            RedirectOp::Append => write!(f, ">>"),
            RedirectOp::Read => write!(f, "<"),
            RedirectOp::ReadWrite => write!(f, "<>"),
            RedirectOp::DupOutput => write!(f, ">&"),
            RedirectOp::DupInput => write!(f, "<&"),
            RedirectOp::Clobber => write!(f, ">|"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub name: String,
    pub value: String,
}

/// Parse a command string into a Statement.
pub fn parse(_command: &str) -> Result<Statement, String> {
    Err("not implemented".to_string())
}

/// Flatten a Statement into its leaf SimpleCommand and Opaque nodes.
pub fn flatten(stmt: &Statement) -> Vec<&Statement> {
    match stmt {
        Statement::SimpleCommand(_) | Statement::Opaque(_) => vec![stmt],
        Statement::Pipeline(p) => p.stages.iter().flat_map(flatten).collect(),
        Statement::List(l) => {
            let mut out = flatten(&l.first);
            for (_, s) in &l.rest {
                out.extend(flatten(s));
            }
            out
        }
        Statement::Subshell(inner) => flatten(inner),
        Statement::CommandSubstitution(inner) => flatten(inner),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flatten_simple_command() {
        let cmd = Statement::SimpleCommand(SimpleCommand {
            name: Some("ls".into()),
            argv: vec![],
            redirects: vec![],
            assignments: vec![],
        });
        let leaves = flatten(&cmd);
        assert_eq!(leaves.len(), 1);
    }

    #[test]
    fn test_flatten_pipeline() {
        let pipe = Statement::Pipeline(Pipeline {
            stages: vec![
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("curl".into()),
                    argv: vec!["http://example.com".into()],
                    redirects: vec![],
                    assignments: vec![],
                }),
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("sh".into()),
                    argv: vec![],
                    redirects: vec![],
                    assignments: vec![],
                }),
            ],
            negated: false,
        });
        let leaves = flatten(&pipe);
        assert_eq!(leaves.len(), 2);
    }

    #[test]
    fn test_flatten_list() {
        let list = Statement::List(List {
            first: Box::new(Statement::SimpleCommand(SimpleCommand {
                name: Some("echo".into()),
                argv: vec!["hello".into()],
                redirects: vec![],
                assignments: vec![],
            })),
            rest: vec![(
                ListOp::And,
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("rm".into()),
                    argv: vec!["-rf".into(), "/".into()],
                    redirects: vec![],
                    assignments: vec![],
                }),
            )],
        });
        let leaves = flatten(&list);
        assert_eq!(leaves.len(), 2);
    }

    #[test]
    fn test_flatten_opaque() {
        let opaque = Statement::Opaque("eval $cmd".into());
        let leaves = flatten(&opaque);
        assert_eq!(leaves.len(), 1);
    }

    #[test]
    fn test_flatten_nested_subshell() {
        let subshell = Statement::Subshell(Box::new(Statement::Pipeline(Pipeline {
            stages: vec![
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("cat".into()),
                    argv: vec!["/etc/passwd".into()],
                    redirects: vec![],
                    assignments: vec![],
                }),
                Statement::SimpleCommand(SimpleCommand {
                    name: Some("grep".into()),
                    argv: vec!["root".into()],
                    redirects: vec![],
                    assignments: vec![],
                }),
            ],
            negated: false,
        })));
        let leaves = flatten(&subshell);
        assert_eq!(leaves.len(), 2);
    }

    #[test]
    fn test_redirect_op_display() {
        assert_eq!(RedirectOp::Write.to_string(), ">");
        assert_eq!(RedirectOp::Append.to_string(), ">>");
        assert_eq!(RedirectOp::Read.to_string(), "<");
    }
}
