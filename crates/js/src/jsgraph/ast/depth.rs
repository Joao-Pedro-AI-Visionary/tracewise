//! Syntax-tree depth probe.
//!
//! The semantic pass and the converter recurse over the oxc tree, so a tree thousands of levels
//! deep (a `a.b.b.b...` chain parses iteratively, but its tree is as deep as the chain is long)
//! must be refused before either runs. This probe walks the tree with oxc's own visitor and stops
//! descending the moment the limit is crossed, so it never recurses deeper than the limit itself.

use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

use oxc_ast::ast::Program;
use oxc_ast::AstKind;
use oxc_ast_visit::Visit;

/// Marker unwound out of the walk once the limit is crossed (never printed: `resume_unwind`
/// does not call the panic hook).
struct TooDeep;

struct Probe {
    depth: usize,
    limit: usize,
}

impl<'a> Visit<'a> for Probe {
    fn enter_node(&mut self, _kind: AstKind<'a>) {
        self.depth += 1;
        if self.depth > self.limit {
            resume_unwind(Box::new(TooDeep));
        }
    }

    fn leave_node(&mut self, _kind: AstKind<'a>) {
        self.depth -= 1;
    }
}

/// True when `program` has a node nested deeper than `limit` levels.
pub(super) fn program_depth_exceeds(program: &Program<'_>, limit: usize) -> bool {
    let mut probe = Probe { depth: 0, limit };
    catch_unwind(AssertUnwindSafe(|| probe.visit_program(program))).is_err()
}
