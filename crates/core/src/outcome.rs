//! What a run produced: the changes, what it could not do, and how long it took.

use crate::change::Change;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    /// Number of changes written to NetBox.
    pub applied: usize,
    /// Wall time of the run; None for an outcome not produced by a run.
    pub seconds: Option<f64>,
}
