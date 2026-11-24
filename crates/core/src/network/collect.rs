//! What reading a network device may end in, whatever the way it is read.

/// The device could not be collected completely: it is skipped for this run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CollectionError(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_collection_error_prints_its_message() {
        assert_eq!(
            CollectionError("SSH to 192.0.2.1 failed: timeout".to_owned()).to_string(),
            "SSH to 192.0.2.1 failed: timeout"
        );
    }
}
