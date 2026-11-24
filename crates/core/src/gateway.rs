//! The four NetBox operations the tool needs.
//!
//! Every NetBox access goes through this trait, so that the logic is tested
//! against a fake and the dry run can refuse writes in one place.

use std::future::Future;

use serde_json::{Map, Value};

/// A NetBox object as its API returns it.
pub type Row = Map<String, Value>;

/// Query filters of a list call, e.g. `[("device_id", "12")]`.
pub type Filters = Vec<(String, String)>;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GatewayError {
    /// NetBox ignores an unknown filter and returns every object: a typo would
    /// turn a prune into a mass deletion, so the filter is refused instead.
    #[error("unknown filter {filter} on {endpoint}")]
    UnknownFilter { endpoint: String, filter: String },
    /// NetBox drops an empty filter value and returns every object: the same
    /// mass deletion as an unknown filter, so the value is refused as well.
    #[error("empty value for filter {filter} on {endpoint}")]
    EmptyFilter { endpoint: String, filter: String },
    /// NetBox drops a field it does not know and answers the write as done:
    /// the same value would be written at every run, so the write is refused.
    #[error("unknown field {field} on {endpoint}: NetBox would drop it")]
    UnknownField { endpoint: String, field: String },
    /// A write attempted during a dry run.
    #[error("{method} {endpoint} refused: dry run")]
    DryRun { method: String, endpoint: String },
    #[error("{0}")]
    Request(String),
}

/// Endpoints are named `app.name`, e.g. `dcim.interfaces`.
pub trait Gateway: Send + Sync {
    fn list(&self, endpoint: &str, filters: &Filters) -> impl Future<Output = Result<Vec<Row>, GatewayError>> + Send;

    fn create(&self, endpoint: &str, payload: &Row) -> impl Future<Output = Result<Row, GatewayError>> + Send;

    fn update(&self, endpoint: &str, id: u64, payload: &Row) -> impl Future<Output = Result<(), GatewayError>> + Send;

    fn delete(&self, endpoint: &str, id: u64) -> impl Future<Output = Result<(), GatewayError>> + Send;

    /// Whether NetBox takes a write of these fields on `endpoint`, without
    /// sending it: a dry run checks this way what the run would send. No
    /// default: a gateway that wraps another must pass the check on, or a dry
    /// run would say yes to what the real run then refuses.
    fn check_write(
        &self,
        write: Write,
        endpoint: &str,
        fields: &[String],
    ) -> impl Future<Output = Result<(), GatewayError>> + Send;
}

/// A write the fields of which are checked: a creation (POST) or an update (PATCH).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Write {
    Create,
    Update,
}

/// Builds the filters of a list call: `filters([("device_id", 12)])`.
pub fn filters<K: Into<String>, V: ToString>(pairs: impl IntoIterator<Item = (K, V)>) -> Filters {
    pairs.into_iter().map(|(key, value)| (key.into(), value.to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_turn_numbers_and_names_into_query_strings() {
        assert_eq!(filters([("device_id", 12)]), vec![("device_id".to_owned(), "12".to_owned())]);
        assert_eq!(filters([("name", "nexus01.lab01")]), vec![("name".to_owned(), "nexus01.lab01".to_owned())]);
    }

    #[test]
    fn a_dry_run_refusal_names_the_method_and_the_endpoint() {
        let error = GatewayError::DryRun { method: "POST".to_owned(), endpoint: "dcim.interfaces".to_owned() };
        assert_eq!(error.to_string(), "POST dcim.interfaces refused: dry run");
    }

    #[test]
    fn an_unknown_filter_refusal_names_the_filter() {
        let error = GatewayError::UnknownFilter { endpoint: "dcim.devices".to_owned(), filter: "nmae".to_owned() };
        assert_eq!(error.to_string(), "unknown filter nmae on dcim.devices");
    }
}
