//! A gateway that announces its calls, for the progress display.

use omnisync_core::{Filters, Gateway, GatewayError, Row, Write};
use serde_json::Value;

use crate::inventory_apply::DryRun;

/// Tells `report` about every NetBox call just before making it.
///
/// The progress then shows what the run is waiting on: a stalled request is
/// named, not hidden behind the stage label.
pub struct ReportingGateway<G, F> {
    gateway: G,
    report: F,
}

impl<G, F> ReportingGateway<G, F>
where
    G: Gateway,
    F: Fn(&str) + Send + Sync,
{
    pub fn new(gateway: G, report: F) -> Self {
        ReportingGateway { gateway, report }
    }

    /// The gateway the calls go to.
    pub fn get_ref(&self) -> &G {
        &self.gateway
    }
}

// The field that names the object for a person reading the progress.
fn what(payload: &Row) -> String {
    ["name", "address", "mac_address", "vid"]
        .iter()
        .find_map(|key| payload.get(*key))
        .map(|value| match value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

impl<G, F> Gateway for ReportingGateway<G, F>
where
    G: Gateway,
    F: Fn(&str) + Send + Sync,
{
    async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
        let mut sorted: Vec<&(String, String)> = filters.iter().collect();
        sorted.sort();
        let arguments: Vec<String> = sorted.iter().map(|(key, value)| format!("{key}={value}")).collect();
        (self.report)(format!("GET {endpoint} {}", arguments.join(" ")).trim_end());
        self.gateway.list(endpoint, filters).await
    }

    async fn create(&self, endpoint: &str, payload: &Row) -> Result<Row, GatewayError> {
        (self.report)(format!("POST {endpoint} {}", what(payload)).trim_end());
        self.gateway.create(endpoint, payload).await
    }

    async fn update(&self, endpoint: &str, id: u64, payload: &Row) -> Result<(), GatewayError> {
        (self.report)(&format!("PATCH {endpoint} #{id}"));
        self.gateway.update(endpoint, id, payload).await
    }

    async fn delete(&self, endpoint: &str, id: u64) -> Result<(), GatewayError> {
        (self.report)(&format!("DELETE {endpoint} #{id}"));
        self.gateway.delete(endpoint, id).await
    }

    // Nothing is sent: there is no call to announce.
    async fn check_write(&self, write: Write, endpoint: &str, fields: &[String]) -> Result<(), GatewayError> {
        self.gateway.check_write(write, endpoint, fields).await
    }
}

/// A dry run is the gateway's: announcing the calls changes nothing to it.
impl<G: DryRun, F> DryRun for ReportingGateway<G, F> {
    fn dry_run(&self) -> bool {
        self.gateway.dry_run()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use omnisync_core::gateway::filters;
    use serde_json::json;

    use super::*;
    use crate::testing::FakeGateway;

    fn row(value: Value) -> Row {
        value.as_object().expect("a JSON object").clone()
    }

    #[tokio::test]
    async fn reporting_gateway_announces_each_call_before_making_it() {
        let netbox = FakeGateway::new();
        let device = netbox.add("dcim.devices", json!({"name": "nexus01.lab01", "site": 12}));
        let calls: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let reporting = ReportingGateway::new(netbox, |call: &str| calls.lock().unwrap().push(call.to_owned()));
        let created = reporting
            .create("dcim.interfaces", &row(json!({"device": device, "name": "Ethernet1/12", "type": "other"})))
            .await
            .unwrap();
        let id = created["id"].as_u64().unwrap();
        // Given out of order: the announcement sorts the filters by name.
        let listed = reporting
            .list(
                "dcim.interfaces",
                &vec![("name".to_owned(), "Ethernet1/12".to_owned()), ("device_id".to_owned(), device.to_string())],
            )
            .await
            .unwrap();
        reporting.update("dcim.interfaces", id, &row(json!({"description": "uplink"}))).await.unwrap();
        reporting
            .create("ipam.ip_addresses", &row(json!({"address": "192.0.2.1/24", "status": "active"})))
            .await
            .unwrap();
        reporting.delete("dcim.interfaces", id).await.unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "POST dcim.interfaces Ethernet1/12".to_owned(),
                format!("GET dcim.interfaces device_id={device} name=Ethernet1/12"),
                format!("PATCH dcim.interfaces #{id}"),
                "POST ipam.ip_addresses 192.0.2.1/24".to_owned(),
                format!("DELETE dcim.interfaces #{id}"),
            ]
        );
        // The calls themselves go through unchanged.
        assert_eq!(listed.iter().map(|row| row["name"].clone()).collect::<Vec<_>>(), [json!("Ethernet1/12")]);
        assert_eq!(reporting.get_ref().row("dcim.interfaces", id), None);
    }

    #[test]
    fn the_dry_run_of_the_gateway_is_passed_on() {
        let reporting = ReportingGateway::new(FakeGateway::new(), |_: &str| {});
        assert!(!reporting.dry_run());
        reporting.get_ref().refuse_writes(true);
        assert!(reporting.dry_run());
    }

    #[tokio::test]
    async fn a_call_without_filters_or_naming_field_is_announced_bare() {
        let netbox = FakeGateway::new();
        let calls: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let reporting = ReportingGateway::new(netbox, |call: &str| calls.lock().unwrap().push(call.to_owned()));
        reporting.list("ipam.vrfs", &filters::<&str, &str>([])).await.unwrap();
        reporting.create("ipam.vlans", &row(json!({"vid": 26, "site": 12}))).await.unwrap();
        reporting.create("dcim.cables", &row(json!({"a_terminations": [], "b_terminations": []}))).await.unwrap();
        assert_eq!(*calls.lock().unwrap(), ["GET ipam.vrfs", "POST ipam.vlans 26", "POST dcim.cables"]);
    }

    #[tokio::test]
    async fn the_call_is_announced_before_it_is_made() {
        let netbox = FakeGateway::new();
        netbox.fail_after(Some(0));
        let calls: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let reporting = ReportingGateway::new(netbox, |call: &str| calls.lock().unwrap().push(call.to_owned()));
        let refused = reporting.create("ipam.vrfs", &row(json!({"name": "mgmt-sw"}))).await;
        assert_eq!(refused, Err(GatewayError::Request("injected failure".to_owned())));
        assert_eq!(*calls.lock().unwrap(), ["POST ipam.vrfs mgmt-sw"]);
    }
}
