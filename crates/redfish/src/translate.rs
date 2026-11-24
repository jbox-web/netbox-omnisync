//! Turns what a BMC said of its server into what the source asks NetBox for.
//!
//! One pure function, [`desired`]: no I/O, no clock. The source completes a
//! device that exists: it reports the manufacturer and the device type (which
//! it only needs to exist), and on the device itself two things and no more,
//! its device type and its serial. The device is a
//! [`complement`](Desired::complement): never created, never tagged, never an
//! orphan. What the BMC did not report is not declared: NetBox keeps what it
//! has.
//!
//! The whole report is [`Guarded`]: it is written only once NetBox shows, by a
//! MAC address, that the device is the server of this BMC.

use omnisync_core::inventory::guard::Guarded;
use omnisync_core::inventory::hardware::{format_slug, manufacturer_name};
use omnisync_core::inventory::model::{Desired, Identity, Kind};

use crate::model::{Bmc, System};

/// The longest texts NetBox takes, as the VMware source cuts them: both
/// sources must name a manufacturer, a device type and a serial alike.
const MAX_LONG_NAME: usize = 100;
const MAX_SERIAL: usize = 50;

/// The NetBox name of the vendor whose `SKU` is the serial NetBox wants.
const DELL: &str = "Dell";

/// What one BMC gives.
#[derive(Debug, Clone, PartialEq)]
pub struct Translation {
    /// What to write once the device is proven to be the server of the BMC.
    pub report: Guarded,
    /// What looks wrong and stops nothing.
    pub warnings: Vec<String>,
}

/// A text cut to `max` characters.
fn cut(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// The part of a host name before its first dot, in lower case.
fn short_name(name: &str) -> String {
    name.split('.').next().unwrap_or(name).to_lowercase()
}

/// The serial NetBox wants, by vendor.
///
/// A Dell writes its service tag, which is what NetBox, vCenter and the label
/// on the server call the serial, in `SKU`; its `SerialNumber` is another
/// identifier and is never written. An HPE writes its serial in
/// `SerialNumber`, and the product reference in `SKU`. Any other vendor:
/// `SerialNumber`, which is what the Redfish schema says it is.
fn serial(system: &System, manufacturer: Option<&str>) -> Option<String> {
    let serial = if manufacturer == Some(DELL) { &system.sku } else { &system.serial_number };
    serial.as_deref().map(|serial| cut(serial, MAX_SERIAL))
}

/// What the source `source` asks for the NetBox device `device`, whose BMC at
/// `host` answered `bmc`.
pub fn desired(source: &str, device: &str, host: &str, bmc: &Bmc) -> Translation {
    let system = &bmc.system;
    let witness = format!("BMC {host}");
    let mut warnings = Vec::new();
    let mut objects = Vec::new();
    let mut completed = Desired::new(Kind::Device, Identity::device(device), source).complement();

    // The name vCenter would give the same vendor: both sources meet on one manufacturer.
    let manufacturer = system.manufacturer.as_deref().map(|vendor| cut(manufacturer_name(vendor), MAX_LONG_NAME));
    let model = system.model.as_deref().map(|model| cut(model, MAX_LONG_NAME));
    match (&manufacturer, &model) {
        (Some(manufacturer), Some(model)) => {
            // Both only have to exist: one found in NetBox is used as it is.
            objects.push(
                Desired::new(Kind::Manufacturer, Identity::named(manufacturer), source)
                    .field("name", manufacturer.as_str())
                    .create_only("slug", format_slug(manufacturer, MAX_LONG_NAME))
                    .ensure_only(),
            );
            let identity = Identity::device_type(manufacturer, model);
            objects.push(
                Desired::new(Kind::DeviceType, identity.clone(), source)
                    .field("model", model.as_str())
                    .create_only("slug", format_slug(model, MAX_LONG_NAME))
                    .reference("manufacturer", Kind::Manufacturer, Identity::named(manufacturer))
                    .ensure_only(),
            );
            completed = completed.reference("device_type", Kind::DeviceType, identity);
        }
        // Half a device type is none: the one NetBox has is kept.
        (manufacturer, _) => {
            let missing = if manufacturer.is_none() { "manufacturer" } else { "model" };
            warnings.push(format!("device {device}: {witness} reports no {missing}; its device type is left as it is"));
        }
    }
    if let Some(serial) = serial(system, manufacturer.as_deref()) {
        completed = completed.field("serial", serial);
    }
    // A control, not a proof: some systems tell the BMC their short name, some nothing.
    if let Some(host_name) = &system.host_name
        && short_name(host_name) != short_name(device)
    {
        warnings.push(format!("device {device}: {witness} says its server is named {host_name}"));
    }
    if !completed.fields.is_empty() || !completed.references.is_empty() {
        objects.push(completed);
    }
    let macs = system.mac_addresses.iter().cloned().collect();
    Translation { report: Guarded { device: device.to_owned(), witness, macs, objects }, warnings }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::Manager;

    const SOURCE: &str = "bmc.lab01";

    /// A Dell server as an iDRAC describes it.
    fn dell() -> Bmc {
        Bmc {
            redfish_version: Some("1.4.0".to_owned()),
            system: System {
                manufacturer: Some("Dell Inc.".to_owned()),
                model: Some("PowerEdge R630".to_owned()),
                sku: Some("SVCTAG1".to_owned()),
                serial_number: Some("CN0000000A0001".to_owned()),
                host_name: Some("pve01.lab01".to_owned()),
                mac_addresses: vec!["02:00:00:00:00:0E".to_owned(), "02:00:00:00:00:0F".to_owned()],
            },
            manager: Some(Manager {
                model: Some("13G Monolithic".to_owned()),
                firmware_version: Some("2.86.86.86".to_owned()),
            }),
        }
    }

    fn with(change: impl FnOnce(&mut System)) -> Bmc {
        let mut bmc = dell();
        change(&mut bmc.system);
        bmc
    }

    fn translated(bmc: &Bmc) -> Translation {
        desired(SOURCE, "pve01.lab01", "drac-pve01.lab01", bmc)
    }

    fn device(translation: &Translation) -> &Desired {
        translation.report.objects.iter().find(|object| object.kind == Kind::Device).expect("a device")
    }

    #[test]
    fn a_server_is_reported_as_its_manufacturer_its_device_type_and_its_device() {
        let translation = translated(&dell());
        assert_eq!(translation.warnings, Vec::<String>::new());
        // `Dell Inc.` is `Dell` in NetBox, as for a host of a vCenter.
        let manufacturer = Desired::new(Kind::Manufacturer, Identity::named("Dell"), SOURCE)
            .field("name", "Dell")
            .create_only("slug", "dell")
            .ensure_only();
        let device_type = Desired::new(Kind::DeviceType, Identity::device_type("Dell", "PowerEdge R630"), SOURCE)
            .field("model", "PowerEdge R630")
            .create_only("slug", "poweredge-r630")
            .reference("manufacturer", Kind::Manufacturer, Identity::named("Dell"))
            .ensure_only();
        let device = Desired::new(Kind::Device, Identity::device("pve01.lab01"), SOURCE)
            .complement()
            .reference("device_type", Kind::DeviceType, Identity::device_type("Dell", "PowerEdge R630"))
            .field("serial", "SVCTAG1");
        assert_eq!(translation.report.objects, [manufacturer, device_type, device]);
    }

    #[test]
    fn the_device_is_only_completed_with_its_type_and_its_serial() {
        let translation = translated(&dell());
        let device = device(&translation);
        assert!(device.complement);
        // Neither its name, nor a tag, nor anything a hypervisor source says of it.
        assert_eq!(device.fields.keys().collect::<Vec<_>>(), ["serial"]);
        assert_eq!(device.references.keys().collect::<Vec<_>>(), ["device_type"]);
        assert!(device.tags.is_none() && device.custom_fields.is_empty() && device.reference_lists.is_empty());
        // No interface, no address: the cards a BMC lists only serve to recognise the server.
        let kinds: Vec<Kind> = translation.report.objects.iter().map(|object| object.kind).collect();
        assert_eq!(kinds, [Kind::Manufacturer, Kind::DeviceType, Kind::Device]);
    }

    #[test]
    fn the_report_is_guarded_by_the_mac_addresses_of_the_server() {
        let report = translated(&dell()).report;
        assert_eq!(report.device, "pve01.lab01");
        assert_eq!(report.witness, "BMC drac-pve01.lab01");
        assert_eq!(report.macs.into_iter().collect::<Vec<_>>(), ["02:00:00:00:00:0E", "02:00:00:00:00:0F"]);
    }

    #[test]
    fn the_serial_of_a_dell_is_its_service_tag_never_its_serial_number() {
        assert_eq!(device(&translated(&dell())).fields["serial"], json!("SVCTAG1"));
        // Without service tag there is no serial: the other identifier is not one.
        let untagged = with(|system| system.sku = None);
        assert!(!device(&translated(&untagged)).fields.contains_key("serial"));
    }

    #[test]
    fn the_serial_of_an_hpe_is_its_serial_number_never_its_product_reference() {
        let hpe = with(|system| {
            system.manufacturer = Some("HPE".to_owned());
            system.model = Some("ProLiant DL360 Gen9".to_owned());
            system.sku = Some("000000-B21".to_owned());
            system.serial_number = Some("CZJ0000001".to_owned());
        });
        let translation = translated(&hpe);
        assert_eq!(device(&translation).fields["serial"], json!("CZJ0000001"));
        let unserialed = with(|system| {
            system.manufacturer = Some("HP".to_owned());
            system.serial_number = None;
        });
        assert!(!device(&translated(&unserialed)).fields.contains_key("serial"));
    }

    #[test]
    fn the_serial_of_any_other_vendor_is_its_serial_number() {
        let other = with(|system| {
            system.manufacturer = Some("Supermicro".to_owned());
            system.model = Some("SYS-1029P".to_owned());
            system.sku = Some("PRODUCT-REF".to_owned());
            system.serial_number = Some("S000000X0000001".to_owned());
        });
        assert_eq!(device(&translated(&other)).fields["serial"], json!("S000000X0000001"));
        // A system that names no vendor: the field of the schema.
        let anonymous = with(|system| system.manufacturer = None);
        assert_eq!(device(&translated(&anonymous)).fields["serial"], json!("CN0000000A0001"));
    }

    #[test]
    fn an_unknown_serial_is_not_declared_so_that_netbox_keeps_its_own() {
        // The collection turns a blank serial into `None`.
        let blank = with(|system| {
            system.manufacturer = Some("HPE".to_owned());
            system.serial_number = None;
        });
        let translation = translated(&blank);
        // Not even an empty one, which would clear what NetBox has.
        assert!(!device(&translation).fields.contains_key("serial"));
        // The device type is still known.
        assert!(device(&translation).references.contains_key("device_type"));
    }

    #[test]
    fn a_vendor_is_named_as_the_vmware_source_names_it() {
        let named = |vendor: &str| {
            let translation = translated(&with(|system| system.manufacturer = Some(vendor.to_owned())));
            translation.report.objects[0].identity.label().to_owned()
        };
        // `module/netbox/manufacturer_mapping.py` of netbox-sync, through the shared table.
        assert_eq!(named("Dell Inc."), "Dell");
        assert_eq!(named("HP"), "HPE");
        assert_eq!(named("HPE"), "HPE");
        assert_eq!(named("LENOVO"), "Lenovo");
        assert_eq!(named("Acme"), "Acme");
    }

    #[test]
    fn half_a_device_type_is_not_declared() {
        let modelless = translated(&with(|system| system.model = None));
        assert_eq!(
            modelless.warnings,
            ["device pve01.lab01: BMC drac-pve01.lab01 reports no model; its device type is left as it is"]
        );
        // The serial is still written, and nothing else.
        let kinds: Vec<Kind> = modelless.report.objects.iter().map(|object| object.kind).collect();
        assert_eq!(kinds, [Kind::Device]);
        assert!(!device(&modelless).references.contains_key("device_type"));
        let vendorless = translated(&with(|system| system.manufacturer = None));
        assert_eq!(
            vendorless.warnings,
            ["device pve01.lab01: BMC drac-pve01.lab01 reports no manufacturer; its device type is left as it is"]
        );
        assert!(!device(&vendorless).references.contains_key("device_type"));
    }

    #[test]
    fn a_bmc_that_knows_nothing_reports_nothing() {
        let silent =
            Bmc { system: System { mac_addresses: dell().system.mac_addresses, ..System::default() }, ..dell() };
        let translation = translated(&silent);
        assert_eq!(translation.report.objects, []);
    }

    #[test]
    fn a_host_name_that_differs_is_a_warning_and_changes_nothing() {
        let other = translated(&with(|system| system.host_name = Some("esx07.lab01".to_owned())));
        assert_eq!(other.warnings, ["device pve01.lab01: BMC drac-pve01.lab01 says its server is named esx07.lab01"]);
        assert_eq!(other.report.objects, translated(&dell()).report.objects);
    }

    #[test]
    fn a_host_name_is_compared_on_its_short_name_whatever_the_case() {
        // Some systems tell the BMC their short name, some their full name, some another domain.
        for reported in ["pve01", "PVE01", "pve01.lab01", "pve01.example.net"] {
            let translation = translated(&with(|system| system.host_name = Some(reported.to_owned())));
            assert_eq!(translation.warnings, Vec::<String>::new(), "{reported}");
        }
        // A system that tells nothing is not a mismatch.
        assert_eq!(translated(&with(|system| system.host_name = None)).warnings, Vec::<String>::new());
    }

    #[test]
    fn long_texts_are_cut_as_netbox_takes_them() {
        let long = with(|system| {
            system.model = Some("M".repeat(120));
            system.sku = Some("S".repeat(60));
        });
        let translation = translated(&long);
        assert_eq!(translation.report.objects[1].fields["model"], json!("M".repeat(100)));
        assert_eq!(device(&translation).fields["serial"], json!("S".repeat(50)));
    }
}
