//! What a source reports about a device on the word of something else than
//! the device: a BMC, reached at an address the configuration gives.
//!
//! Nothing ties that address to the NetBox device but a line of
//! configuration. Before anything the BMC says is written, the device must be
//! shown to be the server the BMC manages: one of the MAC addresses the BMC
//! reports for its system has to be on an interface of the device in NetBox.
//! Without that proof nothing is written, and the reason is a warning.

use std::collections::BTreeSet;

use serde_json::Value;

use super::model::{Current, Desired, Identity, Kind};

/// What one witness (a BMC) reports about one device.
#[derive(Debug, Clone, PartialEq)]
pub struct Guarded {
    /// Name of the NetBox device the report is about.
    pub device: String,
    /// What reports it, as a warning names it (`BMC drac-pve01.lab01`).
    pub witness: String,
    /// The MAC addresses the witness gives for the server, in any writing.
    pub macs: BTreeSet<String>,
    /// What is written once the device is shown to be that server.
    pub objects: Vec<Desired>,
}

/// The twelve hexadecimal digits of a MAC address, in upper case; `None` for
/// anything else.
pub fn mac_digits(address: &str) -> Option<String> {
    let digits: String = address.chars().filter(|character| !matches!(character, ':' | '-' | '.')).collect();
    (digits.len() == 12 && digits.chars().all(|digit| digit.is_ascii_hexdigit())).then(|| digits.to_uppercase())
}

/// Whether the digits of a MAC address can tell one server: neither all zero
/// (a disabled port, a placeholder), nor the broadcast address, nor a group
/// address (the low bit of the first octet), which many hosts share.
fn proves(digits: &str) -> bool {
    let group = u8::from_str_radix(&digits[..2], 16).is_ok_and(|octet| octet & 1 == 1);
    digits != "000000000000" && !group
}

/// The MAC addresses NetBox holds on the interfaces of the device `id`: the
/// MAC address objects assigned to them, and the address an interface row
/// shows itself.
fn held_macs(device: u64, current: &[Current]) -> BTreeSet<String> {
    let of_device = |object: &&Current| object.kind == Kind::Interface && object.parent == Some((Kind::Device, device));
    let interfaces: Vec<&Current> = current.iter().filter(of_device).collect();
    let ids: BTreeSet<u64> = interfaces.iter().map(|interface| interface.id).collect();
    let shown = interfaces.iter().filter_map(|interface| interface.row.get("mac_address").and_then(Value::as_str));
    let assigned = current
        .iter()
        .filter(|object| object.kind == Kind::MacAddress)
        .filter(|object| matches!(object.parent, Some((Kind::Interface, interface)) if ids.contains(&interface)))
        .filter_map(|object| object.row.get("mac_address").and_then(Value::as_str));
    shown.chain(assigned).filter_map(mac_digits).filter(|digits| proves(digits)).collect()
}

/// The objects of the reports whose device is proven to be the server of
/// their witness, and a warning for each report left out.
///
/// Left out, with everything it reports: a device that is not in NetBox (it
/// is never created from here), a name several devices have, a witness that
/// gives no MAC address, a device NetBox holds no MAC address for yet (nothing
/// can be checked: the next run will, once a source has written its
/// interfaces), and a device none of whose addresses the witness reports —
/// most likely the BMC of another server.
pub fn admit(reports: Vec<Guarded>, current: &[Current]) -> (Vec<Desired>, Vec<String>) {
    let mut objects = Vec::new();
    let mut warnings = Vec::new();
    for report in reports {
        let identity = Identity::device(&report.device);
        let devices: Vec<&Current> =
            current.iter().filter(|object| object.kind == Kind::Device && object.identity == identity).collect();
        let (device, witness) = (&report.device, &report.witness);
        let reported: BTreeSet<String> =
            report.macs.iter().filter_map(|address| mac_digits(address)).filter(|digits| proves(digits)).collect();
        let refusal = match devices.as_slice() {
            [] => Some(format!("not in NetBox; {witness} is left out (a device is never created from its BMC)")),
            [one] => {
                let held = held_macs(one.id, current);
                if reported.is_empty() {
                    Some(format!("{witness} reports no MAC address of its server: nothing proves it is this device"))
                } else if held.is_empty() {
                    Some(format!(
                        "NetBox holds no MAC address on its interfaces yet: {witness} cannot be checked against it"
                    ))
                } else if held.is_disjoint(&reported) {
                    Some(format!(
                        "none of the {} MAC address(es) {witness} reports is on its {} NetBox interface address(es): \
                         wrong BMC for this device?",
                        reported.len(),
                        held.len()
                    ))
                } else {
                    None
                }
            }
            several => Some(format!("{} NetBox devices have this name; {witness} is left out", several.len())),
        };
        match refusal {
            Some(reason) => warnings.push(format!("device {device}: {reason}; nothing is written for it")),
            None => objects.extend(report.objects),
        }
    }
    (objects, warnings)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::gateway::Row;

    fn row(value: Value) -> Row {
        value.as_object().unwrap().clone()
    }

    fn device(id: u64, name: &str) -> Current {
        Current {
            id,
            kind: Kind::Device,
            identity: Identity::device(name),
            parent: None,
            tags: Vec::new(),
            row: row(json!({"id": id, "name": name})),
        }
    }

    /// An interface of the device `device`, showing `mac` itself when given.
    fn interface(id: u64, device: (u64, &str), name: &str, mac: Option<&str>) -> Current {
        Current {
            id,
            kind: Kind::Interface,
            identity: Identity::interface(device.1, name),
            parent: Some((Kind::Device, device.0)),
            tags: Vec::new(),
            row: row(json!({"id": id, "name": name, "mac_address": mac})),
        }
    }

    /// A MAC address object assigned to the interface `interface`.
    fn mac(id: u64, interface: u64, address: &str) -> Current {
        Current {
            id,
            kind: Kind::MacAddress,
            identity: Identity::mac_address(address, None),
            parent: Some((Kind::Interface, interface)),
            tags: Vec::new(),
            row: row(json!({"id": id, "mac_address": address})),
        }
    }

    fn report(device: &str, macs: &[&str]) -> Guarded {
        let serial = Desired::new(Kind::Device, Identity::device(device), "bmc").complement().field("serial", "SVC1");
        Guarded {
            device: device.to_owned(),
            witness: format!("BMC drac-{device}"),
            macs: macs.iter().map(|address| (*address).to_owned()).collect(),
            objects: vec![serial],
        }
    }

    fn admitted(reports: Vec<Guarded>, current: &[Current]) -> (Vec<String>, Vec<String>) {
        let (objects, warnings) = admit(reports, current);
        (objects.iter().map(|object| object.identity.label().to_owned()).collect(), warnings)
    }

    #[test]
    fn a_mac_address_is_compared_whatever_its_writing() {
        assert_eq!(mac_digits("02:00:00:00:00:1e").as_deref(), Some("02000000001E"));
        assert_eq!(mac_digits("02-00-00-00-00-1E").as_deref(), Some("02000000001E"));
        assert_eq!(mac_digits("0200.0000.001e").as_deref(), Some("02000000001E"));
        assert_eq!(mac_digits(""), None);
        assert_eq!(mac_digits("02:00:00:00:00"), None);
        assert_eq!(mac_digits("not a mac addr"), None);
    }

    #[test]
    fn a_device_holding_one_of_the_reported_addresses_is_admitted() {
        // The address is on a MAC address object of an interface of the device, in another letter case.
        let current = [
            device(1, "pve01.lab01"),
            interface(10, (1, "pve01.lab01"), "eno1", None),
            mac(100, 10, "02:00:00:00:00:0e"),
        ];
        let (objects, warnings) =
            admitted(vec![report("pve01.lab01", &["02:00:00:00:00:0E", "02:00:00:00:00:0F"])], &current);
        assert_eq!(objects, ["pve01.lab01"]);
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn the_address_an_interface_row_shows_counts_as_well() {
        let current = [device(1, "PVE01.lab01"), interface(10, (1, "PVE01.lab01"), "eno1", Some("02:00:00:00:00:0E"))];
        // The device is found whatever the case of its name.
        let (objects, warnings) = admitted(vec![report("pve01.lab01", &["02:00:00:00:00:0e"])], &current);
        assert_eq!(objects, ["pve01.lab01"]);
        assert_eq!(warnings, Vec::<String>::new());
    }

    // An all-zero, broadcast or group address is no address of a server: a
    // disabled port, a placeholder. Shared by two unrelated machines, it would
    // prove the wrong one.
    #[test]
    fn a_placeholder_address_proves_nothing() {
        let current = [
            device(1, "pve01.lab01"),
            interface(10, (1, "pve01.lab01"), "eno1", Some("02:00:00:00:00:0E")),
            interface(11, (1, "pve01.lab01"), "eno2", Some("00:00:00:00:00:00")),
            mac(100, 10, "FF:FF:FF:FF:FF:FF"),
            mac(101, 10, "01:00:5E:00:00:01"),
        ];
        let reported = ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "02:00:00:00:00:0F"];
        let (objects, warnings) = admitted(vec![report("pve01.lab01", &reported)], &current);
        assert_eq!(objects, Vec::<String>::new());
        assert_eq!(
            warnings,
            ["device pve01.lab01: none of the 1 MAC address(es) BMC drac-pve01.lab01 reports is on its 1 NetBox \
                 interface address(es): wrong BMC for this device?; nothing is written for it"]
        );
    }

    #[test]
    fn a_device_that_is_not_in_netbox_is_left_out_with_a_warning() {
        let (objects, warnings) = admitted(vec![report("pve09.lab01", &["02:00:00:00:00:0e"])], &[]);
        assert_eq!(objects, Vec::<String>::new());
        assert_eq!(
            warnings,
            [
                "device pve09.lab01: not in NetBox; BMC drac-pve09.lab01 is left out (a device is never created from its \
              BMC); nothing is written for it"
            ]
        );
    }

    #[test]
    fn a_bmc_whose_addresses_are_on_another_device_is_refused_naming_both() {
        let current = [
            device(1, "pve01.lab01"),
            interface(10, (1, "pve01.lab01"), "eno1", None),
            mac(100, 10, "02:00:00:00:00:0E"),
            device(2, "pve02.lab01"),
            interface(20, (2, "pve02.lab01"), "eno1", None),
            mac(200, 20, "02:00:00:00:00:AA"),
            mac(201, 20, "02:00:00:00:00:AB"),
        ];
        // The BMC configured for pve02 is the one of pve01.
        let (objects, warnings) = admitted(vec![report("pve02.lab01", &["02:00:00:00:00:0E"])], &current);
        assert_eq!(objects, Vec::<String>::new());
        assert_eq!(
            warnings,
            ["device pve02.lab01: none of the 1 MAC address(es) BMC drac-pve02.lab01 reports is on its 2 NetBox \
              interface address(es): wrong BMC for this device?; nothing is written for it"]
        );
    }

    #[test]
    fn a_device_without_any_mac_address_in_netbox_is_not_written() {
        // An interface without address, and an address assigned to nothing: no proof either way.
        let loose = Current { parent: None, ..mac(100, 10, "02:00:00:00:00:0E") };
        let current = [device(1, "pve01.lab01"), interface(10, (1, "pve01.lab01"), "eno1", None), loose];
        let (objects, warnings) = admitted(vec![report("pve01.lab01", &["02:00:00:00:00:0E"])], &current);
        assert_eq!(objects, Vec::<String>::new());
        assert_eq!(
            warnings,
            ["device pve01.lab01: NetBox holds no MAC address on its interfaces yet: BMC drac-pve01.lab01 cannot be \
              checked against it; nothing is written for it"]
        );
    }

    #[test]
    fn a_bmc_that_reports_no_address_proves_nothing() {
        let current = [
            device(1, "pve01.lab01"),
            interface(10, (1, "pve01.lab01"), "eno1", None),
            mac(100, 10, "02:00:00:00:00:0E"),
        ];
        let (objects, warnings) = admitted(vec![report("pve01.lab01", &[])], &current);
        assert_eq!(objects, Vec::<String>::new());
        assert_eq!(
            warnings,
            ["device pve01.lab01: BMC drac-pve01.lab01 reports no MAC address of its server: nothing proves it is \
              this device; nothing is written for it"]
        );
    }

    #[test]
    fn a_name_several_devices_have_is_left_out() {
        let current = [device(1, "pve01.lab01"), device(2, "PVE01.LAB01")];
        let (objects, warnings) = admitted(vec![report("pve01.lab01", &["02:00:00:00:00:0E"])], &current);
        assert_eq!(objects, Vec::<String>::new());
        assert_eq!(
            warnings,
            ["device pve01.lab01: 2 NetBox devices have this name; BMC drac-pve01.lab01 is left out; nothing is \
              written for it"]
        );
    }

    #[test]
    fn each_report_is_judged_on_its_own() {
        let current = [
            device(1, "pve01.lab01"),
            interface(10, (1, "pve01.lab01"), "eno1", None),
            mac(100, 10, "02:00:00:00:00:0E"),
        ];
        let reports =
            vec![report("pve09.lab01", &["02:00:00:00:00:99"]), report("pve01.lab01", &["02:00:00:00:00:0E"])];
        let (objects, warnings) = admitted(reports, &current);
        assert_eq!(objects, ["pve01.lab01"]);
        assert_eq!(warnings.len(), 1);
    }
}
