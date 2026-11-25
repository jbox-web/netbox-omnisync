//! Site-level VLAN diff, computed once from every collected switch.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::json;

use crate::change::{Action, Change};

use super::model::Mode;
use super::names::interface_key;
use super::stack::DesiredDevice;
use super::state::NbDevice;

/// Where the VLANs of a device are kept in NetBox: at its site, or in the
/// VLAN group its site shares with others (`[[vlan_groups]]`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum VlanHome {
    /// The NetBox id of the site.
    Site(u64),
    /// The NetBox id and the name of the VLAN group.
    Group { id: u64, name: String },
}

impl fmt::Display for VlanHome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VlanHome::Site(id) => write!(formatter, "site {id}"),
            VlanHome::Group { name, .. } => write!(formatter, "VLAN group {name}"),
        }
    }
}

/// What the VLANs of one home need.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VlanDiff {
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
    /// VLANs that cannot be created: NetBox would refuse them, and a refused
    /// write ends the run.
    pub errors: Vec<String>,
}

/// `diff_vlans` for the VLANs of a site: the changes and the warnings.
pub fn diff_site_vlans(
    site_id: u64,
    wanted: &BTreeMap<String, BTreeMap<u16, String>>,
    current: &BTreeMap<u16, (u64, String)>,
    unnamed: &BTreeSet<String>,
) -> (Vec<Change>, Vec<String>) {
    let diff = diff_vlans(&VlanHome::Site(site_id), wanted, current, unnamed);
    (diff.changes, diff.warnings)
}

/// `unnamed` holds the sources whose VLAN names are not VLAN names (a firewall
/// gives its interface names): they name a VLAN only to create one no switch
/// defines, and never rename one.
///
/// `wanted` maps each source to the VLANs it defines (VID -> name), `current`
/// each VID of the home to its NetBox id and name.
///
/// A VLAN of a group is created in the group and at no site: NetBox refuses a
/// VLAN of a site on an interface of another one. And NetBox makes a name
/// unique in a group: a VLAN whose name another VLAN of the group has is not
/// created (an error naming both), nor renamed (a warning).
pub fn diff_vlans(
    home: &VlanHome,
    wanted: &BTreeMap<String, BTreeMap<u16, String>>,
    current: &BTreeMap<u16, (u64, String)>,
    unnamed: &BTreeSet<String>,
) -> VlanDiff {
    let mut names: BTreeMap<u16, BTreeSet<&str>> = BTreeMap::new();
    let mut fallback: BTreeMap<u16, BTreeSet<&str>> = BTreeMap::new();
    for (source, vlans) in wanted {
        let target = if unnamed.contains(source) { &mut fallback } else { &mut names };
        for (vid, name) in vlans {
            target.entry(*vid).or_default().insert(name);
        }
    }
    for (vid, candidates) in &fallback {
        if !names.contains_key(vid)
            && !current.contains_key(vid)
            && let Some(first) = candidates.first()
        {
            names.insert(*vid, BTreeSet::from([*first]));
        }
    }
    // The names taken in a group, with the VLAN that has each: those NetBox
    // holds, then those this diff creates or gives.
    let mut taken: BTreeMap<String, u16> = match home {
        VlanHome::Group { .. } => current.iter().map(|(vid, (_, name))| (name.clone(), *vid)).collect(),
        VlanHome::Site(_) => BTreeMap::new(),
    };
    let grouped = matches!(home, VlanHome::Group { .. });
    let mut diff = VlanDiff::default();
    for (vid, candidates) in &names {
        let Some(name) = candidates.first() else {
            continue;
        };
        let key = vid.to_string();
        let place = match home {
            VlanHome::Site(id) => ("site", json!(id)),
            VlanHome::Group { id, .. } => ("group", json!(id)),
        };
        let create = || {
            Change::new("vlan", Action::Create, "", &key).fields([
                place.clone(),
                ("vid", json!(vid)),
                ("name", json!(name)),
            ])
        };
        let other = taken.get(*name).copied().filter(|other| other != vid);
        let existing = current.get(vid);
        if candidates.len() > 1 {
            // A name that flips at every run would never let the diff reach zero.
            let listed: Vec<&str> = candidates.iter().copied().collect();
            diff.warnings.push(format!(
                "VLAN {vid}: switches disagree on its name ({}); name left untouched",
                listed.join(", ")
            ));
        }
        match (existing, other) {
            (None, Some(other)) => diff
                .errors
                .push(format!("VLAN {vid}: its name {name} is the one of VLAN {other} in {home}; not created")),
            (None, None) => {
                if grouped {
                    taken.insert((*name).to_owned(), *vid);
                }
                diff.changes.push(create());
            }
            (Some(_), _) if candidates.len() > 1 => {}
            (Some((_, current_name)), _) if current_name == name => {}
            (Some(_), Some(other)) => diff
                .warnings
                .push(format!("VLAN {vid}: its name {name} is the one of VLAN {other} in {home}; name left untouched")),
            (Some((id, current_name)), None) => {
                if grouped {
                    // The old name is free once this rename is written, which
                    // comes before the renames of higher VLAN numbers.
                    taken.remove(current_name);
                    taken.insert((*name).to_owned(), *vid);
                }
                diff.changes.push(
                    Change::new("vlan", Action::Update, "", &key)
                        .fields([("name", json!(name))])
                        .before([("name", json!(current_name))])
                        .id(*id),
                );
            }
        }
    }
    diff
}

/// The number a port is read on when its VLAN is not the one of the group of
/// its site: 0 is no VLAN id (IEEE 802.1Q), so it is never what a source
/// asks for, and the diff always finds a difference to write.
pub const FOREIGN_VLAN: u16 = 0;

/// Reads the VLANs `device` points to that are not VLANs of its group as
/// `FOREIGN_VLAN`: the diff then writes the field again, with the VLAN of
/// the group that has that number, or with nothing when the source no longer
/// puts a VLAN there.
///
/// A port only knows the number of its VLAN, and NetBox may hold two VLANs
/// of that number: the one of the site, from before the site joined a group,
/// and the one of the group. `group_vlans` maps each VLAN number of the group
/// to its NetBox id.
pub fn mark_foreign_vlans(device: &mut NbDevice, group_vlans: &BTreeMap<u16, (u64, String)>) {
    let in_group = |vid: u16, id: u64| group_vlans.get(&vid).is_some_and(|(held, _)| *held == id);
    for interface in device.interfaces.values_mut() {
        if let (Some(vid), Some(id)) = (interface.untagged_vlan, interface.untagged_vlan_id)
            && !in_group(vid, id)
        {
            interface.untagged_vlan = Some(FOREIGN_VLAN);
        }
        // Without the ids (an older reader), the list is taken as it is.
        if !interface.tagged_vlan_ids.is_empty() {
            let mut tagged: Vec<u16> = interface
                .tagged_vlan_ids
                .iter()
                .map(|(vid, id)| if in_group(*vid, *id) { *vid } else { FOREIGN_VLAN })
                .collect();
            tagged.sort_unstable();
            interface.tagged_vlans = tagged;
        }
    }
}

/// Takes the VLANs that are not in `held` out of the ports of `device`, and
/// gives them.
///
/// For a source that names no VLAN (a configuration report): the VLANs of
/// its ports are only numbers, and one NetBox does not hold cannot be
/// created. `held` is every VLAN number of the home of the device, the VLANs
/// this run creates there included. An access VLAN left out is unknown to
/// NetBox, not absent from the port: the one the port has there is kept.
pub fn leave_out_missing_vlans(device: &mut DesiredDevice, held: &BTreeSet<u16>) -> BTreeSet<u16> {
    let mut missing = BTreeSet::new();
    for interface in device.interfaces.values_mut() {
        let Some(dot1q) = interface.dot1q.as_mut() else {
            continue;
        };
        if let Some(vid) = dot1q.untagged_vlan.filter(|vid| !held.contains(vid)) {
            missing.insert(vid);
            dot1q.untagged_vlan = None;
            interface.untagged_vlan_managed = false;
        }
        missing.extend(dot1q.tagged_vlans.iter().filter(|vid| !held.contains(vid)));
        dot1q.tagged_vlans.retain(|vid| held.contains(vid));
    }
    missing
}

/// Settles what NetBox holds as the untagged VLAN of the trunks of `device`
/// whose source does not tell their native VLAN (a configuration report).
///
/// Such a source lists the VLANs a trunk allows, the native one among them,
/// and leaves the untagged VLAN of the port as NetBox has it. On a port
/// NetBox has as a trunk, that VLAN is its native one, entered by who knew
/// it: it is not repeated among the tagged VLANs, as a switch that tells its
/// native VLAN does not repeat it (`dot1q::trunk`). On a port NetBox has as
/// an access port, it is the access VLAN of a port that is no longer one:
/// nobody told it as a native VLAN, and it is cleared.
///
/// Read before `mark_foreign_vlans`, which hides the number of a VLAN of the
/// site once the site is in a group.
pub fn settle_native_vlans(device: &mut DesiredDevice, current: &NbDevice) {
    for (name, interface) in &mut device.interfaces {
        let Some(dot1q) = interface.dot1q.as_mut().filter(|dot1q| dot1q.mode != Mode::Access) else {
            continue;
        };
        let Some(held) = current.interfaces.get(&interface_key(name)) else {
            continue;
        };
        if interface.untagged_vlan_managed {
            continue;
        }
        if held.mode.as_deref() == Some(Mode::Access.as_str()) {
            interface.untagged_vlan_managed = true;
        } else if let Some(native) = held.untagged_vlan {
            dot1q.tagged_vlans.retain(|vid| *vid != native);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{Dot1q, Interface};
    use super::super::state::NbInterface;
    use super::*;

    /// A trunk as a report and its description give it: its tagged VLANs, not its native one.
    fn report_trunk(name: &str, tagged_vlans: &[u16]) -> Interface {
        Interface { untagged_vlan_managed: false, ..port(name, Mode::Tagged, None, tagged_vlans) }
    }

    fn settled(trunk: Interface, held: NbInterface) -> Interface {
        let mut device = DesiredDevice::new("fplab1-sw001", None);
        device.interfaces.insert(trunk.name.clone(), trunk.clone());
        let current = NbDevice {
            id: 1,
            name: "fplab1-sw001".to_owned(),
            site_id: 13,
            site: String::new(),
            serial: String::new(),
            primary_ip4: None,
            interfaces: BTreeMap::from([(interface_key(&held.name), held)]),
            ips: Vec::new(),
        };
        settle_native_vlans(&mut device, &current);
        device.interfaces.remove(&trunk.name).expect("the trunk")
    }

    fn held(mode: &str, untagged_vlan: Option<u16>) -> NbInterface {
        NbInterface { mode: Some(mode.to_owned()), untagged_vlan, ..NbInterface::new(1, "GigabitEthernet1/0/26") }
    }

    // The six trunks of each stack whose native VLAN is 24: `GigabitEthernet1/0/26 | Yes |
    // lab1-pve01.prod/eno1/1G V:19-20,24 | 2 | Trunk` in fplab1-sw001-convention.html, the 24 being
    // `Trunking Native Mode VLAN` of the port. The report does not give it, NetBox holds it.
    #[test]
    fn the_native_vlan_netbox_has_on_a_trunk_is_not_repeated_among_its_tagged_vlans() {
        let trunk = report_trunk("GigabitEthernet1/0/26", &[19, 20, 24]);
        assert_eq!(settled(trunk.clone(), held("tagged", Some(24))), report_trunk("GigabitEthernet1/0/26", &[19, 20]));
        assert_eq!(
            settled(trunk.clone(), held("tagged-all", Some(24))),
            report_trunk("GigabitEthernet1/0/26", &[19, 20])
        );
        // Without an untagged VLAN in NetBox, or on a port NetBox does not have, the list is whole.
        assert_eq!(settled(trunk.clone(), held("tagged", None)), trunk);
        let other = NbInterface { untagged_vlan: Some(24), ..NbInterface::new(2, "GigabitEthernet1/0/27") };
        assert_eq!(settled(trunk.clone(), other), trunk);
    }

    // The untagged VLAN of a port NetBox has as an access port is its access VLAN, not the native
    // VLAN of the trunk the report now says it is: nobody told that one.
    #[test]
    fn the_access_vlan_of_a_port_that_became_a_trunk_is_not_taken_for_its_native_vlan() {
        let trunk = report_trunk("GigabitEthernet1/0/26", &[10, 11, 12]);
        let wanted = settled(trunk.clone(), held("access", Some(12)));
        // The whole list is tagged, and the access VLAN is cleared.
        assert_eq!(wanted, Interface { untagged_vlan_managed: true, ..trunk.clone() });
        // A trunk without list is cleared of it as well.
        let bare = Interface { tagged_vlans_managed: false, ..report_trunk("GigabitEthernet1/0/26", &[]) };
        assert_eq!(settled(bare.clone(), held("access", Some(12))), Interface { untagged_vlan_managed: true, ..bare });
    }

    // A source that tells the untagged VLAN of its ports is left as it is.
    #[test]
    fn a_port_whose_untagged_vlan_the_source_tells_is_not_settled() {
        let trunk = port("GigabitEthernet1/0/26", Mode::Tagged, Some(1), &[19, 24]);
        assert_eq!(settled(trunk.clone(), held("tagged", Some(24))), trunk);
        let access = port("GigabitEthernet1/0/26", Mode::Access, Some(12), &[]);
        assert_eq!(settled(access.clone(), held("tagged", Some(24))), access);
    }

    fn port(name: &str, mode: Mode, untagged_vlan: Option<u16>, tagged_vlans: &[u16]) -> Interface {
        Interface {
            dot1q: Some(Dot1q { mode, untagged_vlan, tagged_vlans: tagged_vlans.to_vec() }),
            ..Interface::new(name, true)
        }
    }

    #[test]
    fn the_vlans_netbox_does_not_hold_are_left_out_of_the_ports_and_given() {
        let mut device = DesiredDevice::new("fplab1-sw001", None);
        let ports = [
            port("Gi1/0/1", Mode::Access, Some(1511), &[]),
            port("Gi1/0/2", Mode::Access, Some(12), &[]),
            port("Te1/1/8", Mode::Tagged, None, &[4, 10, 12, 952]),
            Interface::new("Vlan952", true),
        ];
        device.interfaces = ports.iter().cloned().map(|port| (port.name.clone(), port)).collect();
        let missing = leave_out_missing_vlans(&mut device, &BTreeSet::from([10, 12]));
        assert_eq!(missing, BTreeSet::from([4, 952, 1511]));
        // The access VLAN NetBox does not hold is not known to it: the one the port has there is kept.
        let unknown = &device.interfaces["Gi1/0/1"];
        assert_eq!(unknown.dot1q, Some(Dot1q { mode: Mode::Access, untagged_vlan: None, tagged_vlans: Vec::new() }));
        assert!(!unknown.untagged_vlan_managed);
        assert_eq!(device.interfaces["Gi1/0/2"], ports[1]);
        assert_eq!(device.interfaces["Te1/1/8"], port("Te1/1/8", Mode::Tagged, None, &[10, 12]));
        assert_eq!(device.interfaces["Vlan952"], ports[3]);
    }

    fn wanted(sources: &[(&str, u16, &str)]) -> BTreeMap<String, BTreeMap<u16, String>> {
        sources
            .iter()
            .map(|(source, vid, name)| ((*source).to_owned(), BTreeMap::from([(*vid, (*name).to_owned())])))
            .collect()
    }

    fn current(vlans: &[(u16, u64, &str)]) -> BTreeMap<u16, (u64, String)> {
        vlans.iter().map(|(vid, id, name)| (*vid, (*id, (*name).to_owned()))).collect()
    }

    fn weak() -> BTreeSet<String> {
        BTreeSet::from(["fw01.dc1".to_owned()])
    }

    fn create(vid: u16, name: &str) -> Change {
        Change::new("vlan", Action::Create, "", &vid.to_string()).fields([
            ("site", json!(12)),
            ("vid", json!(vid)),
            ("name", json!(name)),
        ])
    }

    #[test]
    fn missing_vlan_is_created() {
        let (changes, warnings) =
            diff_site_vlans(12, &wanted(&[("nexus01.lab01", 2800, "Admin")]), &current(&[]), &BTreeSet::new());
        assert_eq!(
            changes,
            [Change::new("vlan", Action::Create, "", "2800").fields([
                ("site", json!(12)),
                ("vid", json!(2800)),
                ("name", json!("Admin")),
            ])]
        );
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn name_follows_the_switches() {
        let (changes, _) = diff_site_vlans(
            12,
            &wanted(&[("nexus01.lab01", 2800, "Admin")]),
            &current(&[(2800, 112, "VLAN2800-Admin")]),
            &BTreeSet::new(),
        );
        assert_eq!(
            changes,
            [Change::new("vlan", Action::Update, "", "2800")
                .fields([("name", json!("Admin"))])
                .before([("name", json!("VLAN2800-Admin"))])
                .id(112)]
        );
    }

    #[test]
    fn unchanged_vlan_gives_nothing() {
        assert_eq!(
            diff_site_vlans(12, &wanted(&[("a", 1, "default")]), &current(&[(1, 5, "default")]), &BTreeSet::new()),
            (vec![], vec![])
        );
    }

    #[test]
    fn conflicting_names_leave_vlan_untouched() {
        let (changes, warnings) = diff_site_vlans(
            12,
            &wanted(&[("nexus01.lab01", 2800, "Admin"), ("nexus03.lab01", 2800, "Management")]),
            &current(&[(2800, 112, "VLAN2800-Admin")]),
            &BTreeSet::new(),
        );
        assert_eq!(changes, []);
        assert_eq!(warnings, ["VLAN 2800: switches disagree on its name (Admin, Management); name left untouched"]);
    }

    // Not in the Python tests: read from `vlans.py`, a VLAN the switches disagree
    // on is still created when NetBox lacks it, under the first name in order.
    #[test]
    fn conflicting_names_still_create_a_missing_vlan() {
        let (changes, warnings) = diff_site_vlans(
            12,
            &wanted(&[("nexus01.lab01", 2800, "Management"), ("nexus03.lab01", 2800, "Admin")]),
            &current(&[]),
            &BTreeSet::new(),
        );
        assert_eq!(changes, [create(2800, "Admin")]);
        assert_eq!(warnings, ["VLAN 2800: switches disagree on its name (Admin, Management); name left untouched"]);
    }

    #[test]
    fn vlan_is_never_deleted() {
        let (changes, _) = diff_site_vlans(
            12,
            &wanted(&[("a", 1, "default")]),
            &current(&[(1, 5, "default"), (99, 6, "old")]),
            &BTreeSet::new(),
        );
        assert_eq!(changes, []);
    }

    #[test]
    fn source_that_does_not_name_vlans_still_creates_a_missing_one() {
        let (changes, warnings) = diff_site_vlans(12, &wanted(&[("fw01.dc1", 12, "HOUSING")]), &current(&[]), &weak());
        assert_eq!(changes, [create(12, "HOUSING")]);
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn source_that_does_not_name_vlans_never_renames_one() {
        let wanted = wanted(&[("fw01.dc1", 12, "HOUSING")]);
        assert_eq!(diff_site_vlans(12, &wanted, &current(&[(12, 7, "VLAN12-Housing")]), &weak()), (vec![], vec![]));
    }

    #[test]
    fn switch_names_the_vlan_whatever_the_other_source_says() {
        let wanted = wanted(&[("fw01.dc1", 12, "HOUSING"), ("nexus01.lab01", 12, "Housing")]);
        assert_eq!(diff_site_vlans(12, &wanted, &current(&[]), &weak()), (vec![create(12, "Housing")], vec![]));
        assert_eq!(diff_site_vlans(12, &wanted, &current(&[(12, 7, "Housing")]), &weak()), (vec![], vec![]));
    }

    fn east() -> VlanHome {
        VlanHome::Group { id: 7, name: "East".to_owned() }
    }

    #[test]
    fn a_missing_vlan_of_a_group_is_created_in_the_group_and_at_no_site() {
        let diff = diff_vlans(&east(), &wanted(&[("nexus01.lab01", 2800, "Admin")]), &current(&[]), &BTreeSet::new());
        assert_eq!(
            diff.changes,
            [Change::new("vlan", Action::Create, "", "2800").fields([
                ("group", json!(7)),
                ("vid", json!(2800)),
                ("name", json!("Admin")),
            ])]
        );
        assert_eq!((diff.warnings, diff.errors), (vec![], vec![]));
    }

    #[test]
    fn a_vlan_of_a_group_is_renamed_as_one_of_a_site_is() {
        let held = current(&[(2800, 112, "VLAN2800-Admin")]);
        let diff = diff_vlans(&east(), &wanted(&[("nexus01.lab01", 2800, "Admin")]), &held, &BTreeSet::new());
        assert_eq!(
            diff.changes,
            [Change::new("vlan", Action::Update, "", "2800")
                .fields([("name", json!("Admin"))])
                .before([("name", json!("VLAN2800-Admin"))])
                .id(112)]
        );
    }

    // NetBox refuses two VLANs of a group under one name, and a refused write ends the run.
    #[test]
    fn a_vlan_whose_name_another_vlan_of_the_group_has_is_an_error_naming_both_and_is_not_created() {
        let held = current(&[(120, 5, "dmz")]);
        let diff = diff_vlans(&east(), &wanted(&[("nexus01.lab01", 130, "dmz")]), &held, &BTreeSet::new());
        assert_eq!(diff.changes, []);
        assert_eq!(diff.errors, ["VLAN 130: its name dmz is the one of VLAN 120 in VLAN group East; not created"]);
    }

    #[test]
    fn two_vlans_a_diff_would_create_under_one_name_in_a_group_are_not_both_created() {
        let both: BTreeMap<String, BTreeMap<u16, String>> = BTreeMap::from([(
            "nexus01.lab01".to_owned(),
            BTreeMap::from([(120, "dmz".to_owned()), (130, "dmz".to_owned())]),
        )]);
        let diff = diff_vlans(&east(), &both, &current(&[]), &BTreeSet::new());
        assert_eq!(diff.changes.iter().map(|change| change.key.as_str()).collect::<Vec<_>>(), ["120"]);
        assert_eq!(diff.errors, ["VLAN 130: its name dmz is the one of VLAN 120 in VLAN group East; not created"]);
    }

    #[test]
    fn a_rename_to_a_name_another_vlan_of_the_group_has_is_left_out_with_a_warning() {
        let held = current(&[(120, 5, "dmz"), (130, 6, "old")]);
        let diff = diff_vlans(&east(), &wanted(&[("nexus01.lab01", 130, "dmz")]), &held, &BTreeSet::new());
        assert_eq!((diff.changes, diff.errors), (vec![], vec![]));
        assert_eq!(
            diff.warnings,
            ["VLAN 130: its name dmz is the one of VLAN 120 in VLAN group East; name left untouched"]
        );
    }

    // The rename of 120 frees `dmz` in the same diff: 130 takes it, and the
    // applier writes 120 first (the changes come in VLAN order).
    #[test]
    fn a_name_a_rename_frees_in_the_group_can_be_taken_in_the_same_diff() {
        let held = current(&[(120, 5, "dmz"), (130, 6, "old")]);
        let both: BTreeMap<String, BTreeMap<u16, String>> = BTreeMap::from([(
            "nexus01.lab01".to_owned(),
            BTreeMap::from([(120, "prod".to_owned()), (130, "dmz".to_owned())]),
        )]);
        let diff = diff_vlans(&east(), &both, &held, &BTreeSet::new());
        assert_eq!((diff.warnings, diff.errors), (vec![], vec![]));
        let renamed: Vec<(&str, &serde_json::Value)> =
            diff.changes.iter().map(|change| (change.key.as_str(), &change.fields["name"])).collect();
        assert_eq!(renamed, [("120", &json!("prod")), ("130", &json!("dmz"))]);
    }

    // At a site NetBox lets two VLANs share a name: nothing changes there.
    #[test]
    fn two_vlans_of_a_site_may_share_a_name() {
        let held = current(&[(120, 5, "dmz")]);
        let (changes, warnings) =
            diff_site_vlans(12, &wanted(&[("nexus01.lab01", 130, "dmz")]), &held, &BTreeSet::new());
        assert_eq!(changes, [create(130, "dmz")]);
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn a_home_is_shown_as_the_site_or_the_group_it_is() {
        assert_eq!(VlanHome::Site(12).to_string(), "site 12");
        assert_eq!(east().to_string(), "VLAN group East");
    }

    // A port only knows the number of its VLAN. One still on a VLAN of the
    // site is read as on a VLAN no source names, so that the diff rewrites
    // it: with the VLAN of the group of that number, or with nothing when the
    // device no longer wants one there.
    #[test]
    fn a_vlan_a_port_points_to_outside_its_group_is_read_as_one_to_rewrite() {
        use crate::network::state::NbInterface;
        let port = |name: &str, untagged: Option<(u16, u64)>, tagged: &[(u16, u64)]| {
            let mut tagged_vlans: Vec<u16> = tagged.iter().map(|(vid, _)| *vid).collect();
            tagged_vlans.sort_unstable();
            NbInterface {
                untagged_vlan: untagged.map(|(vid, _)| vid),
                untagged_vlan_id: untagged.map(|(_, id)| id),
                tagged_vlans,
                tagged_vlan_ids: tagged.to_vec(),
                ..NbInterface::new(1, name)
            }
        };
        let mut device = NbDevice {
            id: 1,
            name: "fw01".to_owned(),
            site_id: 2,
            site: "east-01".to_owned(),
            serial: String::new(),
            primary_ip4: None,
            interfaces: BTreeMap::from([
                // On the VLAN 10 of the site (id 30): not the one of the group (id 31).
                ("a".to_owned(), port("a", Some((10, 30)), &[])),
                // Already on the one of the group.
                ("b".to_owned(), port("b", Some((10, 31)), &[])),
                // A trunk half moved: 10 is the one of the group, 11 the one of the site, 12 is not in the group.
                ("c".to_owned(), port("c", None, &[(10, 31), (11, 32), (12, 34)])),
                // Untagged on the 10 of the group, tagged on the 10 of the site: two objects, one number.
                ("d".to_owned(), port("d", Some((10, 31)), &[(10, 30)])),
            ]),
            ips: Vec::new(),
        };
        mark_foreign_vlans(&mut device, &current(&[(10, 31, "prod"), (11, 33, "dmz")]));
        let seen: Vec<(Option<u16>, &[u16])> = device
            .interfaces
            .values()
            .map(|interface| (interface.untagged_vlan, interface.tagged_vlans.as_slice()))
            .collect();
        assert_eq!(
            seen,
            [
                (Some(FOREIGN_VLAN), &[][..]),
                (Some(10), &[][..]),
                (None, &[FOREIGN_VLAN, FOREIGN_VLAN, 10][..]),
                (Some(10), &[FOREIGN_VLAN][..]),
            ]
        );
        // VLAN 0 is never a VLAN a source names: the diff always sees a difference.
        assert_eq!(FOREIGN_VLAN, 0);
    }
}
