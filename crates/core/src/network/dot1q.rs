//! Translate switchport settings into NetBox 802.1Q terms.

use std::collections::BTreeSet;
use std::ops::RangeInclusive;

use super::model::{Dot1q, Mode};

/// Every VID a trunk can carry.
pub const ALL_VLANS: RangeInclusive<u16> = 1..=4094;

/// An item of a switch VLAN list is neither a VID nor a range of VIDs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid VLAN list item '{0}'")]
pub struct VlanListError(pub String);

fn vid(text: &str, part: &str) -> Result<u16, VlanListError> {
    text.parse().map_err(|_| VlanListError(part.to_owned()))
}

/// Expand a switch VLAN list such as `26,2701-2703` into VIDs.
pub fn expand_vlan_list(text: &str) -> Result<BTreeSet<u16>, VlanListError> {
    let mut vids = BTreeSet::new();
    for part in text.replace(' ', "").split(',') {
        if part.is_empty() || part.eq_ignore_ascii_case("none") {
            continue;
        }
        match part.split_once('-') {
            Some((low, high)) => {
                let (low, high) = (vid(low, part)?, vid(high, part)?);
                // A range that ends before it starts holds nothing: a mistake, not an empty list.
                if low > high {
                    return Err(VlanListError(part.to_owned()));
                }
                vids.extend(low..=high);
            }
            None => {
                vids.insert(vid(part, part)?);
            }
        }
    }
    Ok(vids)
}

/// VLANs as a switch lists them: `10-12,25`; `none` without any.
pub fn vlan_list(vids: &BTreeSet<u16>) -> String {
    let mut ranges: Vec<(u16, u16)> = Vec::new();
    for vid in vids {
        match ranges.last_mut() {
            Some((_, last)) if last.checked_add(1) == Some(*vid) => *last = *vid,
            _ => ranges.push((*vid, *vid)),
        }
    }
    if ranges.is_empty() {
        return "none".to_owned();
    }
    let written: Vec<String> = ranges
        .into_iter()
        .map(|(first, last)| if first == last { first.to_string() } else { format!("{first}-{last}") })
        .collect();
    written.join(",")
}

pub fn access(vlan: Option<u16>, defined: &BTreeSet<u16>) -> Dot1q {
    Dot1q { mode: Mode::Access, untagged_vlan: vlan.filter(|vid| defined.contains(vid)), tagged_vlans: Vec::new() }
}

/// Build a trunk; `allowed=None` means the switch reported every VLAN (IOS `ALL`).
pub fn trunk(native: Option<u16>, allowed: Option<&BTreeSet<u16>>, defined: &BTreeSet<u16>) -> Dot1q {
    let untagged_vlan = native.filter(|vid| defined.contains(vid));
    let Some(allowed) = allowed.filter(|allowed| !ALL_VLANS.into_iter().all(|vid| allowed.contains(&vid))) else {
        return Dot1q { mode: Mode::TaggedAll, untagged_vlan, tagged_vlans: Vec::new() };
    };
    // Only VLANs defined on the switch: `1-4091,4093-4094` must not create thousands of VLANs.
    let tagged_vlans = allowed.intersection(defined).copied().filter(|vid| Some(*vid) != native).collect();
    Dot1q { mode: Mode::Tagged, untagged_vlan, tagged_vlans }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vids<const N: usize>(values: [u16; N]) -> BTreeSet<u16> {
        BTreeSet::from(values)
    }

    fn expand(text: &str) -> BTreeSet<u16> {
        expand_vlan_list(text).expect("a valid VLAN list")
    }

    fn dot1q<const N: usize>(mode: Mode, untagged_vlan: Option<u16>, tagged_vlans: [u16; N]) -> Dot1q {
        Dot1q { mode, untagged_vlan, tagged_vlans: tagged_vlans.to_vec() }
    }

    #[test]
    fn expand_vlan_list_reads_vids_and_ranges() {
        assert_eq!(expand("26,2701-2703"), vids([26, 2701, 2702, 2703]));
        assert_eq!(expand("none"), vids([]));
        assert_eq!(expand(""), vids([]));
    }

    #[test]
    fn expand_vlan_list_ignores_spaces_and_the_case_of_none() {
        assert_eq!(expand("26, 2701 - 2702"), vids([26, 2701, 2702]));
        assert_eq!(expand("NONE"), vids([]));
    }

    #[test]
    fn expand_vlan_list_refuses_what_is_not_a_vid() {
        assert_eq!(expand_vlan_list("26,ALL"), Err(VlanListError("ALL".to_owned())));
        assert_eq!(expand_vlan_list("26-x").expect_err("x is no VID").to_string(), "invalid VLAN list item '26-x'");
        // A range that ends before it starts holds no VLAN: a typing mistake, not an empty list.
        assert_eq!(expand_vlan_list("10,20-10"), Err(VlanListError("20-10".to_owned())));
        assert_eq!(expand("12-12"), vids([12]));
    }

    #[test]
    fn a_vlan_list_is_written_as_a_switch_writes_it() {
        assert_eq!(vlan_list(&vids([26, 2701, 2702, 2703])), "26,2701-2703");
        assert_eq!(vlan_list(&vids([4, 5, 6, 10, 12, 4094])), "4-6,10,12,4094");
        assert_eq!(vlan_list(&vids([65534, 65535])), "65534-65535");
        assert_eq!(vlan_list(&vids([])), "none");
    }

    #[test]
    fn trunk_every_vlan_is_tagged_all() {
        assert_eq!(trunk(Some(1), Some(&expand("1-4094")), &vids([1, 26])), dot1q(Mode::TaggedAll, Some(1), []));
    }

    #[test]
    fn trunk_ios_all_keyword_is_tagged_all() {
        assert_eq!(trunk(Some(1), None, &vids([1])), dot1q(Mode::TaggedAll, Some(1), []));
    }

    #[test]
    fn trunk_restricted_to_defined_vlans() {
        let allowed = expand("1-4091,4093-4094");
        assert_eq!(trunk(Some(1), Some(&allowed), &vids([1, 26, 4092])), dot1q(Mode::Tagged, Some(1), [26]));
    }

    #[test]
    fn trunk_native_not_repeated_in_tagged() {
        let defined = vids([26, 2600, 2712]);
        assert_eq!(
            trunk(Some(26), Some(&vids([26, 2600, 2712])), &defined),
            dot1q(Mode::Tagged, Some(26), [2600, 2712])
        );
    }

    #[test]
    fn trunk_native_not_defined() {
        assert_eq!(trunk(Some(999), Some(&vids([26])), &vids([26])), dot1q(Mode::Tagged, None, [26]));
    }

    #[test]
    fn access_vlan_not_defined() {
        assert_eq!(access(Some(5), &vids([1])), dot1q(Mode::Access, None, []));
        assert_eq!(access(Some(2800), &vids([1, 2800])), dot1q(Mode::Access, Some(2800), []));
    }
}
