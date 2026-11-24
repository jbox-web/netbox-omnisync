//! Name normalisation shared by the parsers, the diff and the cable resolver.

use std::sync::LazyLock;

use regex::Regex;

// Interface prefix (lower-cased) -> long form. Long forms map to themselves so
// that an already long name comes back unchanged.
const PREFIXES: &[(&str, &str)] = &[
    ("eth", "Ethernet"),
    ("ethernet", "Ethernet"),
    ("po", "port-channel"),
    ("port-channel", "port-channel"),
    ("lo", "loopback"),
    ("loopback", "loopback"),
    ("vl", "Vlan"),
    ("vlan", "Vlan"),
    ("mgmt", "mgmt"),
    ("gi", "GigabitEthernet"),
    ("gigabitethernet", "GigabitEthernet"),
    ("te", "TenGigabitEthernet"),
    ("tengigabitethernet", "TenGigabitEthernet"),
    ("fa", "FastEthernet"),
    ("fastethernet", "FastEthernet"),
];
// IOS spells port-channels and loopbacks with a capital letter.
const IOS_PREFIXES: &[(&str, &str)] =
    &[("po", "Port-channel"), ("port-channel", "Port-channel"), ("lo", "Loopback"), ("loopback", "Loopback")];

static NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Za-z-]+)(\d.*)$").expect("valid pattern"));
static MAC_CHARS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9A-Fa-f.:-]+$").expect("valid pattern"));
static SERIAL_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\([^)]*\)$").expect("valid pattern"));

fn lookup(table: &[(&str, &'static str)], key: &str) -> Option<&'static str> {
    table.iter().find(|(prefix, _)| *prefix == key).map(|(_, full)| *full)
}

/// Expand an abbreviated interface name (`Eth1/1`, `Te1/0/2`, `Po1`).
pub fn long_interface_name(name: &str, platform: Option<&str>) -> String {
    let stripped = name.trim();
    let Some(captures) = NAME.captures(stripped) else {
        return stripped.to_owned();
    };
    let (prefix, rest) = (&captures[1], &captures[2]);
    let key = prefix.to_lowercase();
    if platform == Some("ios")
        && let Some(full) = lookup(IOS_PREFIXES, &key)
    {
        return format!("{full}{rest}");
    }
    match lookup(PREFIXES, &key) {
        Some(full) => format!("{full}{rest}"),
        None => stripped.to_owned(),
    }
}

/// Identity of an interface: NetBox holds `Port-channel10` where NX-OS says `port-channel10`.
pub fn interface_key(name: &str) -> String {
    name.to_lowercase()
}

/// Return a MAC address in the NetBox form `02:08:D1:90:97:2D`, or None.
pub fn normalise_mac(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if !MAC_CHARS.is_match(value) {
        return None;
    }
    let digits: Vec<char> = value.chars().filter(|c| !matches!(c, '.' | ':' | '-')).collect();
    if digits.len() != 12 {
        return None;
    }
    let pairs: Vec<String> = digits.chunks(2).map(|pair| pair.iter().collect::<String>().to_uppercase()).collect();
    Some(pairs.join(":"))
}

pub fn is_mac(value: &str) -> bool {
    normalise_mac(Some(value)).is_some()
}

/// Remove the `(serial)` suffix CDP appends to NX-OS device IDs.
pub fn strip_serial_suffix(name: &str) -> String {
    SERIAL_SUFFIX.replace(name.trim(), "").into_owned()
}

/// Names to look up in NetBox for a neighbour: raw first, then without each domain.
pub fn name_candidates(name: &str, domains: &[&str]) -> Vec<String> {
    let mut candidates = vec![name.to_owned()];
    for domain in domains {
        if let Some(short) = name.strip_suffix(&format!(".{domain}")) {
            candidates.push(short.to_owned());
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_names_nxos() {
        assert_eq!(long_interface_name("Eth1/1", None), "Ethernet1/1");
        assert_eq!(long_interface_name("Ethernet1/51", None), "Ethernet1/51");
        assert_eq!(long_interface_name("Po10", Some("nxos")), "port-channel10");
        assert_eq!(long_interface_name("mgmt0", None), "mgmt0");
        assert_eq!(long_interface_name("loopback0", Some("nxos")), "loopback0");
    }

    #[test]
    fn long_names_ios() {
        assert_eq!(long_interface_name("Gi1/0/1", Some("ios")), "GigabitEthernet1/0/1");
        assert_eq!(long_interface_name("Te1/0/2", None), "TenGigabitEthernet1/0/2");
        assert_eq!(long_interface_name("Po1", Some("ios")), "Port-channel1");
        assert_eq!(long_interface_name("Fa0", Some("ios")), "FastEthernet0");
    }

    #[test]
    fn unknown_prefix_is_unchanged() {
        assert_eq!(long_interface_name("internal5", None), "internal5");
        assert_eq!(long_interface_name("HA", None), "HA");
    }

    #[test]
    fn surrounding_spaces_are_dropped() {
        assert_eq!(long_interface_name(" Eth1/1 ", None), "Ethernet1/1");
        assert_eq!(long_interface_name(" HA ", None), "HA");
    }

    #[test]
    fn interface_key_ignores_case() {
        assert_eq!(interface_key("Port-channel10"), "port-channel10");
        assert_eq!(interface_key("port-channel10"), "port-channel10");
        assert_eq!(interface_key("Loopback0"), "loopback0");
    }

    #[test]
    fn normalise_mac_accepts_dotted_and_colon_forms() {
        assert_eq!(normalise_mac(Some("0208.d190.972d")).as_deref(), Some("02:08:D1:90:97:2D"));
        assert_eq!(normalise_mac(Some("02:16:31:a4:10:d8")).as_deref(), Some("02:16:31:A4:10:D8"));
        assert_eq!(normalise_mac(Some("02-16-31-a4-10-d8")).as_deref(), Some("02:16:31:A4:10:D8"));
    }

    #[test]
    fn normalise_mac_refuses_what_is_not_a_mac() {
        assert_eq!(normalise_mac(Some("Ethernet1/50")), None);
        assert_eq!(normalise_mac(Some("0208.d190.97")), None);
        assert_eq!(normalise_mac(Some("")), None);
        assert_eq!(normalise_mac(None), None);
    }

    #[test]
    fn is_mac_tells_addresses_from_port_names() {
        assert!(is_mac("0216.31a4.10d8"));
        assert!(!is_mac("Ethernet1/15"));
        assert!(!is_mac("wan1"));
    }

    #[test]
    fn strip_serial_suffix_removes_the_cdp_serial() {
        assert_eq!(strip_serial_suffix("nexus02.lab01(FOC0852S7R5)"), "nexus02.lab01");
        assert_eq!(strip_serial_suffix("esx08.lab01"), "esx08.lab01");
    }

    #[test]
    fn name_candidates_strip_each_known_domain() {
        let raw = "2960-stack.lab01.switch.example.com";
        assert_eq!(name_candidates(raw, &["switch.example.com"]), [raw, "2960-stack.lab01"]);
        assert_eq!(name_candidates("nexus02.lab01", &["switch.example.com"]), ["nexus02.lab01"]);
    }
}
