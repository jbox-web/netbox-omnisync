//! The names NetBox has for the hardware of a server, shared by every source
//! that reports one (a vCenter for its hosts, a BMC for its system): two
//! sources that describe the same server must ask for the same manufacturer
//! and the same device type, or each run would rename what the other wrote.
//!
//! The table and the slug are those of netbox-sync v1.8.0, which filled the
//! NetBox this tool takes over (`docs/vmware-reference.md`).

/// How a vendor name is recognised.
#[derive(Clone, Copy)]
enum Vendor {
    Is(&'static str),
    StartsWith(&'static str),
    Contains(&'static str),
}

/// The vendors netbox-sync renamed, in its order, the first match winning
/// (`module/netbox/manufacturer_mapping.py`): each pattern in lower case, and
/// the name it gives.
const VENDORS: [(Vendor, &str); 22] = [
    (Vendor::Is("amd"), "AMD"),
    (Vendor::Contains("broadcom"), "Broadcom"),
    (Vendor::Contains("cisco"), "Cisco"),
    (Vendor::Contains("dell"), "Dell"),
    (Vendor::StartsWith("fts corp"), "Fujitsu"),
    (Vendor::Contains("fujitsu"), "Fujitsu"),
    (Vendor::Contains("hisilicon"), "HiSilicon"),
    (Vendor::Is("hp"), "HPE"),
    (Vendor::Is("hpe"), "HPE"),
    (Vendor::Contains("huawei"), "Huawei"),
    (Vendor::Contains("hynix"), "Hynix"),
    (Vendor::Contains("inspur"), "Inspur"),
    (Vendor::Contains("intel"), "Intel"),
    (Vendor::StartsWith("len"), "Lenovo"),
    (Vendor::Contains("lenovo"), "Lenovo"),
    (Vendor::Contains("micron"), "Micron"),
    // netbox-sync looks for "nvidea", which no vendor writes: fixed, not ported.
    (Vendor::Contains("nvidia"), "Nvidia"),
    (Vendor::Contains("samsung"), "Samsung"),
    (Vendor::Contains("supermicro"), "Supermicro"),
    (Vendor::Contains("toshiba"), "Toshiba"),
    (Vendor::Is("wd"), "Western Digital"),
    (Vendor::Contains("western digital"), "Western Digital"),
];

/// `format_slug` of netbox-sync: space, comma and dot turned into a hyphen,
/// lower case, everything but `a-z`, `0-9`, `_` and `-` removed, then cut.
/// Hyphens are not collapsed.
pub fn format_slug(text: &str, max: usize) -> String {
    let kept = |character: &char| matches!(character, 'a'..='z' | '0'..='9' | '_' | '-');
    let separated: String =
        text.chars().map(|character| if matches!(character, ' ' | ',' | '.') { '-' } else { character }).collect();
    separated.to_lowercase().chars().filter(kept).take(max).collect()
}

/// The name NetBox has for a vendor.
pub fn manufacturer_name(vendor: &str) -> &str {
    let lowered = vendor.to_lowercase();
    let matches = |rule: &Vendor| match rule {
        Vendor::Is(name) => lowered == *name,
        Vendor::StartsWith(start) => lowered.starts_with(start),
        Vendor::Contains(part) => lowered.contains(part),
    };
    VENDORS.iter().find(|(rule, _)| matches(rule)).map_or(vendor, |(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slug_is_built_as_netbox_sync_built_it() {
        // Space, comma and dot become a hyphen, the rest that is not a-z, 0-9, _ or - goes; no hyphen is collapsed.
        assert_eq!(format_slug("Debian GNU/Linux 8 (64-bit)", 100), "debian-gnulinux-8-64-bit");
        assert_eq!(format_slug("Source: vc.lab", 100), "source-vc-lab");
        assert_eq!(format_slug("Windows 11 Pro, 64-bit", 100), "windows-11-pro--64-bit");
        assert_eq!(format_slug("Été_2", 100), "t_2");
        assert_eq!(format_slug("abcdef", 3), "abc");
    }

    #[test]
    fn a_vendor_is_named_as_netbox_sync_named_it() {
        assert_eq!(manufacturer_name("Dell Inc."), "Dell");
        assert_eq!(manufacturer_name("HP"), "HPE");
        // `^HP$` is the whole name.
        assert_eq!(manufacturer_name("HP Inc"), "HP Inc");
        // `LEN` and `FTS Corp` only have to start the name.
        assert_eq!(manufacturer_name("LENOVO"), "Lenovo");
        assert_eq!(manufacturer_name("FTS Corp Technology"), "Fujitsu");
        assert_eq!(manufacturer_name("Super Micro Computer"), "Super Micro Computer");
        assert_eq!(manufacturer_name("Supermicro"), "Supermicro");
        assert_eq!(manufacturer_name("Cisco Systems Inc"), "Cisco");
        assert_eq!(manufacturer_name("Acme"), "Acme");
    }

    // netbox-sync looks for "nvidea", a typo: NVIDIA hardware was never named
    // Nvidia. Fixed here, not ported (docs/reference-defects.md).
    #[test]
    fn nvidia_hardware_is_named_nvidia() {
        assert_eq!(manufacturer_name("NVIDIA Corporation"), "Nvidia");
        assert_eq!(manufacturer_name("nvidia"), "Nvidia");
    }
}
