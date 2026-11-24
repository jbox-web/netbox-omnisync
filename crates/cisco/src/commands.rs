//! The closed lists of show commands, and the gate every command goes through
//! before it is sent to a switch.
//!
//! The switches are production devices read with a read-only intent: nothing
//! but the commands listed here may reach them.

use std::fmt;

/// How a switch is spoken to: the `type` of its inventory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Nxos,
    Ios,
}

impl Platform {
    /// The platform of an inventory `type`, None for a type that is not read over SSH.
    pub fn from_type(r#type: &str) -> Option<Self> {
        match r#type {
            "nxos" => Some(Platform::Nxos),
            "ios" => Some(Platform::Ios),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Nxos => "nxos",
            Platform::Ios => "ios",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What is read from an NX-OS switch: key -> command, in the order they are run.
pub const NXOS_COMMANDS: [(&str, &str); 9] = [
    ("interfaces", "show interface | json"),
    ("switchport", "show interface switchport | json"),
    ("lags", "show port-channel summary | json"),
    ("vlans", "show vlan brief | json"),
    ("ips", "show ip interface vrf all | json"),
    ("vrfs", "show vrf interface | json"),
    ("inventory", "show inventory | json"),
    ("lldp", "show lldp neighbors detail | json"),
    ("cdp", "show cdp neighbors detail | json"),
];

/// What is read from an IOS switch: key -> command, in the order they are run.
pub const IOS_COMMANDS: [(&str, &str); 8] = [
    ("interfaces", "show interfaces"),
    ("switchport", "show interfaces switchport"),
    ("lags", "show etherchannel summary"),
    ("vlans", "show vlan brief"),
    ("switch", "show switch"),
    ("inventory", "show inventory"),
    ("lldp", "show lldp neighbors detail"),
    ("cdp", "show cdp neighbors detail"),
];

/// A word no command may contain, whatever the platform and whatever the lists
/// become: on some of these switches a transceiver command crashes and reboots
/// the device.
const FORBIDDEN_WORD: &str = "transceiver";

/// The commands of a platform: key -> command, in the order they are run.
pub fn commands(platform: Platform) -> &'static [(&'static str, &'static str)] {
    match platform {
        Platform::Nxos => &NXOS_COMMANDS,
        Platform::Ios => &IOS_COMMANDS,
    }
}

/// A command that must not be sent to a switch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandRefused {
    /// Refused on every platform, before the lists are even looked at.
    #[error("refused, a transceiver command can crash and reboot the switch")]
    Transceiver,
    #[error("refused, not one of the {0} commands")]
    NotListed(Platform),
    #[error("refused, not one of the session settings")]
    NotSetup,
}

/// What is typed before the first command: no pagination (a `--More--` would
/// wait for a key forever), and lines as wide as the terminal asked for, so that
/// neither the echo of a command nor a long line is wrapped. A closed list, as
/// the commands are: nothing else reaches a switch.
pub const SESSION_SETUP: [&str; 2] = ["terminal length 0", "terminal width 511"];

/// Allow a line before the commands only if it is exactly one of
/// [`SESSION_SETUP`]; a line naming a transceiver is refused first, as a command is.
pub fn check_setup(line: &str) -> Result<(), CommandRefused> {
    if line.to_lowercase().contains(FORBIDDEN_WORD) {
        return Err(CommandRefused::Transceiver);
    }
    if SESSION_SETUP.contains(&line) { Ok(()) } else { Err(CommandRefused::NotSetup) }
}

/// Allow a command only if it is exactly one of the commands of the platform.
///
/// Independently and first, any command naming a transceiver is refused on
/// every platform: the list check alone would already stop it today, but this
/// refusal must survive a careless addition to the lists.
pub fn check(platform: Platform, command: &str) -> Result<(), CommandRefused> {
    if command.to_lowercase().contains(FORBIDDEN_WORD) {
        return Err(CommandRefused::Transceiver);
    }
    if commands(platform).iter().any(|(_, listed)| *listed == command) {
        Ok(())
    } else {
        Err(CommandRefused::NotListed(platform))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLATFORMS: [Platform; 2] = [Platform::Nxos, Platform::Ios];

    // What is typed before the first command goes through a closed list of its
    // own: the commands of the platforms are not the only lines that reach a switch.
    #[test]
    fn only_the_session_settings_are_typed_before_the_commands() {
        for line in SESSION_SETUP {
            assert_eq!(check_setup(line), Ok(()), "{line}");
        }
        assert_eq!(check_setup("terminal length 0\nshow running-config"), Err(CommandRefused::NotSetup));
        assert_eq!(check_setup("terminal monitor"), Err(CommandRefused::NotSetup));
        assert_eq!(check_setup("terminal transceiver"), Err(CommandRefused::Transceiver));
    }

    #[test]
    fn the_nxos_list_is_the_one_of_the_python_tool() {
        assert_eq!(
            commands(Platform::Nxos),
            [
                ("interfaces", "show interface | json"),
                ("switchport", "show interface switchport | json"),
                ("lags", "show port-channel summary | json"),
                ("vlans", "show vlan brief | json"),
                ("ips", "show ip interface vrf all | json"),
                ("vrfs", "show vrf interface | json"),
                ("inventory", "show inventory | json"),
                ("lldp", "show lldp neighbors detail | json"),
                ("cdp", "show cdp neighbors detail | json"),
            ]
        );
    }

    #[test]
    fn the_ios_list_is_the_one_of_the_python_tool() {
        assert_eq!(
            commands(Platform::Ios),
            [
                ("interfaces", "show interfaces"),
                ("switchport", "show interfaces switchport"),
                ("lags", "show etherchannel summary"),
                ("vlans", "show vlan brief"),
                ("switch", "show switch"),
                ("inventory", "show inventory"),
                ("lldp", "show lldp neighbors detail"),
                ("cdp", "show cdp neighbors detail"),
            ]
        );
    }

    #[test]
    fn platform_of_an_inventory_type() {
        assert_eq!(Platform::from_type("nxos"), Some(Platform::Nxos));
        assert_eq!(Platform::from_type("ios"), Some(Platform::Ios));
        assert_eq!(Platform::from_type("nipper"), None);
        assert_eq!(Platform::from_type("fortios"), None);
        assert_eq!(Platform::from_type("NXOS"), None);
    }

    #[test]
    fn every_listed_command_passes_for_its_platform() {
        for platform in PLATFORMS {
            for (key, command) in commands(platform) {
                assert_eq!(check(platform, command), Ok(()), "{platform} {key}");
            }
        }
    }

    #[test]
    fn a_listed_nxos_command_is_refused_for_ios() {
        assert_eq!(
            check(Platform::Ios, "show port-channel summary | json"),
            Err(CommandRefused::NotListed(Platform::Ios))
        );
        assert_eq!(check(Platform::Ios, "show interface | json"), Err(CommandRefused::NotListed(Platform::Ios)));
    }

    #[test]
    fn a_listed_ios_command_is_refused_for_nxos() {
        assert_eq!(check(Platform::Nxos, "show interfaces"), Err(CommandRefused::NotListed(Platform::Nxos)));
        assert_eq!(check(Platform::Nxos, "show vlan brief"), Err(CommandRefused::NotListed(Platform::Nxos)));
    }

    #[test]
    fn an_arbitrary_command_is_refused() {
        for platform in PLATFORMS {
            for command in ["show running-config", "configure terminal", "reload", ""] {
                assert_eq!(check(platform, command), Err(CommandRefused::NotListed(platform)), "{platform} {command}");
            }
        }
    }

    #[test]
    fn a_listed_command_with_anything_added_is_refused() {
        for command in [
            "show vlan brief ",
            " show vlan brief",
            "show vlan brief\nreload",
            "show vlan brief ; reload",
            "SHOW VLAN BRIEF",
        ] {
            assert_eq!(check(Platform::Ios, command), Err(CommandRefused::NotListed(Platform::Ios)), "{command:?}");
        }
    }

    #[test]
    fn a_transceiver_command_is_refused_on_both_platforms() {
        for platform in PLATFORMS {
            for command in [
                "show interface transceiver",
                "show interface Ethernet1/1 transceiver details",
                "SHOW INTERFACE TRANSCEIVER",
            ] {
                assert_eq!(check(platform, command), Err(CommandRefused::Transceiver), "{platform} {command}");
            }
        }
    }

    #[test]
    fn no_listed_command_names_a_transceiver() {
        for (key, command) in NXOS_COMMANDS.iter().chain(IOS_COMMANDS.iter()) {
            assert!(!command.to_lowercase().contains("transceiver"), "{key}: {command}");
        }
    }

    #[test]
    fn the_refusals_say_why() {
        assert_eq!(
            CommandRefused::Transceiver.to_string(),
            "refused, a transceiver command can crash and reboot the switch"
        );
        assert_eq!(CommandRefused::NotListed(Platform::Nxos).to_string(), "refused, not one of the nxos commands");
    }
}
