//! The DNS name of an address, from a reverse lookup (PTR).
//!
//! Pure: the lookup itself is I/O and is handed in as a [`ReverseDns`]. A
//! translation asks it through [`Names`], which holds the rules shared by the
//! hypervisor sources: which addresses are looked up, what a name becomes
//! before it is written, and what is never written.
//!
//! Unknown is not empty. An address without name, a lookup that failed, a name
//! NetBox would refuse: none of them reports a `dns_name`, so NetBox keeps the
//! one it has. Nothing here ever reports an empty name.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;

/// The longest DNS name NetBox takes.
pub const MAX_DNS_NAME_LENGTH: usize = 255;

/// How many refused names a warning shows, and how much of each.
const SHOWN_NAMES: usize = 3;
const SHOWN_LENGTH: usize = 80;

/// The reverse DNS lookup, kept out of the translations: it is I/O.
///
/// netbox-ssot asked the system resolver for each address, with a timeout of
/// two seconds, and took the first name; netbox-sync asked for all of them at
/// once. When the lookup failed or gave nothing both wrote no DNS name at
/// all, so the one NetBox had was kept: a `None` does the same.
pub trait ReverseDns {
    /// The name the address resolves to, `None` when the lookup fails or
    /// gives nothing. The name is given as the DNS has it: [`Names`] removes
    /// its final dot, lowers its case and refuses what NetBox would refuse.
    fn name_of(&self, address: IpAddr) -> Option<String>;
}

impl<F: Fn(IpAddr) -> Option<String>> ReverseDns for F {
    fn name_of(&self, address: IpAddr) -> Option<String> {
        self(address)
    }
}

impl ReverseDns for BTreeMap<IpAddr, String> {
    fn name_of(&self, address: IpAddr) -> Option<String> {
        self.get(&address).cloned()
    }
}

impl ReverseDns for HashMap<IpAddr, String> {
    fn name_of(&self, address: IpAddr) -> Option<String> {
        self.get(&address).cloned()
    }
}

/// A resolver that knows no name: no DNS name is declared, and NetBox keeps
/// the ones it has.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReverseDns;

impl ReverseDns for NoReverseDns {
    fn name_of(&self, _address: IpAddr) -> Option<String> {
        None
    }
}

/// A resolver that knows no name and remembers what it was asked.
///
/// A translation is pure and synchronous, a lookup is neither: the addresses
/// are first gathered by translating with this, then looked up, then the
/// translation is done again with the answers.
#[derive(Debug, Default)]
pub struct Asked(Mutex<BTreeSet<IpAddr>>);

impl Asked {
    /// The addresses that were asked, each once.
    pub fn into_addresses(self) -> BTreeSet<IpAddr> {
        self.0.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ReverseDns for Asked {
    fn name_of(&self, address: IpAddr) -> Option<String> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(address);
        None
    }
}

/// Whether the name of an address is ever asked: never for a link-local, a
/// loopback or an unspecified address, which are the same on every machine and
/// name none.
pub fn is_looked_up(address: IpAddr) -> bool {
    // An IPv4-mapped IPv6 address is the IPv4 address it carries.
    let address = address.to_canonical();
    let link_local = match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    };
    !link_local && !address.is_loopback() && !address.is_unspecified()
}

/// What a name given by a lookup becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Written {
    /// The name to write: without its final dot, in lower case.
    Name(String),
    /// No name at all (an empty answer, the root): nothing is written.
    Nothing,
    /// A name NetBox would refuse, as it was given: nothing is written.
    Refused(String),
}

/// The name written for what a lookup gave.
///
/// The final dot of a fully qualified name is removed and the case lowered:
/// names are case-insensitive, and NetBox would otherwise hold two spellings
/// of one name. NetBox takes letters, digits, hyphens and underscores in
/// labels separated by single dots, 255 characters at most: anything else is
/// refused here rather than by NetBox, which would refuse the whole address.
pub fn written(name: &str) -> Written {
    let relative = name.strip_suffix('.').unwrap_or(name);
    if relative.is_empty() {
        return Written::Nothing;
    }
    let taken = |character: char| character.is_ascii_alphanumeric() || character == '-' || character == '_';
    let label = |label: &str| !label.is_empty() && label.chars().all(taken);
    if relative.len() > MAX_DNS_NAME_LENGTH || !relative.split('.').all(label) {
        return Written::Refused(name.to_owned());
    }
    Written::Name(relative.to_ascii_lowercase())
}

/// The one name kept among the several a PTR lookup may give: the first, in
/// alphabetical order, of the names NetBox takes. The order of the records in
/// an answer changes from one lookup to the next (round robin): taking the
/// first as it comes would rewrite the name at every run.
///
/// When NetBox takes none of them, the first of the others is given, to be
/// refused and told by [`Names`]; `None` when there is no name at all.
pub fn preferred<I: IntoIterator<Item = String>>(names: I) -> Option<String> {
    let mut taken: Vec<(String, String)> = Vec::new();
    let mut refused: Vec<String> = Vec::new();
    for name in names {
        match written(&name) {
            Written::Name(written) => taken.push((written, name)),
            Written::Refused(_) => refused.push(name),
            Written::Nothing => {}
        }
    }
    let first_taken = taken.into_iter().min().map(|(_, name)| name);
    first_taken.or_else(|| refused.into_iter().min())
}

/// The names of the addresses of one translation.
pub struct Names<'a> {
    resolver: &'a dyn ReverseDns,
    refused: BTreeMap<IpAddr, String>,
}

impl<'a> Names<'a> {
    pub fn new(resolver: &'a dyn ReverseDns) -> Self {
        Names { resolver, refused: BTreeMap::new() }
    }

    /// The `dns_name` to report for an address; `None` reports none, and
    /// NetBox keeps the one it has.
    pub fn of(&mut self, address: IpAddr) -> Option<String> {
        // An IPv4-mapped IPv6 address is the IPv4 address it carries, and is asked as such.
        let address = address.to_canonical();
        if !is_looked_up(address) {
            return None;
        }
        match written(&self.resolver.name_of(address)?) {
            Written::Name(name) => Some(name),
            Written::Nothing => None,
            Written::Refused(name) => {
                self.refused.insert(address, name);
                None
            }
        }
    }

    /// One warning for every name that was refused, `None` when none was: the
    /// tool runs every few minutes and a wrong PTR record stays wrong for days.
    pub fn warning(&self) -> Option<String> {
        if self.refused.is_empty() {
            return None;
        }
        // A name is shown cut and escaped: it comes from the network.
        let show = |(address, name): (&IpAddr, &String)| {
            let cut: String = name.chars().take(SHOWN_LENGTH).collect();
            let more = if cut.len() < name.len() { "..." } else { "" };
            format!("{address}: \"{}{more}\"", cut.escape_debug())
        };
        let mut shown: Vec<String> = self.refused.iter().take(SHOWN_NAMES).map(show).collect();
        if self.refused.len() > SHOWN_NAMES {
            shown.push("...".to_owned());
        }
        let (names, are) = if self.refused.len() == 1 { ("name", "is") } else { ("names", "are") };
        Some(format!(
            "reverse DNS: {} {names} NetBox would refuse {are} not written ({})",
            self.refused.len(),
            shown.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn name(text: &str) -> Written {
        Written::Name(text.to_owned())
    }

    #[test]
    fn the_final_dot_is_removed_and_the_case_lowered() {
        // networking.go, ReverseLookup: domain := strings.TrimSuffix(names[0], ".")
        assert_eq!(written("web01.lab.example."), name("web01.lab.example"));
        // support.py, reverse_lookup: resolved_name = response.name.lower()
        assert_eq!(written("WEB01.Lab.Example"), name("web01.lab.example"));
        assert_eq!(written("web01"), name("web01"));
    }

    #[test]
    fn netbox_takes_letters_digits_hyphens_and_underscores() {
        assert_eq!(written("_srv-01.lab_2.example"), name("_srv-01.lab_2.example"));
    }

    #[test]
    fn a_name_netbox_would_refuse_is_refused() {
        let refused = |text: &str| Written::Refused(text.to_owned());
        assert_eq!(written("web 01.example"), refused("web 01.example"));
        assert_eq!(written("web01.exämple"), refused("web01.exämple"));
        assert_eq!(written("*.example"), refused("*.example"));
        assert_eq!(written("web01..example"), refused("web01..example"));
        assert_eq!(written(".example"), refused(".example"));
        // Only one final dot is the root.
        assert_eq!(written("web01.example.."), refused("web01.example.."));
    }

    #[test]
    fn a_name_is_255_characters_at_most() {
        // Four labels of 63 characters and three dots: 255.
        let label = "a".repeat(63);
        let longest = [label.as_str(); 4].join(".");
        assert_eq!(longest.len(), 255);
        assert_eq!(written(&longest), name(&longest));
        // The final dot is not counted: it is not written.
        assert_eq!(written(&format!("{longest}.")), name(&longest));
        let too_long = format!("{longest}a");
        assert_eq!(written(&too_long), Written::Refused(too_long.clone()));
    }

    #[test]
    fn an_empty_name_is_no_name() {
        assert_eq!(written(""), Written::Nothing);
        assert_eq!(written("."), Written::Nothing);
    }

    #[test]
    fn link_local_loopback_and_unspecified_addresses_are_never_looked_up() {
        for never in ["169.254.10.2", "fe80::be24:11ff:feaa:bbcc", "127.0.0.1", "::1", "0.0.0.0", "::"] {
            assert!(!is_looked_up(ip(never)), "{never}");
        }
        // An IPv4-mapped address is the IPv4 address it carries.
        assert!(!is_looked_up(ip("::ffff:169.254.10.2")));
        for asked in ["10.0.0.5", "192.0.2.10", "2001:db8::5", "fd00::5", "::ffff:10.0.0.5"] {
            assert!(is_looked_up(ip(asked)), "{asked}");
        }
    }

    #[test]
    fn among_several_names_the_first_in_alphabetical_order_is_kept_whatever_the_order_of_the_answer() {
        let records = |names: &[&str]| preferred(names.iter().map(|name| (*name).to_owned()));
        assert_eq!(records(&["web01.example.", "app01.example.", "db01.example."]), Some("app01.example.".to_owned()));
        assert_eq!(records(&["db01.example.", "app01.example.", "web01.example."]), Some("app01.example.".to_owned()));
        // Compared as they are written: in lower case.
        assert_eq!(records(&["B.example.", "a.example."]), Some("a.example.".to_owned()));
        assert_eq!(records(&[]), None);
    }

    #[test]
    fn a_name_netbox_refuses_is_never_preferred_to_one_it_takes() {
        let records = |names: &[&str]| preferred(names.iter().map(|name| (*name).to_owned()));
        assert_eq!(records(&["a bad name.", "web01.example."]), Some("web01.example.".to_owned()));
        assert_eq!(records(&[".", "web01.example."]), Some("web01.example.".to_owned()));
        // None is taken: the first of them is given, to be refused and told.
        assert_eq!(records(&["b bad.", "a bad."]), Some("a bad.".to_owned()));
        // The root alone is no name.
        assert_eq!(records(&["."]), None);
    }

    #[test]
    fn a_resolved_name_is_given_as_it_is_written() {
        let resolver: BTreeMap<IpAddr, String> = BTreeMap::from([(ip("10.0.0.5"), "WEB01.lab.example.".to_owned())]);
        let mut names = Names::new(&resolver);
        assert_eq!(names.of(ip("10.0.0.5")), Some("web01.lab.example".to_owned()));
        assert_eq!(names.of(ip("10.0.0.6")), None);
        assert_eq!(names.warning(), None);
    }

    #[test]
    fn an_address_that_is_never_looked_up_is_not_even_asked() {
        let asked = Asked::default();
        let mut names = Names::new(&asked);
        for address in ["fe80::1", "169.254.0.7", "127.0.0.1", "10.0.0.5", "2001:db8::5", "10.0.0.5"] {
            assert_eq!(names.of(ip(address)), None);
        }
        assert_eq!(asked.into_addresses(), BTreeSet::from([ip("10.0.0.5"), ip("2001:db8::5")]));
    }

    #[test]
    fn an_ipv4_mapped_address_is_asked_as_the_ipv4_address_it_carries() {
        let resolver: BTreeMap<IpAddr, String> = BTreeMap::from([(ip("10.0.0.5"), "web01.lab.example.".to_owned())]);
        let mut names = Names::new(&resolver);
        assert_eq!(names.of(ip("::ffff:10.0.0.5")), Some("web01.lab.example".to_owned()));
    }

    #[test]
    fn an_empty_name_is_not_reported_and_not_warned_about() {
        let resolver = |_: IpAddr| Some(String::new());
        let mut names = Names::new(&resolver);
        assert_eq!(names.of(ip("10.0.0.5")), None);
        assert_eq!(names.warning(), None);
    }

    #[test]
    fn refused_names_are_not_reported_and_told_in_one_warning() {
        let resolver = |address: IpAddr| Some(format!("host {address}.example."));
        let mut names = Names::new(&resolver);
        for address in ["10.0.0.8", "10.0.0.5", "10.0.0.7", "10.0.0.6", "10.0.0.5"] {
            assert_eq!(names.of(ip(address)), None);
        }
        assert_eq!(
            names.warning().as_deref(),
            Some(
                "reverse DNS: 4 names NetBox would refuse are not written \
                 (10.0.0.5: \"host 10.0.0.5.example.\", 10.0.0.6: \"host 10.0.0.6.example.\", \
                 10.0.0.7: \"host 10.0.0.7.example.\", ...)"
            )
        );
    }

    #[test]
    fn a_refused_name_is_shown_cut_and_escaped() {
        let long = format!("{}\n", "x".repeat(300));
        let resolver = move |_: IpAddr| Some(long.clone());
        let mut names = Names::new(&resolver);
        assert_eq!(names.of(ip("10.0.0.5")), None);
        let expected =
            format!("reverse DNS: 1 name NetBox would refuse is not written (10.0.0.5: \"{}...\")", "x".repeat(80));
        assert_eq!(names.warning(), Some(expected));
    }
}
