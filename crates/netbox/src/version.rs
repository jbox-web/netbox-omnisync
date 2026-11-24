//! The releases of NetBox this build was tested against, and what the tool
//! does with a NetBox of another one.
//!
//! NetBox changes the shape of its objects from one minor release to the next
//! (the unit of a disk size in 4.1, the MAC addresses made objects of their
//! own in 4.2, the selection custom fields read as `{value, label}` in 4.7),
//! and it ignores a field it does not know on write: a tool that writes to a
//! release it was not tested with may write wrong values without any error.
//! Each supported release is the last patch of its minor in the integration
//! tests (`crates/cli/tests/integration`, the `integration` job of CI).

use std::future::Future;

use omnisync_core::gateway::GatewayError;

// ------------------------------------------------------------------ VERSION SEAM
// Everything that depends on the release of NetBox is decided here. A release
// that writes or reads an object differently gets its difference as a method of
// `Dialect`, matched on `self`, and the code that writes or reads that object
// asks it: never a version compared elsewhere.

/// A minor release of NetBox this build was tested against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dialect {
    V4_5,
    V4_6,
    V4_7,
}

impl Dialect {
    /// Every supported minor release, the oldest first.
    pub const SUPPORTED: [Dialect; 3] = [Dialect::V4_5, Dialect::V4_6, Dialect::V4_7];

    /// The minor release, as NetBox numbers it.
    pub fn minor(self) -> &'static str {
        match self {
            Dialect::V4_5 => "4.5",
            Dialect::V4_6 => "4.6",
            Dialect::V4_7 => "4.7",
        }
    }

    /// The dialect of the release `version` that NetBox gives in
    /// `/api/status/` (`4.7.5`); a full version of a Docker image
    /// (`4.5.10-Docker-4.0.2`) is read as its release. None for a release this
    /// build was not tested against, a pre-release (`4.5.0-beta1`) included.
    pub fn of(version: &str) -> Option<Dialect> {
        // The suffix of a Docker image names the image, not NetBox.
        let (release, suffix) = version.split_once('-').unwrap_or((version, ""));
        if !suffix.is_empty() && !suffix.starts_with("Docker-") {
            return None;
        }
        let parts: Vec<&str> = release.split('.').collect();
        let [major, minor, patch] = parts.as_slice() else {
            return None;
        };
        if patch.is_empty() || !patch.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let minor = format!("{major}.{minor}");
        Dialect::SUPPORTED.into_iter().find(|dialect| dialect.minor() == minor)
    }
}

// ------------------------------------------------------------------ VERSION SEAM

/// The supported minor releases, for a message: `4.5, 4.6, 4.7`.
pub fn supported() -> String {
    Dialect::SUPPORTED.map(Dialect::minor).join(", ")
}

/// What a run does with a NetBox of a release this build was not tested
/// against (`netbox.unsupported_version`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnsupportedVersion {
    /// Nothing is read from the sources nor written: the run fails.
    #[default]
    Refuse,
    /// The run goes on, and its report says it.
    Warn,
}

/// What a run may do with the NetBox of release `version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// A supported release.
    Supported(Dialect),
    /// Another release, run anyway: the warning of the report.
    Unsupported(String),
}

/// Whether a run goes on with the NetBox of release `version`; the message of
/// the refusal otherwise.
pub fn admit(version: &str, policy: UnsupportedVersion) -> Result<Admitted, String> {
    if let Some(dialect) = Dialect::of(version) {
        return Ok(Admitted::Supported(dialect));
    }
    let tested = supported();
    match policy {
        UnsupportedVersion::Refuse => Err(format!(
            "NetBox {version} is not a release this build was tested with ({tested}): nothing was read nor written \
             (netbox.unsupported_version = \"warn\" runs it anyway)"
        )),
        UnsupportedVersion::Warn => Ok(Admitted::Unsupported(format!(
            "NetBox {version} is not a release this build was tested with ({tested}): the run went on, \
             as netbox.unsupported_version says"
        ))),
    }
}

/// A NetBox that says its release.
pub trait NetboxVersion {
    /// The release of NetBox, as `/api/status/` gives it (`netbox-version`).
    fn netbox_version(&self) -> impl Future<Output = Result<String, GatewayError>> + Send;

    /// Reads what NetBox says it takes (its OpenAPI schema), which every write
    /// is checked against: a run asks for it before it reads any source.
    fn load_schema(&self) -> impl Future<Output = Result<(), GatewayError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    // `/api/status/` of the Docker images 4.5.10 and 4.7.5 of the integration
    // tests (2026-11-24): `4.5.10`, `4.7.5`. `4.5.10-Docker-4.0.2` is the full
    // version of the 4.5.10 image (`RELEASE.full_version`), which status does not
    // give: a build after the release is still read as the release.
    #[test]
    fn a_release_is_known_by_its_minor_whatever_its_patch_and_its_build() {
        assert_eq!(Dialect::of("4.5.10"), Some(Dialect::V4_5));
        assert_eq!(Dialect::of("4.5.10-Docker-4.0.2"), Some(Dialect::V4_5));
        assert_eq!(Dialect::of("4.6.0"), Some(Dialect::V4_6));
        assert_eq!(Dialect::of("4.7.5"), Some(Dialect::V4_7));
    }

    #[test]
    fn a_release_this_build_was_not_tested_with_has_no_dialect() {
        // A pre-release is not the release it comes before: 4.5.0-beta1 is not 4.5.
        for version in
            ["4.8.0", "4.4.10", "4.3.7", "5.0.0", "4.40.1", "4", "", "v4.4.10", "4.5.0-beta1", "4.7.0-dev", "4.6"]
        {
            assert_eq!(Dialect::of(version), None, "{version}");
        }
    }

    #[test]
    fn an_unsupported_release_is_refused_unless_the_configuration_says_to_warn() {
        assert_eq!(admit("4.7.5", UnsupportedVersion::Refuse), Ok(Admitted::Supported(Dialect::V4_7)));
        assert_eq!(
            admit("4.8.0", UnsupportedVersion::Refuse),
            Err("NetBox 4.8.0 is not a release this build was tested with (4.5, 4.6, 4.7): nothing was read \
                 nor written (netbox.unsupported_version = \"warn\" runs it anyway)"
                .to_owned())
        );
        assert_eq!(
            admit("4.8.0", UnsupportedVersion::Warn),
            Ok(Admitted::Unsupported(
                "NetBox 4.8.0 is not a release this build was tested with (4.5, 4.6, 4.7): the run went on, \
                 as netbox.unsupported_version says"
                    .to_owned()
            ))
        );
        assert_eq!(UnsupportedVersion::default(), UnsupportedVersion::Refuse);
    }
}
