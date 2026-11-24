//! TLS to a host whose certificate is pinned: a firewall or a BMC presents
//! the self-signed certificate it was shipped with, and no authority can vouch
//! for it. Shared by the FortiOS and the Redfish clients.

use std::error::Error as StdError;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, OtherError, SignatureScheme};
use sha2::{Digest, Sha256};

/// A fingerprint that is not the SHA-256 of a certificate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("must be the SHA-256 of the certificate (64 hexadecimal digits, colons allowed)")]
pub struct FingerprintError;

/// The SHA-256 of the one certificate a host may present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Reads a fingerprint as `openssl x509 -fingerprint -sha256` prints it or as
    /// the inventory stores it: 64 hexadecimal digits of either case, colons allowed.
    pub fn parse(text: &str) -> Result<Self, FingerprintError> {
        let mut digits = text.chars().filter(|c| *c != ':').map(|c| c.to_digit(16));
        let mut bytes = [0u8; 32];
        for byte in &mut bytes {
            let (Some(Some(high)), Some(Some(low))) = (digits.next(), digits.next()) else {
                return Err(FingerprintError);
            };
            *byte = u8::try_from(high * 16 + low).map_err(|_| FingerprintError)?;
        }
        if digits.next().is_some() {
            return Err(FingerprintError);
        }
        Ok(Fingerprint(bytes))
    }

    /// Whether `certificate`, in DER, is the pinned one.
    pub fn matches(&self, certificate: &[u8]) -> bool {
        Sha256::digest(certificate).as_slice() == self.0
    }
}

/// The certificate presented is not the pinned one.
#[derive(Debug, thiserror::Error)]
#[error("the certificate presented is not the pinned one")]
pub struct PinMismatch;

/// Accepts one certificate only, the one whose SHA-256 is given.
///
/// A firewall or a BMC presents a self-signed certificate: no authority to
/// verify, so the certificate itself is pinned. The check runs during the TLS handshake,
/// before anything is sent.
#[derive(Debug)]
struct PinnedCertificate {
    fingerprint: Fingerprint,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertificate {
    /// The pinned fingerprint replaces the authority and host name checks.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.fingerprint.matches(end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(PinMismatch)))))
        }
    }

    // A certificate is public: the server must still prove that it holds its key.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS configuration that accepts the certificate of `fingerprint` and no other.
pub fn pinned_tls(fingerprint: Fingerprint) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = PinnedCertificate { fingerprint, provider: provider.clone() };
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

/// The TLS error behind a failed request, if any. An I/O error hides the error
/// it wraps from `source`: it is looked into as well.
pub fn tls_error<'a>(error: &'a (dyn StdError + 'static)) -> Option<&'a rustls::Error> {
    let mut current = Some(error);
    while let Some(cause) = current {
        if let Some(tls) = cause.downcast_ref::<rustls::Error>() {
            return Some(tls);
        }
        if let Some(wrapped) = cause.downcast_ref::<std::io::Error>().and_then(std::io::Error::get_ref)
            && let Some(tls) = tls_error(wrapped)
        {
            return Some(tls);
        }
        current = cause.source();
    }
    None
}

/// Whether a failed request was refused because the certificate presented is
/// not the pinned one.
pub fn is_pin_mismatch(error: &(dyn StdError + 'static)) -> bool {
    matches!(
        tls_error(error),
        Some(rustls::Error::InvalidCertificate(CertificateError::Other(other))) if other.0.is::<PinMismatch>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of the three bytes `abc` (FIPS 180-4, appendix B.1).
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn fingerprint_matches_the_certificate_it_is_the_sha256_of() {
        let pinned = Fingerprint::parse(ABC).expect("64 hexadecimal digits");
        assert!(pinned.matches(b"abc"));
    }

    #[test]
    fn fingerprint_differs_from_any_other_certificate() {
        let pinned = Fingerprint::parse(ABC).expect("64 hexadecimal digits");
        assert!(!pinned.matches(b"abd"));
        assert!(!pinned.matches(b""));
        assert!(!Fingerprint::parse(&"00".repeat(32)).expect("64 hexadecimal digits").matches(b"abc"));
    }

    #[test]
    fn fingerprint_is_read_in_upper_or_lower_case_with_or_without_colons() {
        let pinned = Fingerprint::parse(ABC).expect("64 hexadecimal digits");
        assert_eq!(Fingerprint::parse(&ABC.to_uppercase()), Ok(pinned));
        // As `openssl x509 -fingerprint -sha256` prints it.
        let openssl = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD";
        assert_eq!(Fingerprint::parse(openssl), Ok(pinned));
        assert!(Fingerprint::parse(openssl).expect("a fingerprint").matches(b"abc"));
    }

    #[test]
    fn fingerprint_of_a_wrong_length_is_refused() {
        // 62 and 66 digits, the lengths of a SHA-1 and of an MD5, and nothing.
        for digits in [62, 66, 40, 32, 0] {
            assert_eq!(Fingerprint::parse(&"a".repeat(digits)), Err(FingerprintError), "{digits} digits");
        }
        assert_eq!(Fingerprint::parse(&ABC[..63]), Err(FingerprintError));
    }

    #[test]
    fn fingerprint_that_is_not_hexadecimal_is_refused() {
        assert_eq!(Fingerprint::parse(&"zz".repeat(32)), Err(FingerprintError));
        assert_eq!(Fingerprint::parse(&format!(" {}", &ABC[..63])), Err(FingerprintError));
        assert_eq!(Fingerprint::parse(&format!("+{}", &ABC[..63])), Err(FingerprintError));
        // 64 bytes, but not 64 digits.
        assert_eq!(Fingerprint::parse(&"é".repeat(32)), Err(FingerprintError));
    }
}
