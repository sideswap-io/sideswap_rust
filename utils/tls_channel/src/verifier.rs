//! RFC 7250 raw public key verifiers. With raw public keys the "certificate"
//! rustls hands us is just the peer's `SubjectPublicKeyInfo` DER.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::keys::PublicKey;

fn tls12_not_enabled() -> rustls::Error {
    rustls::Error::General("TLS 1.2 is not enabled".into())
}

/// Client side: the server must present exactly the expected public key.
#[derive(Debug)]
pub(crate) struct ExpectedServerKey {
    spki: Vec<u8>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ExpectedServerKey {
    pub(crate) fn new(expected: &PublicKey, algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self {
            spki: expected.spki_der(),
            algorithms,
        }
    }
}

impl ServerCertVerifier for ExpectedServerKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.spki.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(CertificateError::UnknownIssuer.into())
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls12_not_enabled())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Server side: require a well-formed Ed25519 raw public key and prove the
/// client holds the private key. Whether that key is allowed is decided by the
/// caller after the handshake.
#[derive(Debug)]
pub(crate) struct AnyClientKey {
    algorithms: WebPkiSupportedAlgorithms,
}

impl AnyClientKey {
    pub(crate) fn new(algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self { algorithms }
    }
}

impl ClientCertVerifier for AnyClientKey {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        match PublicKey::from_spki_der(end_entity.as_ref()) {
            Some(_) => Ok(ClientCertVerified::assertion()),
            None => Err(CertificateError::BadEncoding.into()),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls12_not_enabled())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
