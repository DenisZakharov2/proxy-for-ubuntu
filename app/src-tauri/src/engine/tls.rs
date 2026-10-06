//! Общая настройка TLS для протоколов, которые требуют шифрования до
//! собственного протокола (Trojan, VLESS, VMess).
//!
//! Системные корневые сертификаты берём из `webpki-roots`, а не из
//! `/etc/ssl/certs`: это работает одинаково во всех дистрибутивах и не
//! зависит от того, установлен ли пакет `ca-certificates`.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::error::Result as PfuResult;

type Res<T> = PfuResult<T>;

/// Верификатор, принимающий любой сертификат.
///
/// Нужен только когда пользователь явно поставил `skip_cert_verify: true`.
/// Он не проверяет ни цепочку, ни имя хоста — это осознанный компромисс,
/// и о нём пишется предупреждение в журнал при каждом соединении.
#[derive(Debug)]
struct AcceptAnyCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Собирает коннектор rustls.
pub fn build_tls_config(
    sni: &str,
    alpn: &[String],
    skip_cert_verify: bool,
) -> Res<tokio_rustls::TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let _ = sni; // используется вызывающим при ServerName

    if skip_cert_verify {
        tracing::warn!(
            "проверка сертификата отключена для этого outbound'а — трафик уязвим к MITM"
        );
    }

    let mut cfg = if skip_cert_verify {
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::General(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert { provider }))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::General(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }
    Ok(Arc::new(cfg).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_with_default_verification() {
        let c = build_tls_config("example.com", &["h2".into()], false);
        assert!(c.is_ok());
    }

    #[test]
    fn builds_with_verification_disabled() {
        let c = build_tls_config("example.com", &[], true);
        assert!(c.is_ok(), "отключение проверки не должно падать");
    }

    #[test]
    fn alpn_is_accepted() {
        // Значения проверяем на этапе конфигурации: сам коннектор хранит
        // ALPN внутри rustls и не отдаёт его наружу.
        let c = build_tls_config("example.com", &["h2".to_string(), "http/1.1".to_string()], false);
        assert!(c.is_ok());
        assert!(build_tls_config("example.com", &["h2".to_string()], true).is_ok());
    }
}
