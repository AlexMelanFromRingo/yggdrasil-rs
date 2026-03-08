//! Node configuration.
//!
//! Port of yggdrasil-go/src/config/config.go

use anyhow::{anyhow, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Platform defaults
// ---------------------------------------------------------------------------

pub struct PlatformDefaults {
    pub default_admin_listen: &'static str,
    pub default_config_file: &'static str,
    pub default_multicast_interfaces: Vec<MulticastInterfaceConfig>,
    pub maximum_if_mtu: u64,
    pub default_if_mtu: u64,
    pub default_if_name: &'static str,
}

#[cfg(target_os = "linux")]
pub fn get_defaults() -> PlatformDefaults {
    PlatformDefaults {
        default_admin_listen: "unix:///var/run/yggdrasil.sock",
        default_config_file: "/etc/yggdrasil.conf",
        default_multicast_interfaces: vec![MulticastInterfaceConfig {
            regex: ".*".to_string(),
            beacon: true,
            listen: true,
            port: 0,
            priority: 0,
            password: String::new(),
        }],
        maximum_if_mtu: 65535,
        default_if_mtu: 65535,
        default_if_name: "auto",
    }
}

#[cfg(target_os = "macos")]
pub fn get_defaults() -> PlatformDefaults {
    PlatformDefaults {
        default_admin_listen: "unix:///var/run/yggdrasil.sock",
        default_config_file: "/etc/yggdrasil.conf",
        default_multicast_interfaces: vec![MulticastInterfaceConfig {
            regex: ".*".to_string(),
            beacon: true,
            listen: true,
            port: 0,
            priority: 0,
            password: String::new(),
        }],
        maximum_if_mtu: 65535,
        default_if_mtu: 65535,
        default_if_name: "auto",
    }
}

#[cfg(target_os = "windows")]
pub fn get_defaults() -> PlatformDefaults {
    PlatformDefaults {
        default_admin_listen: "tcp://localhost:9001",
        default_config_file: "C:\\ProgramData\\Yggdrasil\\yggdrasil.conf",
        default_multicast_interfaces: vec![],
        maximum_if_mtu: 65535,
        default_if_mtu: 65535,
        default_if_name: "auto",
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn get_defaults() -> PlatformDefaults {
    PlatformDefaults {
        default_admin_listen: "tcp://localhost:9001",
        default_config_file: "/etc/yggdrasil.conf",
        default_multicast_interfaces: vec![],
        maximum_if_mtu: 65535,
        default_if_mtu: 65535,
        default_if_name: "auto",
    }
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Hex-encoded byte slice, serialised as a lowercase hex string.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct KeyBytes(pub Vec<u8>);

impl std::fmt::Debug for KeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyBytes({})", hex::encode(&self.0))
    }
}

impl Serialize for KeyBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for KeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Ok(KeyBytes(bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticastInterfaceConfig {
    #[serde(rename = "Regex")]
    pub regex: String,
    #[serde(rename = "Beacon")]
    pub beacon: bool,
    #[serde(rename = "Listen")]
    pub listen: bool,
    #[serde(rename = "Port", default)]
    pub port: u16,
    #[serde(rename = "Priority", default)]
    pub priority: u64,
    #[serde(rename = "Password", default)]
    pub password: String,
}

/// A TLS certificate stored in memory (not serialised to config).
#[derive(Debug, Clone)]
pub struct TlsCertificate {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// Main node configuration, serialised as HJSON/JSON.
///
/// Port of `NodeConfig` in yggdrasil-go.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Ed25519 private key (hex-encoded, 64 bytes).
    #[serde(rename = "PrivateKey", skip_serializing_if = "Option::is_none")]
    pub private_key: Option<KeyBytes>,

    /// Path to a PEM file containing the private key (alternative to inline key).
    #[serde(rename = "PrivateKeyPath", default, skip_serializing_if = "String::is_empty")]
    pub private_key_path: String,

    /// The TLS certificate derived from the private key (not written to config).
    #[serde(skip)]
    pub certificate: Option<TlsCertificate>,

    /// Outbound peer URIs (e.g. "tls://a.b.c.d:e").
    #[serde(rename = "Peers", default)]
    pub peers: Vec<String>,

    /// Outbound peers per source interface.
    #[serde(rename = "InterfacePeers", default)]
    pub interface_peers: HashMap<String, Vec<String>>,

    /// Listen addresses for incoming connections.
    #[serde(rename = "Listen", default)]
    pub listen: Vec<String>,

    /// Admin socket listen address.
    #[serde(rename = "AdminListen", default, skip_serializing_if = "String::is_empty")]
    pub admin_listen: String,

    /// Multicast interface configurations.
    #[serde(rename = "MulticastInterfaces", default)]
    pub multicast_interfaces: Vec<MulticastInterfaceConfig>,

    /// Allowed peer public keys (hex). If empty, all are allowed.
    #[serde(rename = "AllowedPublicKeys", default)]
    pub allowed_public_keys: Vec<String>,

    /// TUN interface name ("auto", "none", or a specific name).
    #[serde(rename = "IfName", default)]
    pub if_name: String,

    /// TUN interface MTU.
    #[serde(rename = "IfMTU", default)]
    pub if_mtu: u64,

    /// Whether to log DHT lookups.
    #[serde(rename = "LogLookups", default, skip_serializing_if = "std::ops::Not::not")]
    pub log_lookups: bool,

    /// Whether to hide platform/version from NodeInfo.
    #[serde(rename = "NodeInfoPrivacy", default)]
    pub node_info_privacy: bool,

    /// Optional node info map.
    #[serde(rename = "NodeInfo", default, skip_serializing_if = "Option::is_none")]
    pub node_info: Option<serde_json::Value>,
}

impl NodeConfig {
    /// Generates a new config with a random private key and platform defaults.
    pub fn generate() -> Result<Self> {
        let defaults = get_defaults();
        let mut cfg = NodeConfig {
            private_key: None,
            private_key_path: String::new(),
            certificate: None,
            peers: vec![],
            interface_peers: HashMap::new(),
            listen: vec![],
            admin_listen: defaults.default_admin_listen.to_string(),
            multicast_interfaces: defaults.default_multicast_interfaces.clone(),
            allowed_public_keys: vec![],
            if_name: defaults.default_if_name.to_string(),
            if_mtu: defaults.default_if_mtu,
            log_lookups: false,
            node_info_privacy: false,
            node_info: None,
        };
        cfg.new_private_key();
        cfg.postprocess()?;
        Ok(cfg)
    }

    /// Generates and stores a new random ed25519 private key.
    /// Stored as 64 bytes: seed[0..32] || pubkey[32..64] (Go-compatible format).
    pub fn new_private_key(&mut self) {
        let key = SigningKey::generate(&mut OsRng);
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(key.as_bytes());
        raw[32..].copy_from_slice(key.verifying_key().as_bytes());
        self.private_key = Some(KeyBytes(raw.to_vec()));
    }

    /// Returns the signing key, if a private key is configured.
    pub fn signing_key(&self) -> Result<SigningKey> {
        let kb = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("no private key configured"))?;
        if kb.0.len() != 64 {
            return Err(anyhow!(
                "private key must be 64 bytes, got {}",
                kb.0.len()
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&kb.0[..32]);
        Ok(SigningKey::from_bytes(&bytes))
    }

    /// Returns the verifying (public) key.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        Ok(self.signing_key()?.verifying_key())
    }

    /// Parses the config from HJSON/JSON bytes.
    pub fn from_hjson(data: &[u8]) -> Result<Self> {
        // Try HJSON first, fall back to strict JSON
        let s = std::str::from_utf8(data)?;
        let value: serde_json::Value = deser_hjson::from_str(s)
            .map_err(|e| anyhow!("HJSON parse error: {e}"))?;
        let mut cfg: NodeConfig = serde_json::from_value(value)
            .map_err(|e| anyhow!("config deserialise error: {e}"))?;

        // If private_key_path is set, load key from file
        if !cfg.private_key_path.is_empty() {
            cfg.private_key = None;
            let pem_bytes = std::fs::read(&cfg.private_key_path)?;
            cfg.unmarshal_pem_private_key(&pem_bytes)?;
        }

        cfg.postprocess()?;
        Ok(cfg)
    }

    /// Serialises the config to HJSON (actually pretty-printed JSON here,
    /// since HJSON serialisation libraries are limited).
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// PEM-encodes the private key as PKCS#8.
    pub fn marshal_pem_private_key(&self) -> Result<Vec<u8>> {
        let key = self.signing_key()?;
        // ed25519-dalek SigningKey → PKCS8 PEM via pkcs8 crate
        use pkcs8::EncodePrivateKey;
        let doc = key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map_err(|e| anyhow!("PKCS8 encode error: {e}"))?;
        Ok(doc.as_bytes().to_vec())
    }

    /// Loads a private key from PEM-encoded PKCS#8 bytes.
    pub fn unmarshal_pem_private_key(&mut self, pem_bytes: &[u8]) -> Result<()> {
        use pkcs8::DecodePrivateKey;
        let s = std::str::from_utf8(pem_bytes)?;
        let key = SigningKey::from_pkcs8_pem(s)
            .map_err(|e| anyhow!("PKCS8 decode error: {e}"))?;
        // Store as 64-byte ed25519 private key (seed || pub)
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(key.as_bytes());
        raw[32..].copy_from_slice(key.verifying_key().as_bytes());
        self.private_key = Some(KeyBytes(raw.to_vec()));
        Ok(())
    }

    /// Generates a self-signed TLS certificate from the node's private key.
    pub fn generate_self_signed_certificate(&mut self) -> Result<()> {
        let signing_key = self.signing_key()?;
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let key_pem = self.marshal_pem_private_key()?;
        let key_pem_str = std::str::from_utf8(&key_pem)?.to_string();

        let key_pair = KeyPair::from_pem(&key_pem_str)
            .map_err(|e| anyhow!("rcgen KeyPair error: {e}"))?;

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            pub_hex,
        );
        // RFC5280 §4.1.2.5: "never expires" sentinel
        params.not_after = rcgen::date_time_ymd(9999, 12, 31);

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| anyhow!("rcgen self-sign error: {e}"))?;

        self.certificate = Some(TlsCertificate {
            cert_pem: cert.pem().into_bytes(),
            key_pem,
        });
        Ok(())
    }

    /// Build a `rustls::ServerConfig` from the stored certificate.
    pub fn build_rustls_config(&self) -> Result<std::sync::Arc<rustls::ServerConfig>> {
        use rustls::ServerConfig;
        use rustls_pemfile::{certs, private_key};
        use std::io::Cursor;

        let cert_data = self
            .certificate
            .as_ref()
            .ok_or_else(|| anyhow!("no certificate generated yet"))?;

        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            certs(&mut Cursor::new(&cert_data.cert_pem))
                .collect::<std::result::Result<Vec<_>, _>>()?;

        let key = private_key(&mut Cursor::new(&cert_data.key_pem))?
            .ok_or_else(|| anyhow!("no private key in PEM"))?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Ok(std::sync::Arc::new(config))
    }

    /// Build a `rustls::ClientConfig` that accepts any server certificate
    /// (identity is verified via the yggdrasil handshake instead).
    pub fn build_rustls_client_config(&self) -> Result<std::sync::Arc<rustls::ClientConfig>> {
        use rustls::ClientConfig;
        use rustls_pemfile::{certs, private_key};
        use std::io::Cursor;

        let cert_data = self
            .certificate
            .as_ref()
            .ok_or_else(|| anyhow!("no certificate generated yet"))?;

        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            certs(&mut Cursor::new(&cert_data.cert_pem))
                .collect::<std::result::Result<Vec<_>, _>>()?;

        let key = private_key(&mut Cursor::new(&cert_data.key_pem))?
            .ok_or_else(|| anyhow!("no private key in PEM"))?;

        // We skip server verification — identity is verified in the Yggdrasil handshake.
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerifier))
            .with_client_auth_cert(certs, key)?;

        Ok(std::sync::Arc::new(config))
    }

    // Internal: run post-processing after parse/create.
    fn postprocess(&mut self) -> Result<()> {
        // If we have a private key but no certificate, generate one.
        if self.private_key.is_some() && self.certificate.is_none() {
            self.generate_self_signed_certificate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TLS certificate verifier that skips verification (identity checked by handshake)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dh: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dh: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
