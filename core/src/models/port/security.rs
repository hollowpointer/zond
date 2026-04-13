// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Port Security and Encryption Metadata
//!
//! This module provides the [`Security`] model, focused on capturing TLS/SSL
//! negotiated parameters, ALPN records, and X.509 certificate lifecycles.

use std::time::{Duration, SystemTime};

/// Information about transport security (TLS/SSL) successfully negotiated on a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// The specific TLS version negotiated (e.g., "TLSv1.3").
    tls_version: Option<String>,

    /// The cipher suite selected by the server (e.g., "TLS_AES_256_GCM_SHA384").
    cipher_suite: Option<String>,

    /// Application-Layer Protocol Negotiation (ALPN) protocols supported (e.g., ["h2", "http/1.1"]).
    alpn: Vec<String>,

    /// Public key information and lifecycle summaries for the presented X.509 certificate.
    certificate: Option<CertificateInfo>,
}

impl Security {
    /// Creates a new, empty security record.
    pub fn new() -> Self {
        Self {
            tls_version: None,
            cipher_suite: None,
            alpn: Vec::new(),
            certificate: None,
        }
    }

    /// Returns the negotiated TLS version, if any.
    pub fn tls_version(&self) -> Option<&str> {
        self.tls_version.as_deref()
    }

    /// Returns the negotiated cipher suite, if any.
    pub fn cipher_suite(&self) -> Option<&str> {
        self.cipher_suite.as_deref()
    }

    /// Returns the negotiated ALPN protocols.
    pub fn alpn(&self) -> &[String] {
        &self.alpn
    }

    /// Returns the certificate information, if available.
    pub fn certificate(&self) -> Option<&CertificateInfo> {
        self.certificate.as_ref()
    }

    /// Builder method to set the negotiated TLS version.
    pub fn with_tls_version(mut self, version: impl Into<String>) -> Self {
        self.tls_version = Some(version.into());
        self
    }

    /// Builder method to set the negotiated cipher suite.
    pub fn with_cipher_suite(mut self, cipher: impl Into<String>) -> Self {
        self.cipher_suite = Some(cipher.into());
        self
    }

    /// Builder method to add an ALPN protocol string.
    pub fn add_alpn(mut self, protocol: impl Into<String>) -> Self {
        let proto_str = protocol.into();
        if !self.alpn.contains(&proto_str) {
            self.alpn.push(proto_str);
        }
        self
    }

    /// Builder method to attach parsed certificate information.
    pub fn with_certificate(mut self, cert: CertificateInfo) -> Self {
        self.certificate = Some(cert);
        self
    }

    /// Merges another security record into this one.
    ///
    /// Preserves existing TLS version and cipher suite if already populated,
    /// but safely deduplicates and merges ALPN arrays.
    pub fn merge(&mut self, other: Security) {
        if self.tls_version.is_none() {
            self.tls_version = other.tls_version;
        }
        if self.cipher_suite.is_none() {
            self.cipher_suite = other.cipher_suite;
        }
        if self.certificate.is_none() {
            self.certificate = other.certificate;
        }

        // Merge and deduplicate ALPN protocols
        for protocol in other.alpn {
            if !self.alpn.contains(&protocol) {
                self.alpn.push(protocol);
            }
        }
    }

    /// Returns `true` if the certificate is actively valid at the current system time.
    /// Returns `false` if the certificate is expired, not yet valid, or missing.
    pub fn is_cert_valid(&self) -> bool {
        self.is_cert_valid_at(SystemTime::now())
    }

    /// Returns `true` if the certificate is valid at a specific target time.
    pub fn is_cert_valid_at(&self, target_time: SystemTime) -> bool {
        self.certificate.as_ref().map_or(false, |c| {
            target_time >= c.validity_start() && target_time <= c.validity_end()
        })
    }

    /// Returns `true` if the certificate is currently valid, but expires within the given threshold.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// # use zond_core::models::port::{Security, CertificateInfo};
    /// # let mut sec = Security::new();
    ///
    /// // Check if the certificate expires in the next 30 days
    /// let expires_soon = sec.is_cert_expiring(Duration::from_secs(86400 * 30));
    /// ```
    pub fn is_cert_expiring(&self, threshold: Duration) -> bool {
        let now = SystemTime::now();
        self.certificate.as_ref().map_or(false, |c| {
            // Must be currently valid...
            if now < c.validity_start() || now > c.validity_end() {
                return false;
            }
            // ...but expiring before the threshold
            c.validity_end() < now + threshold
        })
    }
}

impl Default for Security {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed summary of a service's X.509 security certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// The Common Name (CN) of the certificate subject.
    common_name: String,

    /// Subject Alternative Names (SANs) associated with the certificate.
    sans: Vec<String>,

    /// The name of the Issuing Certificate Authority (CA).
    issuer: String,

    /// The timestamp when the certificate becomes valid.
    validity_start: SystemTime,

    /// The timestamp when the certificate expires.
    validity_end: SystemTime,

    /// The type of public key used (e.g., "RSA", "ECDSA", "Ed25519").
    pubkey_type: String,

    /// The size of the public key in bits (e.g., 2048, 4096, 256).
    pubkey_bits: u32,

    /// The SHA-256 fingerprint of the raw DER-encoded certificate.
    fingerprint_sha256: String,
}

impl CertificateInfo {
    /// Creates a new certificate information record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        common_name: impl Into<String>,
        sans: Vec<String>,
        issuer: impl Into<String>,
        validity_start: SystemTime,
        validity_end: SystemTime,
        pubkey_type: impl Into<String>,
        pubkey_bits: u32,
        fingerprint_sha256: impl Into<String>,
    ) -> Self {
        Self {
            common_name: common_name.into(),
            sans,
            issuer: issuer.into(),
            validity_start,
            validity_end,
            pubkey_type: pubkey_type.into(),
            pubkey_bits,
            fingerprint_sha256: fingerprint_sha256.into(),
        }
    }

    /// Returns the Common Name (CN) of the certificate.
    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    /// Returns the Subject Alternative Names (SANs).
    pub fn sans(&self) -> &[String] {
        &self.sans
    }

    /// Returns the issuer of the certificate.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the start time of the certificate's validity.
    pub fn validity_start(&self) -> SystemTime {
        self.validity_start
    }

    /// Returns the expiration time of the certificate.
    pub fn validity_end(&self) -> SystemTime {
        self.validity_end
    }

    /// Returns the public key type (e.g., "RSA").
    pub fn pubkey_type(&self) -> &str {
        &self.pubkey_type
    }

    /// Returns the size of the public key in bits.
    pub fn pubkey_bits(&self) -> u32 {
        self.pubkey_bits
    }

    /// Returns the SHA-256 fingerprint of the certificate.
    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint_sha256
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_cert(start_offset: i64, end_offset: i64) -> CertificateInfo {
        let now = SystemTime::now();

        let start = if start_offset < 0 {
            now - Duration::from_secs(start_offset.unsigned_abs())
        } else {
            now + Duration::from_secs(start_offset as u64)
        };

        let end = if end_offset < 0 {
            now - Duration::from_secs(end_offset.unsigned_abs())
        } else {
            now + Duration::from_secs(end_offset as u64)
        };

        CertificateInfo::new(
            "test.local",
            vec!["*.test.local".into()],
            "Local CA",
            start,
            end,
            "RSA",
            2048,
            "deadbeef",
        )
    }

    #[test]
    fn security_builder_pattern() {
        let sec = Security::new()
            .with_tls_version("TLSv1.3")
            .with_cipher_suite("TLS_AES_256_GCM_SHA384")
            .add_alpn("h2")
            .add_alpn("http/1.1");

        assert_eq!(sec.tls_version(), Some("TLSv1.3"));
        assert_eq!(sec.cipher_suite(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(sec.alpn().len(), 2);
    }

    #[test]
    fn security_merge_logic() {
        let mut s1 = Security::new()
            .with_tls_version("TLSv1.2")
            .add_alpn("http/1.1");

        let s2 = Security::new()
            .with_cipher_suite("AES128-GCM")
            .add_alpn("h2")
            .add_alpn("http/1.1"); // Should be deduplicated

        s1.merge(s2);

        assert_eq!(s1.tls_version(), Some("TLSv1.2"));
        assert_eq!(s1.cipher_suite(), Some("AES128-GCM"));
        assert_eq!(s1.alpn().len(), 2);
        assert!(s1.alpn().contains(&"h2".to_string()));
    }

    #[test]
    fn certificate_validity_lifecycle() {
        // Valid from 10 days ago until 10 days from now
        let valid_cert = mock_cert(-864000, 864000);
        let sec_valid = Security::new().with_certificate(valid_cert);

        assert!(sec_valid.is_cert_valid());
        // Threshold check: Does it expire in the next 5 days? No.
        assert!(!sec_valid.is_cert_expiring(Duration::from_secs(86400 * 5)));
        // Threshold check: Does it expire in the next 15 days? Yes.
        assert!(sec_valid.is_cert_expiring(Duration::from_secs(86400 * 15)));

        // Expired 5 days ago
        let expired_cert = mock_cert(-864000, -432000);
        let sec_expired = Security::new().with_certificate(expired_cert);

        assert!(!sec_expired.is_cert_valid());
        // An already expired cert shouldn't trigger "expiring soon" alerts
        assert!(!sec_expired.is_cert_expiring(Duration::from_secs(86400 * 30)));

        // Not yet valid (starts tomorrow)
        let future_cert = mock_cert(86400, 864000);
        let sec_future = Security::new().with_certificate(future_cert);

        assert!(!sec_future.is_cert_valid());
    }
}
