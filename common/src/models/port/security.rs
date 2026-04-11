// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Port Security and Encryption Metadata
//!
//! This module provides the [`Security`] model, focused on TLS/SSL and other
//! transport-layer security features.

use std::time::SystemTime;

/// Information about transport security (TLS/SSL) discovered on a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// The specific TLS version negotiated (e.g., "TLSv1.3").
    pub tls_version: Option<String>,

    /// The cipher suite selected (e.g., "TLS_AES_256_GCM_SHA384").
    pub cipher_suite: Option<String>,

    /// Public key information or certificate summaries.
    pub certificate: Option<CertificateInfo>,
}

impl Security {
    /// Returns `true` if the certificate is expired or expiring within the given duration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{SystemTime, Duration};
    /// # use zond_common::models::port::{Security, CertificateInfo};
    /// # let mut sec = Security { tls_version: None, cipher_suite: None, certificate: Some(CertificateInfo {
    /// #     common_name: "example.com".to_string(), sans: vec![], issuer: "CA".to_string(),
    /// #     validity_end: SystemTime::now() + Duration::from_secs(3600), fingerprint: "abc".to_string()
    /// # }) };
    ///
    /// let is_dangerous = sec.certificate.as_ref().map_or(false, |c| {
    ///     c.validity_end < SystemTime::now() + Duration::from_secs(86400 * 30) // 30 days
    /// });
    /// ```
    pub fn is_cert_expiring(&self, threshold: std::time::Duration) -> bool {
        self.certificate.as_ref().map_or(false, |c| {
            c.validity_end < SystemTime::now() + threshold
        })
    }
}

/// A summary of a service's security certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// The Common Name (CN) of the certificate subject.
    pub common_name: String,

    /// Alternative names (Subject Alt Names) associated with the certificate.
    pub sans: Vec<String>,

    /// The name of the Issuing Authority (CA).
    pub issuer: String,

    /// The expiration date of the certificate.
    pub validity_end: SystemTime,

    /// Fingerprint (SHA256) of the certificate.
    pub fingerprint: String,
}

impl Security {
    /// Merges another security record into this one.
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
    use std::time::{SystemTime, Duration};

    #[test]
    fn security_merge_picks_up_missing_fields() {
        let mut s1 = Security {
            tls_version: Some("TLSv1.2".to_string()),
            cipher_suite: None,
            certificate: None,
        };

        let s2 = Security {
            tls_version: None,
            cipher_suite: Some("AES128-GCM".to_string()),
            certificate: None,
        };

        s1.merge(s2);
        assert_eq!(s1.tls_version.as_deref(), Some("TLSv1.2"));
        assert_eq!(s1.cipher_suite.as_deref(), Some("AES128-GCM"));
    }

    #[test]
    fn security_expiring_check_logic() {
        let now = SystemTime::now();
        let sec = Security {
            tls_version: None,
            cipher_suite: None,
            certificate: Some(CertificateInfo {
                common_name: "test".into(),
                sans: vec![],
                issuer: "test".into(),
                validity_end: now + Duration::from_secs(100),
                fingerprint: "test".into(),
            }),
        };

        assert!(sec.is_cert_expiring(Duration::from_secs(200)));
        assert!(!sec.is_cert_expiring(Duration::from_secs(50)));
    }
}
