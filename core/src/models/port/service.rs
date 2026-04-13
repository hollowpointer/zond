// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Service Identification
//!
//! This module provides the [`Service`] model, detailing network services
//! and their specific implementation details. It supports progressive
//! fingerprinting, allowing low-confidence guesses to be upgraded as
//! deeper script and protocol analysis finishes.

/// Information about a detected service on a network port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The high-level service protocol name (e.g., "ssh", "http", "postgresql").
    name: String,

    /// A metric from 0 to 100 representing the certainty of this identification.
    ///
    /// For example: `0` = Table lookup by port number. `100` = Full protocol handshake.
    confidence: u8,

    /// The specific product or daemon name (e.g., "OpenSSH", "nginx").
    product: Option<String>,

    /// The version string reported or detected (e.g., "8.9p1", "1.21.0").
    version: Option<String>,

    /// Additional metadata or environment hints (e.g., "protocol 2.0", "Debian").
    extrainfo: Option<String>,

    /// A list of Common Platform Enumeration (CPE) identifiers.
    cpe: Vec<String>,
}

impl Service {
    /// Creates a new service record with a baseline confidence score.
    ///
    /// Creates a new service identity.
    ///
    /// The `confidence` value is clamped to a maximum of 100.
    pub fn new(name: impl Into<String>, confidence: u8) -> Self {
        Self {
            name: name.into(),
            confidence: confidence.min(100),
            product: None,
            version: None,
            extrainfo: None,
            cpe: Vec::new(),
        }
    }

    /// Returns the high-level service protocol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the identification confidence score (0-100).
    pub fn confidence(&self) -> u8 {
        self.confidence
    }

    /// Returns the detected product name, if any.
    pub fn product(&self) -> Option<&str> {
        self.product.as_deref()
    }

    /// Returns the detected version string, if any.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Returns additional environmental metadata, if any.
    pub fn extrainfo(&self) -> Option<&str> {
        self.extrainfo.as_deref()
    }

    /// Returns the list of CPE identifiers.
    pub fn cpe(&self) -> &[String] {
        &self.cpe
    }

    /// Builder method to assign a product string.
    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    /// Builder method to assign a version string.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Builder method to add a single CPE identifier.
    pub fn add_cpe(mut self, cpe: impl Into<String>) -> Self {
        let cpe_str = cpe.into();
        if !self.cpe.contains(&cpe_str) {
            self.cpe.push(cpe_str);
        }
        self
    }

    /// Merges another service record into this one safely.
    ///
    /// The merge strategy is confidence-driven. If the incoming `other` service
    /// has a strictly higher confidence score, it will overwrite the primary
    /// identity (`name`, `product`, `version`). Otherwise, it behaves additively,
    /// filling in `None` fields and deduplicating CPEs.
    pub fn merge(&mut self, other: Service) {
        let higher_confidence = other.confidence > self.confidence;

        if higher_confidence {
            self.name = other.name;
            self.confidence = other.confidence;

            // Overwrite existing data with the higher-confidence payload
            if other.product.is_some() {
                self.product = other.product;
            }
            if other.version.is_some() {
                self.version = other.version;
            }
            if other.extrainfo.is_some() {
                self.extrainfo = other.extrainfo;
            }
        } else {
            // Additive merge for equal or lower confidence probes
            if self.product.is_none() {
                self.product = other.product;
            }
            if self.version.is_none() {
                self.version = other.version;
            }
            if self.extrainfo.is_none() {
                self.extrainfo = other.extrainfo;
            }
        }

        // CPEs are always merged and deduplicated, regardless of confidence.
        // Even a low-confidence probe might extract a valid CPE string.
        for c in other.cpe {
            if !self.cpe.contains(&c) {
                self.cpe.push(c);
            }
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

    #[test]
    fn service_builder_pattern() {
        let srv = Service::new("http", 85)
            .with_product("nginx")
            .with_version("1.21.0")
            .add_cpe("cpe:/a:igor_sysoev:nginx:1.21.0");

        assert_eq!(srv.name(), "http");
        assert_eq!(srv.confidence(), 85);
        assert_eq!(srv.product(), Some("nginx"));
        assert_eq!(srv.version(), Some("1.21.0"));
        assert_eq!(srv.cpe().len(), 1);
    }

    #[test]
    fn service_confidence_is_clamped_to_100() {
        let srv = Service::new("ssh", 101);
        assert_eq!(srv.confidence(), 100);
    }

    #[test]
    fn service_merge_lower_confidence_does_not_overwrite_identity() {
        let mut srv1 = Service::new("http", 85).with_product("nginx");
        let srv2 = Service::new("unknown", 10).with_version("2.0");

        srv1.merge(srv2);

        // Name and product shouldn't change, but version should be adopted from lower confidence
        // if not already present.
        assert_eq!(srv1.name(), "http");
        assert_eq!(srv1.confidence(), 85);
        assert_eq!(srv1.product(), Some("nginx"));
        assert_eq!(srv1.version(), Some("2.0"));
    }

    #[test]
    fn service_merge_higher_confidence_overwrites_identity() {
        let mut srv1 = Service::new("http", 50).with_product("nginx");
        let srv2 = Service::new("http", 100)
            .with_product("Apache")
            .with_version("2.4");

        srv1.merge(srv2);

        // The higher confidence payload completely overwrites the identity
        assert_eq!(srv1.name(), "http");
        assert_eq!(srv1.confidence(), 100);
        assert_eq!(srv1.product(), Some("Apache"));
        assert_eq!(srv1.version(), Some("2.4"));
    }

    #[test]
    fn service_merge_deduplicates_cpes() {
        let mut srv1 = Service::new("ssh", 100).add_cpe("cpe:/a:openbsd:openssh");
        let srv2 = Service::new("ssh", 100).add_cpe("cpe:/o:linux:linux_kernel");

        srv1.merge(srv2);

        assert_eq!(srv1.cpe().len(), 2);
    }
}
