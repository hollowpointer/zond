// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Service Identification
//!
//! This module provides the [`Service`] model, describing a detected network
//! service and its specific implementation details.

/// Information about a detected service on a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The high-level service name (e.g., "ssh", "http", "postgresql").
    pub name: String,

    /// The specific product name (e.g., "OpenSSH", "nginx", "Microsoft SQL Server").
    pub product: Option<String>,

    /// The version string reported or detected (e.g., "8.9p1", "1.21.0").
    pub version: Option<String>,

    /// Additional detection information (e.g., "protocol 2.0", "Debian-5ubuntu1").
    pub extrainfo: Option<String>,

    /// A list of Common Platform Enumeration (CPE) identifiers.
    pub cpe: Vec<String>,
}

impl Service {
    /// Creates a new, baseline service record.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            product: None,
            version: None,
            extrainfo: None,
            cpe: Vec::new(),
        }
    }

    /// Merges another service record into this one.
    ///
    /// Preserves existing data where possible, but updates with more granular information
    /// if provided by the secondary record.
    pub fn merge(&mut self, other: Service) {
        if self.name != other.name {
            // Note: In case of identity conflict, we generally keep the current name
            // but log/warn could be added here in higher-level logic.
        }

        if self.product.is_none() {
            self.product = other.product;
        }

        if self.version.is_none() {
            self.version = other.version;
        }

        if self.extrainfo.is_none() {
            self.extrainfo = other.extrainfo;
        }

        // Merge CPEs and deduplicate
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
    fn service_merge_preserves_existing_data() {
        let mut s1 = Service::new("http");
        s1.product = Some("nginx".to_string());

        let mut s2 = Service::new("http");
        s2.version = Some("1.21.0".to_string());

        s1.merge(s2);

        assert_eq!(s1.product.as_deref(), Some("nginx"));
        assert_eq!(s1.version.as_deref(), Some("1.21.0"));
    }

    #[test]
    fn service_merge_deduplicates_cpes() {
        let mut s1 = Service::new("ssh");
        s1.cpe.push("cpe:/a:openbsd:openssh:8.9".to_string());

        let mut s2 = Service::new("ssh");
        s2.cpe.push("cpe:/a:openbsd:openssh:8.9".to_string());
        s2.cpe.push("cpe:/o:linux:linux_kernel".to_string());

        s1.merge(s2);

        assert_eq!(s1.cpe.len(), 2);
        assert!(s1.cpe.contains(&"cpe:/o:linux:linux_kernel".to_string()));
    }
}
