// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Port Discovery and Metadata
//!
//! This module defines the core types for identifying and detailing network services.
//! It is architected for future-proof service fingerprinting, security analysis,
//! and low-level discovery telemetry.
//!
//! ## Beyond Nmap
//!
//! While traditional scanners often focus on raw reachability, Zond's `Port` model
//! is designed for deep inspection:
//! * **Recursive Merging**: Safely aggregates results from multiple scan phases (SYN, Aggressive, Service, Script).
//! * **Security First**: Native support for TLS/SSL certificate lifecycle analysis.
//! * **Low-Level Telemetry**: Preserves raw TTL and reason codes for advanced OS guessing.

use std::collections::HashMap;

pub mod discovery;
pub mod security;
pub mod service;
pub mod set;

pub use discovery::Discovery;
pub use security::{CertificateInfo, Security};
pub use service::Service;
pub use set::{PortSet, PortSetParseError};

/// Supported transport layer protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// The reachability state of a specific port.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortState {
    /// Actively rejecting connections (e.g., TCP RST or ICMP Unreachable).
    Closed,
    /// Packets are being dropped silently by a firewall.
    Dropped,
    /// Explicitly rejected by an intermediary device.
    Blocked,
    /// Actively accepting connections.
    Open,
}

/// A comprehensive "Rich" model representing a service endpoint discovered on a host.
///
/// Unlike a simple port number, a `Port` captures the full lifecycle of a service:
/// how it was found, its security posture, and its functional identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// The 16-bit port number.
    pub number: u16,

    /// The transport protocol (TCP/UDP).
    pub protocol: Protocol,

    /// The discovered state of the port.
    pub state: PortState,

    /// Rich service identity (e.g., "OpenSSH 8.9", CPE strings).
    pub service: Option<Service>,

    /// Security/Encryption details (TLS certificate, ciphers).
    pub security: Option<Security>,

    /// Discovery telemetry (TTL, reason for state, timestamps).
    pub discovery: Option<Discovery>,

    /// Extensible map for scan scripts and custom detection engines.
    /// Wrapped in an Option to avoid heap allocation for filtered/dropped ports.
    pub scripts: Option<HashMap<String, String>>,
}

impl Port {
    /// Creates a new, basic Port instance.
    pub fn new(number: u16, protocol: Protocol, state: PortState) -> Self {
        Self {
            number,
            protocol,
            state,
            service: None,
            security: None,
            discovery: None,
            scripts: None,
        }
    }

    /// Merges architectural findings from another Port record into this one.
    ///
    /// Prioritizes the most definitive port state using Ord-based comparison.
    /// Merges nested `Service`, `Security`, and `Discovery` metadata recursively.
    pub fn merge(&mut self, other: Port) {
        // 1. Merge State (using the Ord derivation for Closed < Dropped < Blocked < Open)
        self.state = std::cmp::max(self.state.clone(), other.state);

        // 2. Merge Service Info
        if let Some(other_service) = other.service {
            if let Some(ref mut self_service) = self.service {
                self_service.merge(other_service);
            } else {
                self.service = Some(other_service);
            }
        }

        // 3. Merge Security Info
        if let Some(other_security) = other.security {
            if let Some(ref mut self_security) = self.security {
                self_security.merge(other_security);
            } else {
                self.security = Some(other_security);
            }
        }

        // 4. Merge Discovery (Keep existing if present, discovery is usually primary)
        if self.discovery.is_none() {
            self.discovery = other.discovery;
        }

        // 5. Merge Scripts
        if let Some(other_scripts) = other.scripts {
            let self_scripts = self.scripts.get_or_insert_with(HashMap::new);
            for (key, value) in other_scripts {
                self_scripts.entry(key).or_insert(value);
            }
        }
    }

    /// Builder method to add service information.
    pub fn with_service(mut self, service: Service) -> Self {
        self.service = Some(service);
        self
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
    fn merge_state_upgrades_to_open() {
        let mut port = Port::new(80, Protocol::Tcp, PortState::Closed);
        port.merge(Port::new(80, Protocol::Tcp, PortState::Open));
        assert_eq!(port.state, PortState::Open);
    }

    #[test]
    fn merge_upgrades_closed_to_dropped() {
        let mut port = Port::new(80, Protocol::Tcp, PortState::Closed);
        port.merge(Port::new(80, Protocol::Tcp, PortState::Dropped));
        assert_eq!(port.state, PortState::Dropped);
    }

    #[test]
    fn merge_combines_nested_service_metadata() {
        let mut port = Port::new(22, Protocol::Tcp, PortState::Open);
        port.service = Some(Service::new("ssh"));

        let mut other = Port::new(22, Protocol::Tcp, PortState::Open);
        let mut srv = Service::new("ssh");
        srv.product = Some("OpenSSH".to_string());
        other.service = Some(srv);

        port.merge(other);
        let s = port.service.unwrap();
        assert_eq!(s.name, "ssh");
        assert_eq!(srv_product(&s), Some("OpenSSH"));
    }

    #[test]
    fn merge_scripts_handles_option_and_aggregation() {
        let mut port = Port::new(80, Protocol::Tcp, PortState::Open);
        
        // s1: Initially None
        let mut other1 = Port::new(80, Protocol::Tcp, PortState::Open);
        let mut scripts1 = HashMap::new();
        scripts1.insert("http-title".to_string(), "Index".to_string());
        other1.scripts = Some(scripts1);

        port.merge(other1);
        assert_eq!(port.scripts.as_ref().unwrap().get("http-title").map(|s| s.as_str()), Some("Index"));

        // s2: Aggregation
        let mut other2 = Port::new(80, Protocol::Tcp, PortState::Open);
        let mut scripts2 = HashMap::new();
        scripts2.insert("http-server".to_string(), "nginx".to_string());
        other2.scripts = Some(scripts2);

        port.merge(other2);
        assert_eq!(port.scripts.as_ref().unwrap().len(), 2);
    }

    fn srv_product(s: &Service) -> Option<&str> {
        s.product.as_deref()
    }
}
