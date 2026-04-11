// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Port Discovery and Metadata
//!
//! This module defines the core types for identifying and detailing network services.
//! It is split into two primary areas:
//! 1. **Core Models**: [`Port`], [`Protocol`], and [`PortState`] for describing identified services.
//! 2. **Targeting**: [`PortSet`] (in [`set` sub-module]) for defining scan ranges.

pub mod set;

pub use set::{PortSet, PortSetParseError};

/// Supported transport layer protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// The reachability state of a specific port.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    /// Actively accepting connections.
    Open,
    /// Actively rejecting connections.
    Closed,
    /// Dropping packets silently (firewalled).
    Ghosted,
    /// Explicitly rejected by an intermediary.
    Blocked,
}

/// A "Rich" model representing a service endpoint discovered on a host.
///
/// Unlike raw identifiers, a `Port` captures the full context of a service,
/// including its state and detected fingerprint/banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// The 16-bit port number.
    pub number: u16,
    /// The transport protocol (TCP/UDP).
    pub protocol: Protocol,
    /// The discovered state of the port.
    pub state: PortState,
    /// Service metadata (e.g., "OpenSSH 8.9", "nginx/1.21").
    pub service_info: Option<String>,
}

impl Port {
    /// Creates a new, basic Port instance.
    pub fn new(number: u16, protocol: Protocol, state: PortState) -> Self {
        Self {
            number,
            protocol,
            state,
            service_info: None,
        }
    }

    /// Merges new findings into an existing port record in place.
    ///
    /// Prioritizes the most definitive port state (`Open` > `Blocked`/`Ghosted` > `Closed`).
    pub fn merge(&mut self, other: Port) {
        match (&self.state, &other.state) {
            (PortState::Open, _) => {}
            (_, PortState::Open) => self.state = PortState::Open,
            (PortState::Closed, PortState::Blocked | PortState::Ghosted) => {
                self.state = other.state.clone();
            }
            _ => {}
        }

        if self.service_info.is_none() && other.service_info.is_some() {
            self.service_info = other.service_info;
        }
    }

    /// Builder method to add service banner information.
    pub fn with_banner(mut self, banner: &str) -> Self {
        self.service_info = Some(banner.to_string());
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
    fn merge_state_upgrades_closed_to_intermediate() {
        let mut port = Port::new(80, Protocol::Tcp, PortState::Closed);
        port.merge(Port::new(80, Protocol::Tcp, PortState::Blocked));
        assert_eq!(port.state, PortState::Blocked);
    }

    #[test]
    fn merge_adds_missing_service_info() {
        let mut port = Port::new(22, Protocol::Tcp, PortState::Open);
        let other = Port::new(22, Protocol::Tcp, PortState::Open).with_banner("OpenSSH 8.9p1");

        port.merge(other);
        assert_eq!(port.service_info.as_deref(), Some("OpenSSH 8.9p1"));
    }
}
