// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Host Reachability Status
//!
//! This module defines the [`HostStatus`] model and supporting structures
//! for recording how and why a host is considered reachable.
//!
//! The cornerstone of this module is the semantic ordering of status variants,
//! allowing disparate scan results to be merged deterministically by prioritizing
//! the most definitive evidence of a host's state.

use std::sync::Arc;

/// The high-level reachability state of a network host.
///
/// Variants are ordered by **semantic severity** and **reachability certainty**:
/// `Unknown < Down < Filtered < Up`.
///
/// This ordering is critical for the [`Host::merge`](crate::models::Host::merge) logic:
/// if one scan identifies a host as `Down` but a concurrent high-fidelity scan
/// identifies it as `Up`, the `Up` status will prevail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostStatus {
    /// Reachability has not yet been determined or the scan results were inconclusive.
    Unknown,
    /// The host is explicitly confirmed to be offline or unreachable (e.g., ICMP Host Unreachable).
    Down,
    /// The host exists on the network, but active probes are being dropped or rejected by a firewall.
    Filtered,
    /// The host is confirmed to be online and fully responding to probes.
    Up,
}

/// Known protocols or events that provide evidence of host reachability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StatusProtocol {
    /// Discovered via Address Resolution Protocol (Layer 2). Usually confirms local adjacency.
    Arp,
    /// Discovered via ICMP Echo Request/Reply.
    IcmpEcho,
    /// Discovered via a successful TCP 3-way handshake on an open port.
    TcpSyn,
    /// Discovered via a valid application-level response over UDP.
    Udp,
    /// A custom discovery method initiated by a specialized scanning script.
    Custom(Arc<str>),
}

/// A structured rationale for a host's reachability state.
///
/// `StatusReason` pairs a protocol event with optional human-readable or machine-parsable
/// details to provide a transparent "audit trail" for host discovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatusReason {
    /// The specific protocol-level event that triggered this status.
    pub protocol: StatusProtocol,

    /// Extended details about the response (e.g., "Received TCP RST", "TTL Exceeded in transit").
    ///
    /// Stored as an `Arc<str>` to minimize heap churn when thousands of hosts report
    /// identical rationales.
    pub details: Option<Arc<str>>,
}

impl StatusReason {
    /// Creates a new `StatusReason` with the specified protocol and details.
    pub fn new(protocol: StatusProtocol, details: impl Into<Arc<str>>) -> Self {
        Self {
            protocol,
            details: Some(details.into()),
        }
    }

    /// Creates a new `StatusReason` containing only protocol-level evidence without extra details.
    pub fn basic(protocol: StatusProtocol) -> Self {
        Self {
            protocol,
            details: None,
        }
    }
}

impl HostStatus {
    /// Returns `true` if the host is confirmed to be fully online and responding.
    #[inline]
    pub fn is_up(&self) -> bool {
        matches!(self, HostStatus::Up)
    }

    /// Returns `true` if the host is explicitly confirmed to be offline.
    #[inline]
    pub fn is_down(&self) -> bool {
        matches!(self, HostStatus::Down)
    }

    /// Returns `true` if there is evidence the host is present on the network,
    /// even if communication is restricted by a firewall.
    #[inline]
    pub fn is_alive(&self) -> bool {
        matches!(self, HostStatus::Up | HostStatus::Filtered)
    }
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostStatus::Unknown => write!(f, "Unknown"),
            HostStatus::Down => write!(f, "Down"),
            HostStatus::Filtered => write!(f, "Filtered"),
            HostStatus::Up => write!(f, "Up"),
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
    fn status_ordering_contract() {
        // This test ensures that the derived Ord implementation matches the semantic severity.
        assert!(HostStatus::Unknown < HostStatus::Down);
        assert!(HostStatus::Down < HostStatus::Filtered);
        assert!(HostStatus::Filtered < HostStatus::Up);
    }

    #[test]
    fn status_alive_semantics() {
        assert!(!HostStatus::Unknown.is_alive());
        assert!(!HostStatus::Down.is_alive());
        assert!(HostStatus::Filtered.is_alive());
        assert!(HostStatus::Up.is_alive());
    }

    #[test]
    fn status_display_consistency() {
        assert_eq!(HostStatus::Unknown.to_string(), "Unknown");
        assert_eq!(HostStatus::Up.to_string(), "Up");
    }

    #[test]
    fn status_reason_ergonomics() {
        let reason = StatusReason::new(
            StatusProtocol::Custom(Arc::from("dns-probe")),
            "Resolved A record successfully",
        );

        assert_eq!(
            reason.protocol,
            StatusProtocol::Custom(Arc::from("dns-probe"))
        );
        assert_eq!(reason.details.as_deref(), Some("Resolved A record successfully"));
    }
}
