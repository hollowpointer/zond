// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Host Model
//!
//! This module defines the [`Host`] entity, which represents a single network device detected during a scan.
//!
//! ## Key Concepts
//! * **Unified Model**: A `Host` represents both devices on the local LAN (Layer 2) and remote devices (Layer 3).
//! * **Identity**: A host is primarily identified by its IP address for the duration of a scan.
//! * **Enrichment**: The model is mutable and strictly additive; scans populate optional fields (hostname, vendor) as data becomes available.

use crate::utils::mac;
use pnet::datalink::MacAddr;
use std::{
    collections::{BTreeSet, HashSet, VecDeque},
    net::IpAddr,
    time::Duration,
};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum NetworkRole {
    Gateway,
    DHCP,
    DNS,
}

/// Represents a discovered network host.
///
/// A host is defined by what we know about it.
#[derive(Debug, Clone)]
pub struct Host {
    /// The primary way to identify the host (on this run).
    /// Note: A host might have multiple IPs, but we usually discover it via one.
    pub primary_ip: IpAddr,

    /// The resolved hostname (if any).
    pub hostname: Option<String>,

    /// All known IP addresses for this host.
    pub ips: BTreeSet<IpAddr>,

    /// Open ports found on the host.
    /// TODO: Refactor to a rich `Port` struct in a future iteration.
    pub ports: BTreeSet<u16>,

    /// The MAC address (only available if the host is on the same LAN).
    pub mac: Option<MacAddr>,

    /// The device vendor/manufacturer (derived from MAC).
    pub vendor: Option<String>,

    /// Inferred network roles (e.g., is it a Gateway?).
    pub network_roles: HashSet<NetworkRole>,

    /// The last 10 round-trip time measurements.
    rtt_history: VecDeque<Duration>,
}

impl Host {
    /// Creates a new Host with minimal information (just an IP).
    pub fn new(primary_ip: IpAddr) -> Self {
        let mut ips = BTreeSet::new();
        ips.insert(primary_ip);

        Self {
            primary_ip,
            hostname: None,
            ips,
            ports: BTreeSet::new(),
            mac: None,
            vendor: None,
            network_roles: HashSet::new(),
            rtt_history: VecDeque::with_capacity(10),
        }
    }

    pub fn with_mac(mut self, mac: MacAddr) -> Self {
        self.mac = Some(mac);
        self.vendor = mac::get_vendor(mac);
        self
    }

    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.add_rtt(rtt);
        self
    }

    /// Replaces the RTT history of the host
    pub fn set_rtts(&mut self, rtts: VecDeque<Duration>) {
        self.rtt_history = rtts;
        while self.rtt_history.len() > 10 {
            self.rtt_history.pop_front();
        }
    }

    /// Adds a new RTT to the hosts RTT history, keeping only the most recent 10
    pub fn add_rtt(&mut self, rtt: Duration) {
        self.rtt_history.push_back(rtt);
        if self.rtt_history.len() > 10 {
            self.rtt_history.pop_front();
        }
    }

    /// Returns the quickest RTT from the last 10 RTT's
    pub fn min_rtt(&self) -> Option<Duration> {
        self.rtt_history.iter().min().copied()
    }

    /// Returns the slowest RTT from the last 10 RTT's
    pub fn max_rtt(&self) -> Option<Duration> {
        self.rtt_history.iter().max().copied()
    }

    /// Calculates the average RTT using the RTT history
    pub fn average_rtt(&self) -> Option<Duration> {
        if self.rtt_history.is_empty() {
            return None;
        }
        let sum: Duration = self.rtt_history.iter().sum();
        Some(sum / self.rtt_history.len() as u32)
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
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use super::Host;

    static IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100));

    #[test]
    fn rtt_history_caps_at_ten() {
        let mut host: Host = Host::new(IP_ADDR);
        // Creates 11 rtt's and adds them to the host
        (0..11)
            .map(Duration::from_millis)
            .for_each(|rtt| host.add_rtt(rtt));

        assert_eq!(host.rtt_history.len(), 10);
        assert_ne!(host.rtt_history.len(), 11);
    }

    #[test]
    fn rtt_history_adds_to_back_of_list() {
        let mut host: Host = Host::new(IP_ADDR);
        // Creates 8 rtt's and adds them to the host
        (0..8)
            .map(Duration::from_millis)
            .for_each(|rtt| host.add_rtt(rtt));

        assert_eq!(host.rtt_history[7], Duration::from_millis(7));
    }

    #[test]
    fn rtt_history_slides_correctly() {
        let mut host: Host = Host::new(IP_ADDR);
        // Creates 15 rtt's and adds them to the host
        (0..15)
            .map(Duration::from_millis)
            .for_each(|rtt| host.add_rtt(rtt));

        assert_eq!(host.rtt_history[0], Duration::from_millis(5));
        assert_eq!(host.rtt_history[9], Duration::from_millis(14));
    }

    #[test]
    fn min_rtt_returns_correct_val() {
        let mut host: Host = Host::new(IP_ADDR);
        host.add_rtt(Duration::from_millis(6));
        host.add_rtt(Duration::from_millis(5));
        host.add_rtt(Duration::from_millis(10));

        assert_eq!(host.min_rtt(), Some(Duration::from_millis(5)));
    }

    #[test]
    fn max_rtt_returns_correct_val() {
        let mut host: Host = Host::new(IP_ADDR);
        host.add_rtt(Duration::from_millis(6));
        host.add_rtt(Duration::from_millis(5));
        host.add_rtt(Duration::from_millis(10));

        assert_eq!(host.max_rtt(), Some(Duration::from_millis(10)));
    }

    #[test]
    fn average_rtt_calculates_correctly() {
        let mut host: Host = Host::new(IP_ADDR);
        host.add_rtt(Duration::from_millis(9));
        host.add_rtt(Duration::from_millis(3));

        assert_eq!(host.average_rtt(), Some(Duration::from_millis(6)));
    }

    #[test]
    fn average_rtt_returns_none() {
        let host: Host = Host::new(IP_ADDR);
        assert_eq!(host.average_rtt(), None);
    }
}
