// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Network Target Composition
//!
//! This module defines the atomic units of a scan. It bridges the gap between
//! high-level network definitions ([`IpSet`], [`PortSet`]) and the low-level
//! packets sent by the scanner engine.

use crate::models::ip::set::IpSet;
use crate::models::port::{PortSet, Protocol};
use std::net::IpAddr;

/// Represents a single, atomic connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

/// A blueprint pairing a set of IP addresses with a set of ports.
///
/// `TargetSet` supports lazy evaluation of the underlying IP set. Volume queries
/// and iteration will trigger normalization of the IP set if needed.
#[derive(Debug, Clone, Default)]
pub struct TargetSet {
    pub ips: IpSet,
    pub ports: PortSet,
}

impl TargetSet {
    /// Creates a new scan blueprint.
    pub fn new(ips: IpSet, ports: PortSet) -> Self {
        Self { ips, ports }
    }

    /// Prepares the internal IP set for high-performance read-only access.
    pub fn canonicalize(&mut self) {
        self.ips.canonicalize();
    }

    /// Returns the total number of targets. Performs lazy IP normalization if needed.
    pub fn total_targets(&mut self) -> u128 {
        self.ips.len() * (self.ports.len() as u128)
    }

    /// Creates a lazy iterator over every IP/Port combination. Performs lazy IP normalization.
    pub fn iter(&mut self) -> impl Iterator<Item = Target> + '_ {
        let ports = &self.ports;
        self.ips.iter().flat_map(move |ip| {
            ports.iter().map(move |(port, protocol)| Target {
                ip,
                port,
                protocol,
            })
        })
    }

    /// Thread-safe version of `total_targets`.
    ///
    /// # Panics
    /// Panics in debug mode if the underlying IP set is not canonicalized.
    pub fn total_targets_canonical(&self) -> u128 {
        self.ips.len_canonical() * (self.ports.len() as u128)
    }
}

/// A collection of multiple [`TargetSet`] units.
#[derive(Debug, Clone, Default)]
pub struct TargetMap {
    pub units: Vec<TargetSet>,
}

impl TargetMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_unit(&mut self, unit: TargetSet) {
        self.units.push(unit);
    }

    /// Triggers normalization for all units.
    pub fn canonicalize(&mut self) {
        for unit in &mut self.units {
            unit.canonicalize();
        }
    }

    /// Returns the total targets across all units. Performs lazy normalization.
    pub fn total_targets(&mut self) -> u128 {
        self.units.iter_mut().map(|u| u.total_targets()).sum()
    }

    /// Returns the total number of unique IP addresses. Performs lazy normalization.
    pub fn total_ips(&mut self) -> u128 {
        self.units.iter_mut().map(|u| u.ips.len()).sum()
    }

    /// Returns true if no targets are defined.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty() || self.units.iter().all(|u| u.ips.is_empty())
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

    fn mock_ip_set(input: &str) -> IpSet {
        input.parse().expect("Valid IP input")
    }

    fn mock_port_set(input: &str) -> PortSet {
        input.parse().expect("Valid Port input")
    }

    #[test]
    fn target_set_lazy_math() {
        let mut ips = mock_ip_set("192.168.1.0/24");
        // Force dirty state
        ips.push_v4_range(crate::models::ip::range::Ipv4Range::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ).unwrap());
        
        let mut ts = TargetSet::new(ips, mock_port_set("80, 443"));
        // Query triggers normalization
        assert_eq!(ts.total_targets(), (256 + 1) * 2);
    }

    #[test]
    fn target_map_aggregation() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(mock_ip_set("10.0.0.1-10.0.0.5"), mock_port_set("80,443")));
        assert_eq!(map.total_targets(), 10);
    }
}
