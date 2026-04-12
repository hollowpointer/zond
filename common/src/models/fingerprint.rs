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
use std::{net::IpAddr, sync::Arc};

/// Represents a single, atomic connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

/// A blueprint pairing a set of IP addresses with a set of ports.
///
/// `TargetSet` supports lazy evaluation of the underlying sets. Volume queries
/// and iteration will safely trigger normalization of the IPs and ports.
#[derive(Debug, Clone, Default)]
pub struct TargetSet {
    /// Internal IP set. Kept private to protect lazy-evaluation invariants.
    ips: IpSet,
    /// Internal Port set. Kept private to protect lazy-evaluation invariants.
    ports: PortSet,
}

impl TargetSet {
    /// Creates a new scan blueprint.
    pub fn new(ips: IpSet, ports: PortSet) -> Self {
        Self { ips, ports }
    }

    /// Returns a read-only reference to the underlying IP set.
    pub fn ips(&self) -> &IpSet {
        &self.ips
    }

    /// Returns a read-only reference to the underlying Port set.
    pub fn ports(&self) -> &PortSet {
        &self.ports
    }

    /// Prepares the internal IP and Port sets for high-performance read-only access.
    pub fn canonicalize(&mut self) {
        self.ips.canonicalize();
        self.ports.canonicalize();
    }

    /// Returns the total number of targets. Performs lazy normalization if needed.
    pub fn total_targets(&mut self) -> u128 {
        self.canonicalize();
        let port_len = self.ports.len();
        self.ips.len() * (port_len as u128)
    }

    /// Creates a lazy iterator over every IP/Port combination. Performs lazy normalization.
    ///
    /// This uses `Arc` internally to prevent O(N) memory allocations when iterating
    /// over massive subnets (e.g., /8 or IPv6 ranges).
    pub fn iter(&mut self) -> impl Iterator<Item = Target> + '_ {
        self.canonicalize();

        // Wrap the ports in an Arc slice to completely eliminate heap allocations
        // inside the IP iteration loop.
        let ports_arc: Arc<[(u16, Protocol)]> = self.ports.to_vec().into();

        self.ips.iter().flat_map(move |ip| {
            let local_ports = Arc::clone(&ports_arc);
            (0..local_ports.len()).map(move |i| Target {
                ip,
                port: local_ports[i].0,
                protocol: local_ports[i].1,
            })
        })
    }

    /// Thread-safe version of `total_targets`.
    ///
    /// # Panics
    /// Panics in debug mode if the underlying IP or Port set is not canonicalized.
    pub fn total_targets_canonical(&self) -> u128 {
        self.ips.len_canonical() * (self.ports.len_canonical() as u128)
    }

    /// Returns true if either the IP set or the Port set is completely empty.
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() || self.ports.is_empty()
    }
}

/// A collection of multiple [`TargetSet`] units.
///
/// `TargetMap` is useful for defining complex, disparate scan definitions
/// (e.g., scanning `10.0.0.0/24` on Port 80, but `192.168.1.5` on Ports 1-65535).
#[derive(Debug, Clone, Default)]
pub struct TargetMap {
    units: Vec<TargetSet>,
}

impl TargetMap {
    /// Creates a new, empty `TargetMap`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a new unit definition to the map.
    pub fn add_unit(&mut self, unit: TargetSet) {
        self.units.push(unit);
    }

    /// Triggers normalization for all units.
    pub fn canonicalize(&mut self) {
        for unit in &mut self.units {
            unit.canonicalize();
        }
    }

    /// Returns the gross total of target connections across all units.
    /// Performs lazy normalization.
    pub fn gross_targets(&mut self) -> u128 {
        self.units.iter_mut().map(|u| u.total_targets()).sum()
    }

    /// Returns the gross number of IP addresses across all units.
    /// Performs lazy normalization.
    ///
    /// **Note:** This is a raw capacity count. If the same IP address exists
    /// in multiple `TargetSet` units, it will be counted multiple times.
    pub fn gross_ips(&mut self) -> u128 {
        self.units.iter_mut().map(|u| u.ips().len()).sum()
    }

    /// Returns true if no targets are defined across any unit.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty() || self.units.iter().all(|u| u.is_empty())
    }

    /// Creates a flattened iterator over every target in every unit.
    pub fn iter(&mut self) -> impl Iterator<Item = Target> + '_ {
        self.units.iter_mut().flat_map(|unit| unit.iter())
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

    // Mock definitions for tests
    fn mock_ip_set(input: &str) -> IpSet {
        input.parse().expect("Valid IP input")
    }

    fn mock_port_set(input: &str) -> PortSet {
        input.parse().expect("Valid Port input")
    }

    #[test]
    fn target_set_lazy_math() {
        let mut ips = mock_ip_set("192.168.1.0/24");
        // Assume IpSet has a way to push a raw range or single IP
        // ips.push(...);

        let mut ts = TargetSet::new(ips, mock_port_set("80, 443"));
        assert_eq!(ts.total_targets(), 256 * 2);
    }

    #[test]
    fn target_map_aggregation() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            mock_ip_set("10.0.0.1-10.0.0.5"),
            mock_port_set("80,443"),
        ));
        assert_eq!(map.gross_targets(), 10);
    }

    #[test]
    fn iteration_is_allocation_safe() {
        let mut ts = TargetSet::new(mock_ip_set("192.168.1.1"), mock_port_set("80, 443"));
        let targets: Vec<Target> = ts.iter().collect();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].port, 80);
        assert_eq!(targets[1].port, 443);
    }
}
