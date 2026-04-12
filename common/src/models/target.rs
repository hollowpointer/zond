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
use thiserror::Error;

/// Errors that can occur during target composition and calculation.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum TargetError {
    #[error("Target collection is in a dirty state; call `canonicalize()` before concurrent reads")]
    UncanonicalizedState,

    #[error("Target calculation resulted in an integer overflow")]
    CapacityOverflow,
}

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
    /// Tracks whether the underlying sets are currently normalized for safe reads.
    is_canonicalized: bool,
}

impl TargetSet {
    /// Creates a new scan blueprint. Defaults to an uncanonicalized state.
    pub fn new(ips: IpSet, ports: PortSet) -> Self {
        Self {
            ips,
            ports,
            is_canonicalized: false,
        }
    }

    /// Returns a read-only reference to the underlying IP set.
    pub fn ips(&self) -> &IpSet {
        &self.ips
    }

    /// Returns a read-only reference to the underlying Port set.
    pub fn ports(&self) -> &PortSet {
        &self.ports
    }

    /// Returns the number of unique IP addresses in this set.
    /// Performs lazy normalization.
    pub fn ip_count(&mut self) -> u128 {
        self.ips.len()
    }

    /// Returns the number of unique ports in this set.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Prepares the internal IP and Port sets for high-performance read-only access.
    pub fn canonicalize(&mut self) {
        if !self.is_canonicalized {
            self.ips.canonicalize();
            self.is_canonicalized = true;
        }
    }

    /// Returns the total number of targets. Performs lazy normalization if needed.
    ///
    /// Returns a `TargetError::CapacityOverflow` if the calculation exceeds `u128::MAX`.
    pub fn total_targets(&mut self) -> Result<u128, TargetError> {
        self.canonicalize();

        let port_len = self.ports.len() as u128;
        self.ips
            .len()
            .checked_mul(port_len)
            .ok_or(TargetError::CapacityOverflow)
    }

    /// Creates a lazy iterator over every IP/Port combination. Performs lazy normalization.
    ///
    /// This uses `Arc` internally to prevent O(N) memory allocations when iterating
    /// over massive subnets (e.g., /8 or IPv6 ranges).
    pub fn iter(&mut self) -> impl Iterator<Item = Target> + '_ {
        self.canonicalize();

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
    /// This method is strictly read-only. It returns `TargetError::UncanonicalizedState`
    /// if the sets have not been normalized prior to concurrent access.
    pub fn total_targets_canonical(&self) -> Result<u128, TargetError> {
        if !self.is_canonicalized {
            return Err(TargetError::UncanonicalizedState);
        }

        let port_len = self.ports.len() as u128;
        self.ips
            .len_canonical()
            .checked_mul(port_len)
            .ok_or(TargetError::CapacityOverflow)
    }

    /// Returns true if either the IP set or the Port set is completely empty.
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() || self.ports.is_empty()
    }
}

/// A collection of multiple [`TargetSet`] units.
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
    pub fn gross_targets(&mut self) -> Result<u128, TargetError> {
        let mut total: u128 = 0;
        for unit in &mut self.units {
            let unit_total = unit.total_targets()?;
            total = total
                .checked_add(unit_total)
                .ok_or(TargetError::CapacityOverflow)?;
        }
        Ok(total)
    }

    /// Returns the gross number of IP addresses across all units.
    /// Performs lazy normalization.
    pub fn gross_ips(&mut self) -> Result<u128, TargetError> {
        let mut total: u128 = 0;
        for unit in &mut self.units {
            total = total
                .checked_add(unit.ip_count())
                .ok_or(TargetError::CapacityOverflow)?;
        }
        Ok(total)
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
        let mut ts = TargetSet::new(mock_ip_set("192.168.1.0/24"), mock_port_set("80, 443"));
        assert_eq!(ts.total_targets().unwrap(), 256 * 2);
    }

    #[test]
    fn thread_safe_reads_require_canonicalization() {
        let ts = TargetSet::new(mock_ip_set("192.168.1.0/24"), mock_port_set("80"));

        // Reading without canonicalizing should return an explicit error
        let err = ts.total_targets_canonical().unwrap_err();
        assert_eq!(err, TargetError::UncanonicalizedState);
    }

    #[test]
    fn thread_safe_reads_succeed_when_prepared() {
        let mut ts = TargetSet::new(mock_ip_set("192.168.1.0/24"), mock_port_set("80"));
        ts.canonicalize();

        assert_eq!(ts.total_targets_canonical().unwrap(), 256);
    }

    #[test]
    fn target_map_aggregation() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            mock_ip_set("10.0.0.1-10.0.0.5"),
            mock_port_set("80,443"),
        ));
        assert_eq!(map.gross_targets().unwrap(), 10);
    }
}
