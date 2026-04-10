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
///
/// This is the pixel of the scan. Scanners (TCP, SYN, UDP) ingest these
/// objects to perform individual targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

/// A blueprint pairing a set of IP addresses with a set of ports.
///
/// `TargetSet` does not store individual targets in memory; instead, it
/// defines the boundaries of a Scan Area. This allows Zond to handle
/// massive ranges without significant RAM overhead.
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

    /// Returns the total number of targets defined by this set.
    ///
    /// Calculated as (Number of IPs) × (Number of Ports).
    pub fn total_targets(&self) -> u128 {
        (self.ips.len() * (self.ports.len()) as u64) as u128
    }

    /// Creates a lazy iterator over every IP/Port combination in the set.
    ///
    /// This is a linear iterator. For high-concurrency or stealth scanning,
    /// use the specialized dispatcher/shuffler instead.
    pub fn iter(&self) -> impl Iterator<Item = Target> + '_ {
        self.ips.iter().flat_map(move |ip| {
            // Destructure the (u16, Protocol) tuple from PortSet::iter()
            self.ports
                .iter()
                .map(move |(port, protocol)| Target { ip, port, protocol })
        })
    }
}

/// A collection of multiple [`TargetSet`] units.
///
/// This acts as the final "Task List" for the engine, supporting mixed
/// configurations (e.g., scanning one range for HTTP and another for SMB).
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

    /// Returns the total targets across all defined units.
    pub fn total_targets(&self) -> u128 {
        self.units.iter().map(|u| u.total_targets()).sum()
    }

    /// Returns the total number of unique IP addresses targeted.
    pub fn total_ips(&self) -> usize {
        self.units.iter().map(|u| u.ips.len() as usize).sum()
    }

    /// Returns true if no targets are defined.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty() || self.total_targets() == 0
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
    use crate::models::port::Protocol;

    fn mock_ip_set(input: &str) -> IpSet {
        IpSet::try_from(input).expect("Valid IP input for tests")
    }

    fn mock_port_set(input: &str) -> PortSet {
        PortSet::try_from(input).expect("Valid Port input for tests")
    }

    #[test]
    fn target_set_math() {
        let ips = mock_ip_set("192.168.1.0/24"); // 256 IPs
        let ports = mock_port_set("80, 443, 1000-1007"); // 10 Ports
        let ts = TargetSet::new(ips, ports);

        assert_eq!(ts.total_targets(), 2560);
    }

    #[test]
    fn target_set_iteration() {
        let ips = mock_ip_set("1.1.1.1, 1.1.1.2");
        let ports = mock_port_set("80, u:53");
        let ts = TargetSet::new(ips, ports);

        let targets: Vec<Target> = ts.iter().collect();

        // Check total count: 2 IPs * 2 Ports = 4 Targets
        assert_eq!(targets.len(), 4);

        // Verify specific combinations exist
        assert!(targets.contains(&Target {
            ip: "1.1.1.1".parse().unwrap(),
            port: 80,
            protocol: Protocol::Tcp
        }));
        assert!(targets.contains(&Target {
            ip: "1.1.1.2".parse().unwrap(),
            port: 53,
            protocol: Protocol::Udp
        }));
    }

    #[test]
    fn target_map_aggregation() {
        let mut map = TargetMap::new();

        // Unit 1: 5 IPs, 2 Ports = 10 targets
        map.add_unit(TargetSet::new(
            mock_ip_set("10.0.0.1-10.0.0.5"),
            mock_port_set("80, 443"),
        ));

        // Unit 2: 1 IP, 5 Ports = 5 targets
        map.add_unit(TargetSet::new(
            mock_ip_set("1.1.1.1"),
            mock_port_set("22, 80, 443, 8080, 8443"),
        ));

        assert_eq!(map.total_targets(), 15);
        assert_eq!(map.total_ips(), 6);
        assert!(!map.is_empty());
    }

    #[test]
    fn empty_behavior() {
        let map = TargetMap::new();
        assert!(map.is_empty());

        let ts_empty = TargetSet::new(mock_ip_set(""), mock_port_set(""));
        assert_eq!(ts_empty.total_targets(), 0);
    }

    #[test]
    fn u128_overflow_safety() {
        let large_ips = u32::MAX as u128 + 1; // 4,294,967,296
        let large_ports = u16::MAX as u128 + 1; // 65,536

        let result = large_ips * large_ports;
        assert_eq!(result, 281_474_976_710_656);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::Ipv4Addr;

    fn any_ipv4() -> impl Strategy<Value = Ipv4Addr> {
        proptest::prelude::any::<u32>().prop_map(Ipv4Addr::from)
    }

    fn any_ip_set() -> impl Strategy<Value = IpSet> {
        (any_ipv4(), any_ipv4()).prop_map(|(a, b)| {
            let start = std::cmp::min(a, b);
            let mut set = IpSet::new();
            set.insert(std::net::IpAddr::V4(start));
            set
        })
    }

    // Generate a simple port set with a random number of ports
    fn any_port_set() -> impl Strategy<Value = PortSet> {
        (0..=100u16).prop_map(|count| {
            let mut s = String::new();
            for i in 0..count {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&format!("{}", i));
            }
            PortSet::try_from(s.as_str()).unwrap_or_default()
        })
    }

    proptest::proptest! {
        /// Verify that total_targets is always exactly (IPs * Ports).
        #[test]
        fn target_set_volume_invariant(ips in any_ip_set(), ports in any_port_set()) {
            let ts = TargetSet::new(ips.clone(), ports.clone());
            let expected = (ips.len() * ports.len() as u64) as u128;
            prop_assert_eq!(ts.total_targets(), expected);
        }

        /// Verify that target maps correctly sum volumes from multiple units.
        #[test]
        fn target_map_summation(ips1 in any_ip_set(), ips2 in any_ip_set()) {
            let mut map = TargetMap::new();
            let ports = PortSet::default();

            let ts1 = TargetSet::new(ips1.clone(), ports.clone());
            let ts2 = TargetSet::new(ips2.clone(), ports.clone());

            map.add_unit(ts1.clone());
            map.add_unit(ts2.clone());

            prop_assert_eq!(map.total_targets(), ts1.total_targets() + ts2.total_targets());
        }
    }
}
