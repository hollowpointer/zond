// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Port Targeting and Range Management
//!
//! This module provides the [`PortSet`] model, an optimized container for defining
//! which TCP and UDP ports should be scanned.
//!
//! ## Overview
//!
//! Unlike the "Rich" [`Port`](crate::models::port::Port) model which stores result metadata,
//! `PortSet` focus exclusively on efficient range containment and parsing. It supports:
//! * **Mixed Protocols**: Separate tracking for TCP and UDP ranges.
//! * **Smart Parsing**: Human-friendly string parsing (e.g., `"80, 443, u:53, 1000-2000"`).
//! * **High Performance**: Optimized iteration and membership checks.

use crate::models::port::Protocol;
use std::{num::ParseIntError, ops::RangeInclusive, str::FromStr};
use thiserror::Error;

/// Common defaults for rapid discovery scans.
pub const DEFAULT_PORTSET_PORTS: &str = "22, 80, 443, 445, 3389";

// ══════════════════════════════════════════════════════════════════════════════
// Error Types
// ══════════════════════════════════════════════════════════════════════════════

/// Errors that can occur when parsing a port range string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PortSetParseError {
    /// The input string could not be parsed as a 16-bit integer.
    #[error("Failed to parse port from '{input}': {source}")]
    InvalidPort {
        input: String,
        #[source]
        source: ParseIntError,
    },

    /// The range start is higher than the end (e.g., "80-20").
    #[error("Invalid port range: start ({start}) cannot be strictly greater than end ({end})")]
    InvalidRange { start: u16, end: u16 },

    /// The input segment did not match any known port or range format.
    #[error("Malformed port specification, expected a single port or a range: '{0}'")]
    MalformedSpec(String),
}

// ══════════════════════════════════════════════════════════════════════════════
// PortSet Core Model
// ══════════════════════════════════════════════════════════════════════════════

/// A collection of TCP and UDP port ranges used for target discovery.
///
/// `PortSet` is designed to be easily constructed from strings and iterated over
/// during the scan phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSet {
    pub(crate) tcp: Vec<RangeInclusive<u16>>,
    pub(crate) udp: Vec<RangeInclusive<u16>>,
    tcp_dirty: bool,
    udp_dirty: bool,
}

impl PortSet {
    /// Creates a new, empty `PortSet`.
    pub fn new() -> Self {
        Self {
            tcp: Vec::new(),
            udp: Vec::new(),
            tcp_dirty: false,
            udp_dirty: false,
        }
    }

    /// Returns the total number of unique port/protocol combinations.
    ///
    /// Note: This counts every individual port within every range.
    pub fn len(&mut self) -> usize {
        self.canonicalize();
        self.len_canonical()
    }

    /// Returns `true` if no ports are defined for either protocol.
    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty()
    }

    /// Returns an iterator over all individual ports in the set.
    ///
    /// Yields TCP ports first, followed by UDP ports.
    pub fn iter(&mut self) -> impl Iterator<Item = (u16, Protocol)> + '_ {
        self.canonicalize();
        self.iter_canonical()
    }

    /// A thread-safe iterator over canonicalized ranges.
    pub fn iter_canonical(&self) -> impl Iterator<Item = (u16, Protocol)> + '_ {
        debug_assert!(!self.tcp_dirty && !self.udp_dirty, "PortSet must be canonicalized");
        let tcp_iter = self
            .tcp
            .iter()
            .flat_map(|r| r.clone().map(|p| (p, Protocol::Tcp)));
        let udp_iter = self
            .udp
            .iter()
            .flat_map(|r| r.clone().map(|p| (p, Protocol::Udp)));

        tcp_iter.chain(udp_iter)
    }

    /// Flattens the set into a vector of individual ports.
    pub fn to_vec(&mut self) -> Vec<(u16, Protocol)> {
        self.iter().collect()
    }

    pub fn has_tcp(&mut self, port: u16) -> bool {
        self.canonicalize();
        self.has_tcp_canonical(port)
    }

    pub fn has_udp(&mut self, port: u16) -> bool {
        self.canonicalize();
        self.has_udp_canonical(port)
    }

    // ─── Query API (Read-Only / Sync) ────────────────────────────────────────

    /// A high-performance, thread-safe version of `len`.
    pub fn len_canonical(&self) -> usize {
        debug_assert!(!self.tcp_dirty && !self.udp_dirty, "PortSet must be canonicalized");
        let tcp_count: usize = self
            .tcp
            .iter()
            .map(|r| (r.end().saturating_sub(*r.start()) as usize).saturating_add(1))
            .sum();
        let udp_count: usize = self
            .udp
            .iter()
            .map(|r| (r.end().saturating_sub(*r.start()) as usize).saturating_add(1))
            .sum();
        tcp_count + udp_count
    }

    /// A thread-safe version of `has_tcp`. Uses binary search.
    pub fn has_tcp_canonical(&self, port: u16) -> bool {
        debug_assert!(!self.tcp_dirty, "TCP ports must be canonicalized");
        self.tcp.binary_search_by(|range| {
            if port < *range.start() { std::cmp::Ordering::Greater }
            else if port > *range.end() { std::cmp::Ordering::Less }
            else { std::cmp::Ordering::Equal }
        }).is_ok()
    }

    /// A thread-safe version of `has_udp`. Uses binary search.
    pub fn has_udp_canonical(&self, port: u16) -> bool {
        debug_assert!(!self.udp_dirty, "UDP ports must be canonicalized");
        self.udp.binary_search_by(|range| {
            if port < *range.start() { std::cmp::Ordering::Greater }
            else if port > *range.end() { std::cmp::Ordering::Less }
            else { std::cmp::Ordering::Equal }
        }).is_ok()
    }

    /// Triggers sorting and merging of internal ranges.
    pub fn canonicalize(&mut self) {
        if self.tcp_dirty {
            Self::merge_ranges(&mut self.tcp);
            self.tcp_dirty = false;
        }
        if self.udp_dirty {
            Self::merge_ranges(&mut self.udp);
            self.udp_dirty = false;
        }
    }

    fn merge_ranges(ranges: &mut Vec<RangeInclusive<u16>>) {
        if ranges.is_empty() { return; }
        ranges.sort_by_key(|r| *r.start());
        let mut merged = Vec::with_capacity(ranges.len());
        let mut it = ranges.drain(..);
        let mut current = it.next().unwrap();

        for next in it {
            if *next.start() <= (*current.end()).saturating_add(1) {
                if *next.end() > *current.end() {
                    current = *current.start()..=*next.end();
                }
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        *ranges = merged;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Conversion Traits
// ══════════════════════════════════════════════════════════════════════════════

impl Default for PortSet {
    /// Returns a default [`PortSet`] containing common services: 22, 80, 443, 445, 3389.
    fn default() -> Self {
        Self::try_from(DEFAULT_PORTSET_PORTS).expect("Static discovery ports must be valid.")
    }
}

impl TryFrom<&str> for PortSet {
    type Error = PortSetParseError;

    /// Parses a string into a `PortSet`.
    ///
    /// ### Format Support
    /// * **Individual**: `80`, `443`
    /// * **Ranges**: `1000-2000`
    /// * **Protocols**: Defaults to TCP. Use `u:` prefix for UDP (e.g., `u:53`).
    /// * **Mixed**: `80, 443, u:53, 161-162`
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_common::models::port::set::PortSet;
    ///
    /// let mut set = PortSet::try_from("80, u:53, 1000-1005").unwrap();
    /// assert!(set.has_tcp(80));
    /// assert!(set.has_udp(53));
    /// assert_eq!(set.len(), 8); // 1 + 1 + 6
    /// ```
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();

        for part in value.split([',', ' ']).filter(|s| !s.trim().is_empty()) {
            let part = part.trim();

            let (is_udp, raw_range) = if let Some(stripped) = part.strip_prefix("u:") {
                (true, stripped)
            } else {
                (false, part)
            };

            let parts: Vec<&str> = raw_range.split('-').collect();

            let range = match parts.as_slice() {
                [single_port] => {
                    let p = single_port.parse::<u16>().map_err(|source| {
                        PortSetParseError::InvalidPort {
                            input: single_port.to_string(),
                            source,
                        }
                    })?;
                    p..=p
                }
                [start_str, end_str] => {
                    let start = start_str.parse::<u16>().map_err(|source| {
                        PortSetParseError::InvalidPort {
                            input: start_str.to_string(),
                            source,
                        }
                    })?;
                    let end = end_str.parse::<u16>().map_err(|source| {
                        PortSetParseError::InvalidPort {
                            input: end_str.to_string(),
                            source,
                        }
                    })?;

                    if start > end {
                        return Err(PortSetParseError::InvalidRange { start, end });
                    }

                    start..=end
                }
                _ => return Err(PortSetParseError::MalformedSpec(raw_range.to_string())),
            };

            if is_udp {
                udp.push(range);
            } else {
                tcp.push(range);
            }
        }

        let mut set = Self {
            tcp,
            udp,
            tcp_dirty: true,
            udp_dirty: true,
        };
        set.canonicalize();
        Ok(set)
    }
}

impl TryFrom<String> for PortSet {
    type Error = PortSetParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl FromStr for PortSet {
    type Err = PortSetParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl FromIterator<(u16, Protocol)> for PortSet {
    fn from_iter<T: IntoIterator<Item = (u16, Protocol)>>(iter: T) -> Self {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        for (port, proto) in iter {
            match proto {
                Protocol::Tcp => tcp.push(port..=port),
                Protocol::Udp => udp.push(port..=port),
            }
        }
        let mut set = PortSet {
            tcp,
            udp,
            tcp_dirty: true,
            udp_dirty: true,
        };
        set.canonicalize();
        set
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
    fn set_try_from_str_parses_correctly() {
        let port_set_single = PortSet::try_from("21");
        let port_set_multiple = PortSet::try_from("21, 22 80, 800-1000, u:53 8080");

        assert!(port_set_single.is_ok());
        assert!(port_set_multiple.is_ok());

        let mut port_set_single = port_set_single.unwrap();
        let mut port_set_multiple = port_set_multiple.unwrap();

        assert!(port_set_single.has_tcp(21));

        assert!(port_set_multiple.has_tcp(21));
        assert!(port_set_multiple.has_tcp(22));
        assert!(port_set_multiple.has_tcp(80));
        assert!(port_set_multiple.has_tcp(900));
        assert!(port_set_multiple.has_udp(53));
        assert!(port_set_multiple.has_tcp(8080));
    }

    #[test]
    fn set_try_from_str_parses_udp_variants() {
        let port_set_udp = PortSet::try_from("u:22 u:53-100, u:1024");

        assert!(port_set_udp.is_ok());

        let mut port_set_udp = port_set_udp.unwrap();

        assert!(port_set_udp.has_udp(22));
        assert!(port_set_udp.has_udp(53));
        assert!(port_set_udp.has_udp(80));
        assert!(port_set_udp.has_udp(100));
        assert!(port_set_udp.has_udp(1024));
    }

    #[test]
    fn set_empty_input() {
        let empty = PortSet::try_from("   ");
        assert!(empty.is_ok());
        let set = empty.unwrap();
        assert!(set.tcp.is_empty());
        assert!(set.udp.is_empty());
    }

    #[test]
    fn set_boundaries() {
        let mut limits = PortSet::try_from("0, 65535, u:0-65535").unwrap();
        assert!(limits.has_tcp(0));
        assert!(limits.has_tcp(65535));
        assert!(limits.has_udp(32768));
    }

    #[test]
    fn set_messy_delimiters() {
        let mut messy = PortSet::try_from(", 80, , 443 ,").unwrap();
        assert!(messy.has_tcp(80));
        assert!(messy.has_tcp(443));
    }

    #[test]
    fn set_try_from_str_throws_errors() {
        let port_set_invalid_port = PortSet::try_from("80 70000 22");
        let port_set_invalid_range = PortSet::try_from("21 8000-80");
        let port_set_malformed_spec = PortSet::try_from("22 60-70-80 8080");
        let port_set_not_numeric = PortSet::try_from("u:53 abcdef 80");

        assert!(matches!(
            port_set_invalid_port,
            Err(PortSetParseError::InvalidPort { .. })
        ));

        assert!(matches!(
            port_set_invalid_range,
            Err(PortSetParseError::InvalidRange {
                start: 8000,
                end: 80
            })
        ));

        assert!(matches!(
            port_set_not_numeric,
            Err(PortSetParseError::InvalidPort { .. })
        ));

        assert!(matches!(
            port_set_malformed_spec,
            Err(PortSetParseError::MalformedSpec(_))
        ));
    }

    #[test]
    fn set_try_from_string_parses_correctly() {
        let port_set = PortSet::try_from(String::from("21 80-100 u:5353"));

        assert!(port_set.is_ok());

        let mut port_set = port_set.unwrap();

        assert!(port_set.has_tcp(21));
        assert!(port_set.has_tcp(80));
        assert!(port_set.has_tcp(92));
        assert!(port_set.has_tcp(100));
        assert!(port_set.has_udp(5353));
    }

    #[test]
    fn set_overlap_and_adjacency_merging() {
        // Overlap: 1-10 and 5-15 should be 1-15
        let mut set = PortSet::try_from("1-10, 5-15").unwrap();
        assert_eq!(set.len(), 15);
        assert_eq!(set.tcp.len(), 1);

        // Adjacency: 20 and 21 should be 20-21
        let mut set = PortSet::try_from("20, 21").unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.tcp.len(), 1);

        // Subsumption: 100-200 and 150
        let mut set = PortSet::try_from("100-200, 150").unwrap();
        assert_eq!(set.len(), 101);
        assert_eq!(set.tcp.len(), 1);

        // Mixed messy overlaps
        let mut set = PortSet::try_from("u:53, u:53-53, u:50-60, u:55-65").unwrap();
        assert_eq!(set.len(), 16); // 50 to 65
        assert_eq!(set.udp.len(), 1);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest::proptest! {
        /// Verify that any single port inserted is correctly contained in the set.
        #[test]
        fn single_port_roundtrip(p in 0..=65535u16) {
            let s = format!("{}", p);
            let mut set = PortSet::from_str(&s).unwrap();
            prop_assert!(set.has_tcp(p));
            prop_assert_eq!(set.len(), 1);
        }

        /// Verify that any port range [a, b] contains all values within it.
        #[test]
        fn port_range_invariant(a in 0..=65535u16, b in 0..=65535u16) {
            let (start, end) = if a < b { (a, b) } else { (b, a) };
            let s = format!("{}-{}", start, end);
            let mut set = PortSet::from_str(&s).unwrap();

            prop_assert!(set.has_tcp(start));
            prop_assert!(set.has_tcp(end));
            prop_assert_eq!(set.len(), (end - start + 1) as usize);
        }

        /// Verify that UDP prefix 'u:' correctly assigns ports to the UDP set.
        #[test]
        fn udp_prefix_honored(p in 0..=65535u16) {
            let s = format!("u:{}", p);
            let mut set = PortSet::from_str(&s).unwrap();
            prop_assert!(set.has_udp(p));
            prop_assert!(!set.has_tcp(p));
        }

        /// Verify that comma-separated lists correctly aggregate multiple ports.
        #[test]
        fn multiple_ports_aggregation(p1 in 0..=1000u16, p2 in 2000..=3000u16) {
            let s = format!("{}, {}", p1, p2);
            let mut set = PortSet::from_str(&s).unwrap();
            prop_assert!(set.has_tcp(p1));
            prop_assert!(set.has_tcp(p2));
            prop_assert_eq!(set.len(), 2);
        }

        /// Invariant: Normalization produces the same port count as a HashSet.
        #[test]
        fn normalization_invariant(ports in prop::collection::vec(0..=500u16, 1..=50)) {
            let s = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
            let mut set = PortSet::from_str(&s).unwrap();
            
            let unique_count = ports.into_iter().collect::<std::collections::HashSet<_>>().len();
            prop_assert_eq!(set.len(), unique_count);
            prop_assert!(set.tcp.len() <= unique_count);
        }
    }
}
