// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! A set of IPv4 addresses that automatically manages overlapping ranges.
//!
//! This module provides [`IpSet`], which ensures that all stored addresses
//! are unique and contiguous blocks are merged upon insertion.

use super::range::Ipv4Range;
use std::{net::IpAddr, str::FromStr};

/// Errors that can occur when processing an `IpSet`.
#[derive(Debug, thiserror::Error)]
pub enum IpSetError {
    /// Indicates that an invalid IP range or address was provided.
    #[error("Invalid target in set: {0}")]
    InvalidTarget(#[from] crate::models::ip::range::IpError),
}

/// A collection of IPv4 addresses stored as non-overlapping ranges.
#[derive(Debug, Clone, Default)]
pub struct IpSet {
    ranges: Vec<Ipv4Range>,
}

impl IpSet {
    /// Creates a new, empty `IpSet`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an IP address to the set.
    pub fn insert(&mut self, ip: IpAddr) {
        if let IpAddr::V4(v4) = ip {
            self.insert_range(Ipv4Range::new(v4, v4).unwrap());
        }
    }

    /// Adds a range of addresses to the set, merging any overlaps.
    pub fn insert_range(&mut self, new_range: Ipv4Range) {
        self.ranges.push(new_range);

        if self.ranges.len() < 2 {
            return;
        }

        self.ranges.sort_by_key(|r| r.start_addr);

        let mut merged: Vec<Ipv4Range> = Vec::with_capacity(self.ranges.len());
        let mut current = self.ranges[0];

        for next in self.ranges.drain(1..) {
            let curr_end = u32::from(current.end_addr);
            let next_start = u32::from(next.start_addr);

            if next_start <= curr_end.saturating_add(1) {
                let next_end = u32::from(next.end_addr);
                if next_end > curr_end {
                    current.end_addr = next.end_addr;
                }
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        self.ranges = merged;
    }

    /// Checks if the set contains the given IP address.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let IpAddr::V4(v4) = ip else { return false };
        let target = u32::from(*v4);

        self.ranges
            .binary_search_by(|range| {
                let start = u32::from(range.start_addr);
                let end = u32::from(range.end_addr);

                if target < start {
                    std::cmp::Ordering::Greater
                } else if target > end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Returns the total count of unique IP addresses in the set.
    pub fn len(&self) -> u64 {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    /// Returns true if the set contains no addresses.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns the underlying ranges of the set.
    pub fn ranges(&self) -> &[Ipv4Range] {
        &self.ranges
    }

    /// Returns an iterator over every individual IP address in the set.
    pub fn iter(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.ranges.iter().flat_map(|range| range.to_iter())
    }
}

impl IntoIterator for IpSet {
    type Item = IpAddr;
    type IntoIter = std::vec::IntoIter<IpAddr>;

    /// Consumes the `IpSet` and returns an iterator over its individual IP addresses.
    fn into_iter(self) -> Self::IntoIter {
        let mut all_ips = Vec::with_capacity(self.len() as usize);
        for range in self.ranges {
            all_ips.extend(range.to_iter());
        }
        all_ips.into_iter()
    }
}

impl FromIterator<IpSet> for IpSet {
    /// Combines an iterator of `IpSet`s into a single `IpSet`.
    fn from_iter<I: IntoIterator<Item = IpSet>>(iter: I) -> Self {
        let mut master = IpSet::new();
        for set in iter {
            for range in set.ranges {
                master.insert_range(range);
            }
        }
        master
    }
}

impl From<IpAddr> for IpSet {
    /// Converts a single IP address into an IpSet.
    fn from(ip: IpAddr) -> Self {
        let mut set = Self::new();
        set.insert(ip);
        set
    }
}

impl From<Ipv4Range> for IpSet {
    /// Converts a single range into an IpSet.
    fn from(range: Ipv4Range) -> Self {
        let mut set = Self::new();
        set.insert_range(range);
        set
    }
}

impl From<Vec<Ipv4Range>> for IpSet {
    /// Creates an `IpSet` from a vector of `Ipv4Range`s, automatically sorting and merging overlaps.
    fn from(mut ranges: Vec<Ipv4Range>) -> Self {
        if ranges.is_empty() {
            return Self::default();
        }

        ranges.sort_by_key(|r| r.start_addr);
        let mut merged: Vec<Ipv4Range> = Vec::with_capacity(ranges.len());
        let mut current = ranges[0];

        for next in ranges.into_iter().skip(1) {
            let curr_end = u32::from(current.end_addr);
            let next_start = u32::from(next.start_addr);

            if next_start <= curr_end.saturating_add(1) {
                let next_end = u32::from(next.end_addr);
                if next_end > curr_end {
                    current.end_addr = next.end_addr;
                }
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        Self { ranges: merged }
    }
}

impl TryFrom<&str> for IpSet {
    type Error = IpSetError;

    /// Attempts to parse a comma- or space-separated list of IP ranges or CIDRs.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let ranges = value
            .split([',', ' '])
            .filter(|part| !part.trim().is_empty())
            .map(|part| part.parse::<Ipv4Range>())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(IpSet::from(ranges))
    }
}

impl TryFrom<String> for IpSet {
    type Error = IpSetError;

    /// Attempts to parse a comma- or space-separated string of IP ranges or CIDRs.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl FromStr for IpSet {
    type Err = IpSetError;

    /// Parses a string representation (comma- or space-separated list) into an `IpSet`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
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
    use std::net::Ipv4Addr;

    #[test]
    fn insert_single_ips() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        set.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));

        // Should merge into a single range [1, 2]
        assert_eq!(set.ranges.len(), 1);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn insert_range() {
        let mut set = IpSet::new();
        let range =
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 10)).unwrap();
        set.insert_range(range);

        assert_eq!(set.len(), 10);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    }

    #[test]
    fn merge_overlapping_ranges() {
        let mut set = IpSet::new();
        // 10.0.0.1 - 10.0.0.10
        set.insert_range(
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 10)).unwrap(),
        );
        // 10.0.0.5 - 10.0.0.15
        set.insert_range(
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 15)).unwrap(),
        );

        assert_eq!(set.ranges.len(), 1);
        assert_eq!(set.len(), 15);
        assert_eq!(set.ranges[0].end_addr, Ipv4Addr::new(10, 0, 0, 15));
    }

    #[test]
    fn merge_adjacent_ranges() {
        let mut set = IpSet::new();
        // 10.0.0.1 - 10.0.0.10
        set.insert_range(
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 10)).unwrap(),
        );
        // 10.0.0.11 - 10.0.0.20
        set.insert_range(
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 11), Ipv4Addr::new(10, 0, 0, 20)).unwrap(),
        );

        assert_eq!(set.ranges.len(), 1);
        assert_eq!(set.len(), 20);
    }

    #[test]
    fn disjoint_ranges() {
        let mut set = IpSet::new();
        set.insert_range(
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5)).unwrap(),
        );
        set.insert_range(
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 10), Ipv4Addr::new(10, 0, 0, 15)).unwrap(),
        );

        assert_eq!(set.ranges.len(), 2);
        assert_eq!(set.len(), 11);
    }

    #[test]
    fn contains_binary_search() {
        let mut set = IpSet::new();
        set.insert_range(
            Ipv4Range::new(Ipv4Addr::new(172, 16, 0, 1), Ipv4Addr::new(172, 16, 0, 255)).unwrap(),
        );
        set.insert_range(
            Ipv4Range::new(
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 10),
            )
            .unwrap(),
        );

        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 100))));
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));
        assert!(!set.contains(&IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1))));
        assert!(!set.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn iteration_order() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        set.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let ips: Vec<IpAddr> = set.iter().collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
            ]
        );
    }

    #[test]
    fn from_iterator() {
        let set1 = {
            let mut s = IpSet::new();
            s.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
            s
        };
        let set2 = {
            let mut s = IpSet::new();
            s.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
            s
        };

        let master: IpSet = vec![set1, set2].into_iter().collect();
        assert_eq!(master.len(), 2);
        assert_eq!(master.ranges.len(), 1);
    }

    #[test]
    fn is_empty() {
        let mut set = IpSet::new();
        assert!(set.is_empty());
        set.insert(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!set.is_empty());
    }

    #[test]
    fn max_u32_range_boundaries() {
        let mut set = IpSet::new();
        set.insert_range(
            Ipv4Range::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0)).unwrap(),
        );
        set.insert_range(
            Ipv4Range::new(
                Ipv4Addr::new(255, 255, 255, 255),
                Ipv4Addr::new(255, 255, 255, 255),
            )
            .unwrap(),
        );

        assert_eq!(set.ranges.len(), 2);

        set.insert_range(
            Ipv4Range::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 255)).unwrap(),
        );
        assert_eq!(set.ranges.len(), 1);
        assert_eq!(set.len(), 4294967296);
    }

    #[test]
    fn parse_from_str() {
        let set: IpSet = "192.168.1.1/32, 10.0.0.1-10.0.0.5".parse().unwrap();
        assert_eq!(set.ranges.len(), 2);
        assert_eq!(set.len(), 6);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))));
    }

    #[test]
    fn try_from_string() {
        let s = String::from("172.16.0.0/24");
        let set = IpSet::try_from(s).unwrap();
        assert_eq!(set.len(), 256);
    }

    #[test]
    fn from_vec_ranges() {
        let r1 = Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5)).unwrap();
        let r2 = Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 8)).unwrap();
        let set = IpSet::from(vec![r1, r2]);
        assert_eq!(set.ranges.len(), 1);
        assert_eq!(set.len(), 8);
    }
}
