// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # IP Address Sets
//!
//! This module provides the [`IpSet`] model, a high-performance container for managing
//! large collections of unique IP addresses.
//!
//! ## Performance Characteristics
//!
//! `IpSet` uses a **lazy normalization** strategy. Insertions are $O(1)$ amortized,
//! as they simply push to an internal buffer. The set is sorted and merged ($O(N \log N)$)
//! only when a query method is called or when [`IpSet::canonicalize`] is invoked explicitly.
//!
//! For maximum performance in multi-threaded scanning:
//! 1. Build the set using `insert`, `extend`, or `FromIterator`.
//! 2. Call [`IpSet::canonicalize`] once.
//! 3. Use thread-safe query methods like [`IpSet::contains_canonical`].

use super::range::{IpError, IpRange, Ipv4Range, Ipv6Range};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Errors that can occur when processing an [`IpSet`].
#[derive(Debug, thiserror::Error)]
pub enum IpSetError {
    /// Indicates that an invalid IP range or address was provided.
    #[error("Invalid target in set: {0}")]
    InvalidTarget(#[from] IpError),
}

// ══════════════════════════════════════════════════════════════════════════════
// IpSet core model
// ══════════════════════════════════════════════════════════════════════════════

/// A collection of unique IP addresses stored as sorted, non-overlapping ranges.
///
/// Handles automatic merging of overlapping and adjacent ranges lazily.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    v4: Vec<Ipv4Range>,
    v6: Vec<Ipv6Range>,
    v4_dirty: bool,
    v6_dirty: bool,
}

impl IpSet {
    /// Creates a new, empty `IpSet`.
    pub fn new() -> Self {
        Self::default()
    }

    // ─── Insertion API ───────────────────────────────────────────────────────

    /// Adds a single IP address to the set.
    ///
    /// This is a fast $O(1)$ operation that defers merging.
    pub fn insert(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => self.push_v4_range(Ipv4Range::new(v4, v4).unwrap()),
            IpAddr::V6(v6) => self.push_v6_range(Ipv6Range::new(v6, v6).unwrap()),
        }
    }

    /// Adds a unified IP range to the set.
    pub fn insert_range(&mut self, range: IpRange) {
        match range {
            IpRange::V4(r) => self.push_v4_range(r),
            IpRange::V6(r) => self.push_v6_range(r),
        }
    }

    /// Appends an IPv4 range without immediate merging.
    pub fn push_v4_range(&mut self, range: Ipv4Range) {
        self.v4.push(range);
        self.v4_dirty = true;
    }

    /// Appends an IPv6 range without immediate merging.
    pub fn push_v6_range(&mut self, range: Ipv6Range) {
        self.v6.push(range);
        self.v6_dirty = true;
    }

    /// Manually triggers sorting and merging of all internal ranges.
    ///
    /// Call this after bulk insertions to prepare the set for high-performance
    /// read-only queries or multi-threaded scanning.
    pub fn canonicalize(&mut self) {
        if self.v4_dirty {
            if !self.v4.is_empty() {
                self.merge_v4();
            }
            self.v4_dirty = false;
        }
        if self.v6_dirty {
            if !self.v6.is_empty() {
                self.merge_v6();
            }
            self.v6_dirty = false;
        }
    }

    fn merge_v4(&mut self) {
        self.v4.sort_by_key(|r| r.start_addr);
        let mut merged: Vec<Ipv4Range> = Vec::with_capacity(self.v4.len());
        let mut current = self.v4[0];

        for next in self.v4.drain(1..) {
            let curr_end = u32::from(current.end_addr);
            let next_start = u32::from(next.start_addr);

            if next_start <= curr_end.saturating_add(1) {
                if next.end_addr > current.end_addr {
                    current.end_addr = next.end_addr;
                }
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        self.v4 = merged;
    }

    fn merge_v6(&mut self) {
        self.v6.sort_by_key(|r| r.start_addr);
        let mut merged: Vec<Ipv6Range> = Vec::with_capacity(self.v6.len());
        let mut current = self.v6[0];

        for next in self.v6.drain(1..) {
            let curr_end = u128::from(current.end_addr);
            let next_start = u128::from(next.start_addr);

            if next_start <= curr_end.saturating_add(1) {
                if next.end_addr > current.end_addr {
                    current.end_addr = next.end_addr;
                }
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        self.v6 = merged;
    }

    // ─── Query API (Lazy) ────────────────────────────────────────────────────

    /// Checks if the set contains the given IP address. Performs lazy merging if needed.
    pub fn contains(&mut self, ip: &IpAddr) -> bool {
        self.canonicalize();
        self.contains_canonical(ip)
    }

    /// Returns the total count of unique IP addresses. Performs lazy merging if needed.
    pub fn len(&mut self) -> u128 {
        self.canonicalize();
        self.len_canonical()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Returns an iterator over every individual IP address. Performs lazy merging if needed.
    pub fn iter(&mut self) -> impl Iterator<Item = IpAddr> + '_ {
        self.canonicalize();
        self.v4.iter().flat_map(|range| range.to_iter()).chain(
            self.v6.iter().flat_map(|range| range.to_iter())
        )
    }

    // ─── Query API (Read-Only / Sync) ────────────────────────────────────────

    /// A high-performance, thread-safe version of `contains`.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if the set has pending unmerged ranges.
    pub fn contains_canonical(&self, ip: &IpAddr) -> bool {
        debug_assert!(!self.v4_dirty && !self.v6_dirty, "IpSet must be canonicalized before calling contains_canonical");
        match ip {
            IpAddr::V4(v4) => {
                let target = u32::from(*v4);
                self.v4.binary_search_by(|range| {
                        let start = u32::from(range.start_addr);
                        let end = u32::from(range.end_addr);
                        if target < start { std::cmp::Ordering::Greater }
                        else if target > end { std::cmp::Ordering::Less }
                        else { std::cmp::Ordering::Equal }
                    }).is_ok()
            }
            IpAddr::V6(v6) => {
                let target = u128::from(*v6);
                self.v6.binary_search_by(|range| {
                        let start = u128::from(range.start_addr);
                        let end = u128::from(range.end_addr);
                        if target < start { std::cmp::Ordering::Greater }
                        else if target > end { std::cmp::Ordering::Less }
                        else { std::cmp::Ordering::Equal }
                    }).is_ok()
            }
        }
    }

    /// A thread-safe version of `len`.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if the set has pending unmerged ranges.
    pub fn len_canonical(&self) -> u128 {
        debug_assert!(!self.v4_dirty && !self.v6_dirty, "IpSet must be canonicalized before calling len_canonical");
        let v4_len: u128 = self.v4.iter().map(|r| r.len() as u128).sum();
        let v6_len: u128 = self.v6.iter().map(|r| r.len()).sum();
        v4_len + v6_len
    }

    /// Returns the underlying IPv4 ranges. Performs lazy merging if needed.
    pub fn v4(&mut self) -> &[Ipv4Range] {
        self.canonicalize();
        &self.v4
    }

    /// Returns the underlying IPv6 ranges. Performs lazy merging if needed.
    pub fn v6(&mut self) -> &[Ipv6Range] {
        self.canonicalize();
        &self.v6
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Conversion Traits
// ══════════════════════════════════════════════════════════════════════════════

impl IntoIterator for IpSet {
    type Item = IpAddr;
    type IntoIter = Box<dyn Iterator<Item = IpAddr>>;

    /// Consumes the `IpSet` and returns an iterator over its individual IP addresses.
    fn into_iter(mut self) -> Self::IntoIter {
        self.canonicalize();
        let v4_iter = self.v4.into_iter().flat_map(|range| {
            let start: u32 = range.start_addr.into();
            let end: u32 = range.end_addr.into();
            (start..=end).map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
        });

        let v6_iter = self.v6.into_iter().flat_map(|range| {
            let start: u128 = range.start_addr.into();
            let end: u128 = range.end_addr.into();
            (start..=end).map(|ip| IpAddr::V6(Ipv6Addr::from(ip)))
        });

        Box::new(v4_iter.chain(v6_iter))
    }
}

impl Extend<IpAddr> for IpSet {
    fn extend<T: IntoIterator<Item = IpAddr>>(&mut self, iter: T) {
        for ip in iter {
            match ip {
                IpAddr::V4(v4) => self.v4.push(Ipv4Range::new(v4, v4).unwrap()),
                IpAddr::V6(v6) => self.v6.push(Ipv6Range::new(v6, v6).unwrap()),
            }
        }
        self.v4_dirty = true;
        self.v6_dirty = true;
    }
}

impl FromIterator<IpAddr> for IpSet {
    fn from_iter<I: IntoIterator<Item = IpAddr>>(iter: I) -> Self {
        let mut set = IpSet::new();
        set.extend(iter);
        set.canonicalize();
        set
    }
}

impl FromIterator<IpRange> for IpSet {
    fn from_iter<I: IntoIterator<Item = IpRange>>(iter: I) -> Self {
        let mut set = IpSet::new();
        for range in iter {
            match range {
                IpRange::V4(r) => set.v4.push(r),
                IpRange::V6(r) => set.v6.push(r),
            }
        }
        set.v4_dirty = true;
        set.v6_dirty = true;
        set.canonicalize();
        set
    }
}

impl FromIterator<IpSet> for IpSet {
    fn from_iter<I: IntoIterator<Item = IpSet>>(iter: I) -> Self {
        let mut master = IpSet::new();
        for set in iter {
            master.v4.extend(set.v4);
            master.v6.extend(set.v6);
        }
        master.v4_dirty = true;
        master.v6_dirty = true;
        master.canonicalize();
        master
    }
}

impl From<IpAddr> for IpSet {
    fn from(ip: IpAddr) -> Self {
        let mut set = Self::new();
        set.insert(ip);
        set
    }
}

impl From<IpRange> for IpSet {
    fn from(range: IpRange) -> Self {
        let mut set = Self::new();
        set.insert_range(range);
        set
    }
}

impl TryFrom<&str> for IpSet {
    type Error = IpSetError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut set = IpSet::new();
        for part in value.split([',', ' ']).filter(|part| !part.trim().is_empty()) {
            let range = part.parse::<IpRange>()?;
            set.insert_range(range);
        }
        set.canonicalize();
        Ok(set)
    }
}

impl FromStr for IpSet {
    type Err = IpSetError;
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

    #[test]
    fn lazy_merging_v4() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        set.insert(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)));
        
        // Before canonicalization, they stay as individual pushes
        assert_eq!(set.v4.len(), 2);
        assert!(set.v4_dirty);
        
        // Query triggers merge
        assert_eq!(set.len(), 2);
        assert!(!set.v4_dirty);
        assert_eq!(set.v4.len(), 1);
    }

    #[test]
    fn set_battle_test_overlaps() {
        let mut set = IpSet::new();
        // Insert: [10-20]
        set.insert_range("10.0.0.10-10.0.0.20".parse().unwrap());
        // Insert: [5-15] (overlap start)
        set.insert_range("10.0.0.5-10.0.0.15".parse().unwrap());
        // Insert: [15-25] (overlap end)
        set.insert_range("10.0.0.15-10.0.0.25".parse().unwrap());
        // Insert: [30-40] (disjoint)
        set.insert_range("10.0.0.30-10.0.0.40".parse().unwrap());
        // Insert: [0-50] (subsume all)
        set.insert_range("10.0.0.0-10.0.0.50".parse().unwrap());
        
        assert_eq!(set.len(), 51);
        assert_eq!(set.v4().len(), 1);
    }

    #[test]
    fn set_ipv6_adjacency_boundary() {
        let mut set = IpSet::new();
        // ::f...f (max)
        let max_v6 = Ipv6Addr::from(u128::MAX);
        let max_minus_1 = Ipv6Addr::from(u128::MAX - 1);
        
        set.insert(IpAddr::V6(max_minus_1));
        set.insert(IpAddr::V6(max_v6));
        
        assert_eq!(set.len(), 2);
        assert_eq!(set.v6().len(), 1);
    }

    #[test]
    fn iteration_is_lazy_safe() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::from(1)));
        set.insert(IpAddr::V4(Ipv4Addr::from(2)));
        
        // .iter() should trigger canonicalization
        let ips: Vec<IpAddr> = set.iter().collect();
        assert_eq!(ips.len(), 2);
        assert!(!set.v4_dirty);
    }

    #[test]
    fn empty_set_canonical_is_fine() {
        let mut set = IpSet::new();
        set.canonicalize();
        assert_eq!(set.len_canonical(), 0);
        assert!(set.v4().is_empty());
    }

    #[test]
    fn from_str_mixed_advanced() {
        let mut set = IpSet::from_str("1.1.1.1/32, 1.1.1.1, ::1-::1, 10.0.0.1-10.0.0.2").unwrap();
        // 1.1.1.1 (v4) + ::1 (v6) + 10.0.0.1, 10.0.0.2 (v4)
        assert_eq!(set.len(), 4); 
    }

    #[test]
    fn bulk_extend_efficiency() {
        let mut set = IpSet::new();
        let ips = (0..100).map(|i| IpAddr::V4(Ipv4Addr::from(i)));
        set.extend(ips);
        
        assert_eq!(set.v4.len(), 100);
        set.canonicalize();
        assert_eq!(set.v4.len(), 1);
        assert_eq!(set.len(), 100);
    }

    #[test]
    fn canonical_queries_panics_in_debug() {
        #[cfg(debug_assertions)]
        {
            let set = IpSet::from_iter(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
            // from_iter already canonicalizes
            assert!(!set.v4_dirty);
            assert!(set.contains_canonical(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        }
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn any_ipv4() -> impl Strategy<Value = Ipv4Addr> {
        proptest::prelude::any::<u32>().prop_map(Ipv4Addr::from)
    }

    fn any_ipv6() -> impl Strategy<Value = Ipv6Addr> {
        proptest::prelude::any::<u128>().prop_map(Ipv6Addr::from)
    }

    proptest::proptest! {
        #[test]
        fn v4_membership_invariant(ips in proptest::collection::vec(any_ipv4(), 1..50)) {
            let mut set = IpSet::new();
            for &ip in &ips {
                set.insert(IpAddr::V4(ip));
            }
            for ip in ips {
                prop_assert!(set.contains(&IpAddr::V4(ip)));
            }
        }

        #[test]
        fn v6_membership_invariant(ips in proptest::collection::vec(any_ipv6(), 1..50)) {
            let mut set = IpSet::new();
            for &ip in &ips {
                set.insert(IpAddr::V6(ip));
            }
            for ip in ips {
                prop_assert!(set.contains(&IpAddr::V6(ip)));
            }
        }

        #[test]
        fn order_independence_mixed(
            ips in proptest::collection::vec(
                prop_oneof![
                    any_ipv4().prop_map(IpAddr::V4),
                    any_ipv6().prop_map(IpAddr::V6),
                ],
                0..50
            )
        ) {
            let mut set1 = IpSet::new();
            let mut set2 = IpSet::new();

            for &ip in &ips { set1.insert(ip); }
            let mut ips_rev = ips.clone();
            ips_rev.reverse();
            for &ip in &ips_rev { set2.insert(ip); }

            set1.canonicalize();
            set2.canonicalize();
            prop_assert_eq!(set1, set2);
        }
    }
}
