// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # IP Range Management
//!
//! This module provides models and utilities for managing contiguous ranges of
//! IP addresses (both IPv4 and IPv6). It is designed for high-performance network
//! scanning, where efficient storage and quick membership tests are critical.
//!
//! Key components:
//! - [`Ipv4Range`]: specialized 8-byte container for IPv4 corridors.
//! - [`Ipv6Range`]: specialized 32-byte container for IPv6 corridors.
//! - [`IpRange`]: a unified enum for protocol-agnostic API usage.
//! - [`cidr_range`]: constructor for ranges from CIDR notation.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use thiserror::Error;

/// Errors associated with IP address range operations.
#[derive(Debug, Error, PartialEq)]
pub enum IpError {
    /// Occurs when the start address is numerically greater than the end address.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(IpAddr, IpAddr),

    /// Occurs when a CIDR prefix is outside the valid range (0-32 for v4, 0-128 for v6).
    #[error("Invalid CIDR prefix: {0}")]
    InvalidPrefix(u8),

    /// Occurs when a network calculation error arises from the underlying network library.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Occurs when an IP address string cannot be parsed.
    #[error("Failed to parse IP address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    /// Occurs when the provided string format for an IP range is recognized as invalid.
    #[error("Invalid IP range format: {0}")]
    InvalidFormat(String),

    /// Occurs when parsing an integer value for a prefix length fails.
    #[error("Invalid prefix number format: {0}")]
    PrefixParse(#[from] std::num::ParseIntError),
}

// ══════════════════════════════════════════════════════════════════════════════
// IPv4 Range
// ══════════════════════════════════════════════════════════════════════════════

/// A contiguous range of IPv4 addresses defined by a start and end point.
///
/// Both boundaries are inclusive. Stored as two `Ipv4Addr` values (8 bytes total).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Range {
    /// The inclusive starting address of the range.
    pub start_addr: Ipv4Addr,
    /// The inclusive ending address of the range.
    pub end_addr: Ipv4Addr,
}

impl Ipv4Range {
    /// Creates a new `Ipv4Range`.
    ///
    /// # Errors
    ///
    /// Returns [`IpError::InvalidRange`] if `start` is numerically greater than `end`.
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self, IpError> {
        if u32::from(start) <= u32::from(end) {
            Ok(Self {
                start_addr: start,
                end_addr: end,
            })
        } else {
            Err(IpError::InvalidRange(IpAddr::V4(start), IpAddr::V4(end)))
        }
    }

    /// Returns an iterator over every [`IpAddr`] within the range.
    ///
    /// # Performance
    ///
    /// Iterating over large ranges (e.g., /8) is fast, but collecting the results
    /// into a `Vec` will consume significant memory.
    pub fn to_iter(&self) -> impl Iterator<Item = IpAddr> {
        let start: u32 = self.start_addr.into();
        let end: u32 = self.end_addr.into();
        (start..=end).map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
    }

    /// Checks if the given [`Ipv4Addr`] falls within this range (inclusive).
    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        let start: u32 = self.start_addr.into();
        let end: u32 = self.end_addr.into();
        let ip_u32: u32 = (*ip).into();
        ip_u32 >= start && ip_u32 <= end
    }

    /// Returns the number of IP addresses in the range.
    pub fn len(&self) -> u64 {
        let s_u32: u64 = u32::from(self.start_addr) as u64;
        let e_u32: u64 = u32::from(self.end_addr) as u64;
        (e_u32 - s_u32) + 1
    }

    /// Returns true if the range contains no addresses.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// IPv6 Range
// ══════════════════════════════════════════════════════════════════════════════

/// A contiguous range of IPv6 addresses defined by a start and end point.
///
/// Both boundaries are inclusive. Stored as two `Ipv6Addr` values (32 bytes total).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Range {
    /// The inclusive starting address of the range.
    pub start_addr: Ipv6Addr,
    /// The inclusive ending address of the range.
    pub end_addr: Ipv6Addr,
}

impl Ipv6Range {
    /// Creates a new `Ipv6Range`.
    ///
    /// # Errors
    ///
    /// Returns [`IpError::InvalidRange`] if `start` is numerically greater than `end`.
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Result<Self, IpError> {
        if u128::from(start) <= u128::from(end) {
            Ok(Self {
                start_addr: start,
                end_addr: end,
            })
        } else {
            Err(IpError::InvalidRange(IpAddr::V6(start), IpAddr::V6(end)))
        }
    }

    /// Returns an iterator over every [`IpAddr`] within the range.
    ///
    /// # Warning
    ///
    /// IPv6 ranges can be astronomically large. Iterating over a typical CIDR (like a /64)
    /// will take millions of years. This method is provided for small, manually
    /// defined ranges.
    pub fn to_iter(&self) -> impl Iterator<Item = IpAddr> {
        let start: u128 = self.start_addr.into();
        let end: u128 = self.end_addr.into();
        (start..=end).map(|ip| IpAddr::V6(Ipv6Addr::from(ip)))
    }

    /// Checks if the given [`Ipv6Addr`] falls within this range (inclusive).
    pub fn contains(&self, ip: &Ipv6Addr) -> bool {
        let start: u128 = self.start_addr.into();
        let end: u128 = self.end_addr.into();
        let ip_u128: u128 = (*ip).into();
        ip_u128 >= start && ip_u128 <= end
    }

    /// Returns the number of IP addresses in the range.
    pub fn len(&self) -> u128 {
        let s_u128: u128 = u128::from(self.start_addr);
        let e_u128: u128 = u128::from(self.end_addr);
        (e_u128 - s_u128) + 1
    }

    /// Returns true if the range contains no addresses.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Unified IpRange API
// ══════════════════════════════════════════════════════════════════════════════

/// A unified representation of either an IPv4 or IPv6 range.
///
/// This enum acts as the primary entry point for parsing ranges from user input
/// via [`FromStr`] or for library consumers who want protocol-agnostic logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpRange {
    /// An IPv4 address range.
    V4(Ipv4Range),
    /// An IPv6 address range.
    V6(Ipv6Range),
}

impl IpRange {
    /// Returns the start address of the range as an [`IpAddr`].
    pub fn start_addr(&self) -> IpAddr {
        match self {
            IpRange::V4(r) => IpAddr::V4(r.start_addr),
            IpRange::V6(r) => IpAddr::V6(r.start_addr),
        }
    }

    /// Returns the end address of the range as an [`IpAddr`].
    pub fn end_addr(&self) -> IpAddr {
        match self {
            IpRange::V4(r) => IpAddr::V4(r.end_addr),
            IpRange::V6(r) => IpAddr::V6(r.end_addr),
        }
    }

    /// Checks if the given [`IpAddr`] falls within this range.
    ///
    /// Returns `false` if the protocol versions do not match (e.g., checking
    /// if a V6 address is in a V4 range).
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpRange::V4(r), IpAddr::V4(ip)) => r.contains(ip),
            (IpRange::V6(r), IpAddr::V6(ip)) => r.contains(ip),
            _ => false,
        }
    }

    /// Returns the total number of IP addresses in the range.
    pub fn len(&self) -> u128 {
        match self {
            IpRange::V4(r) => r.len() as u128,
            IpRange::V6(r) => r.len(),
        }
    }

    /// Returns true if the range contains no addresses.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FromStr for IpRange {
    type Err = IpError;

    /// Parses an IP range from a string.
    ///
    /// Supports:
    /// - CIDR notation: `192.168.1.0/24`, `2001:db8::/32`
    /// - Hyphenated ranges: `10.0.0.1-10.0.0.5`, `::1-::f`
    /// - Single IPs: `1.1.1.1`, `::1`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // Handle CIDR
        if let Some(pos) = s.find('/') {
            let ip = s[..pos].parse::<IpAddr>()?;
            let prefix = s[pos + 1..].parse::<u8>()?;
            return cidr_range(ip, prefix);
        }

        // Handle hyphenated range
        if let Some(pos) = s.find('-') {
            let start_str = s[..pos].trim();
            let end_str = s[pos + 1..].trim();

            if let Ok(start) = start_str.parse::<Ipv4Addr>() {
                let end = end_str.parse::<Ipv4Addr>()?;
                return Ok(IpRange::V4(Ipv4Range::new(start, end)?));
            } else if let Ok(start) = start_str.parse::<Ipv6Addr>() {
                let end = end_str.parse::<Ipv6Addr>()?;
                return Ok(IpRange::V6(Ipv6Range::new(start, end)?));
            }
            return Err(IpError::InvalidFormat(s.to_string()));
        }

        // Handle single IP
        let ip = s.parse::<IpAddr>()?;
        match ip {
            IpAddr::V4(v4) => Ok(IpRange::V4(Ipv4Range::new(v4, v4).unwrap())),
            IpAddr::V6(v6) => Ok(IpRange::V6(Ipv6Range::new(v6, v6).unwrap())),
        }
    }
}

/// Constructs an [`IpRange`] from an IP address and a CIDR prefix length.
///
/// # Examples
///
/// ```
/// use zond_common::models::ip::range::{cidr_range, IpRange};
/// use std::net::IpAddr;
///
/// let range = cidr_range("192.168.1.5".parse().unwrap(), 24).unwrap();
/// assert_eq!(range.len(), 256);
/// ```
pub fn cidr_range(ip: IpAddr, prefix: u8) -> Result<IpRange, IpError> {
    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err(IpError::InvalidPrefix(prefix));
            }

            let ip_u32 = u32::from(v4);
            let mask = if prefix == 0 {
                0
            } else {
                !u32::MAX.checked_shr(prefix as u32).unwrap_or(0)
            };

            let network = ip_u32 & mask;
            let broadcast = ip_u32 | !mask;

            Ok(IpRange::V4(
                Ipv4Range::new(Ipv4Addr::from(network), Ipv4Addr::from(broadcast)).unwrap(),
            ))
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return Err(IpError::InvalidPrefix(prefix));
            }

            let ip_u128 = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                !u128::MAX.checked_shr(prefix as u32).unwrap_or(0)
            };

            let network = ip_u128 & mask;
            let broadcast = ip_u128 | !mask;

            Ok(IpRange::V6(
                Ipv6Range::new(Ipv6Addr::from(network), Ipv6Addr::from(broadcast)).unwrap(),
            ))
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

    // --- IPv4 Specific Tests ---

    #[test]
    fn new_valid_v4() {
        let start = Ipv4Addr::new(192, 168, 1, 1);
        let end = Ipv4Addr::new(192, 168, 1, 10);
        let range = Ipv4Range::new(start, end).unwrap();
        assert_eq!(range.start_addr, start);
        assert_eq!(range.end_addr, end);
    }

    #[test]
    fn len_calculations_v4() {
        let cases = vec![
            (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 0), 1),
            (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255), 256),
            (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 10), 11),
        ];

        for (start, end, expected_len) in cases {
            let range = Ipv4Range::new(start, end).unwrap();
            assert_eq!(range.len(), expected_len);
        }
    }

    #[test]
    fn contains_logic_v4() {
        let range = Ipv4Range::new(Ipv4Addr::new(172, 16, 0, 10), Ipv4Addr::new(172, 16, 0, 20)).unwrap();
        assert!(range.contains(&Ipv4Addr::new(172, 16, 0, 10)));
        assert!(range.contains(&Ipv4Addr::new(172, 16, 0, 15)));
        assert!(range.contains(&Ipv4Addr::new(172, 16, 0, 20)));
        assert!(!range.contains(&Ipv4Addr::new(172, 16, 0, 9)));
        assert!(!range.contains(&Ipv4Addr::new(172, 16, 0, 21)));
    }

    #[test]
    fn iteration_values_v4() {
        let range = Ipv4Range::new(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 1, 1, 3)).unwrap();
        let ips: Vec<IpAddr> = range.to_iter().collect();
        assert_eq!(ips, vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3)),
        ]);
    }

    #[test]
    fn max_u32_range_boundaries() {
        let start = Ipv4Addr::new(255, 255, 255, 254);
        let end = Ipv4Addr::new(255, 255, 255, 255);
        let range = Ipv4Range::new(start, end).unwrap();
        assert_eq!(range.len(), 2);
    }

    // --- IPv6 Specific Tests ---

    #[test]
    fn ipv6_range_basics() {
        let start = Ipv6Addr::from(100);
        let end = Ipv6Addr::from(200);
        let range = Ipv6Range::new(start, end).unwrap();
        assert_eq!(range.len(), 101);
        assert!(range.contains(&Ipv6Addr::from(150)));
        assert!(!range.contains(&Ipv6Addr::from(201)));
    }

    #[test]
    fn ipv6_large_len() {
        let range = cidr_range(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 64).unwrap();
        assert_eq!(range.len(), 1u128 << 64);
    }

    #[test]
    fn iteration_ipv6_small() {
        let range = Ipv6Range::new(Ipv6Addr::from(1), Ipv6Addr::from(3)).unwrap();
        let ips: Vec<_> = range.to_iter().collect();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], IpAddr::V6(Ipv6Addr::from(1)));
    }

    // --- Parsing & Global Tests ---

    #[test]
    fn from_str_comprehensive() {
        assert_eq!("10.0.0.0/24".parse::<IpRange>().unwrap().len(), 256);
        assert_eq!("192.168.1.0/24".parse::<IpRange>().unwrap().len(), 256);
        assert_eq!("::1/120".parse::<IpRange>().unwrap().len(), 256);
        assert_eq!("1.1.1.1-1.1.1.5".parse::<IpRange>().unwrap().len(), 5);
        assert_eq!("8.8.8.8".parse::<IpRange>().unwrap().len(), 1);
    }

    #[test]
    fn invalid_range_order() {
        let v4_err = Ipv4Range::new(Ipv4Addr::new(1, 1, 1, 2), Ipv4Addr::new(1, 1, 1, 1));
        assert!(matches!(v4_err, Err(IpError::InvalidRange(_, _))));

        let v6_err = Ipv6Range::new(Ipv6Addr::from(2), Ipv6Addr::from(1));
        assert!(matches!(v6_err, Err(IpError::InvalidRange(_, _))));
    }

    #[test]
    fn error_formatting() {
        let prefix_err = IpError::InvalidPrefix(40);
        assert_eq!(format!("{prefix_err}"), "Invalid CIDR prefix: 40");

        let range_err = IpError::InvalidRange(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        );
        assert!(format!("{range_err}").contains("is greater than"));
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

    fn any_ipv4_range() -> impl Strategy<Value = Ipv4Range> {
        (any_ipv4(), 0..5000u32).prop_map(|(start, len)| {
            let start_u32 = u32::from(start);
            let end_u32 = start_u32.saturating_add(len);
            Ipv4Range::new(start, Ipv4Addr::from(end_u32)).unwrap()
        })
    }

    fn any_ipv6_range() -> impl Strategy<Value = Ipv6Range> {
        (any_ipv6(), 0..5000u128).prop_map(|(start, len)| {
            let start_u128 = u128::from(start);
            let end_u128 = start_u128.saturating_add(len);
            Ipv6Range::new(start, Ipv6Addr::from(end_u128)).unwrap()
        })
    }

    proptest::proptest! {
        #[test]
        fn ipv4_range_invariant(a in any_ipv4(), b in any_ipv4()) {
            let start = std::cmp::min(a, b);
            let end = std::cmp::max(a, b);
            let range = Ipv4Range::new(start, end).unwrap();
            prop_assert!(range.contains(&start));
            prop_assert!(range.contains(&end));
            prop_assert_eq!(range.len(), (u32::from(end) - u32::from(start)) as u64 + 1);
        }

        #[test]
        fn ipv6_range_invariant(a in any_ipv6(), b in any_ipv6()) {
            let start = std::cmp::min(a, b);
            let end = std::cmp::max(a, b);
            let range = Ipv6Range::new(start, end).unwrap();
            prop_assert!(range.contains(&start));
            prop_assert!(range.contains(&end));
            prop_assert_eq!(range.len(), (u128::from(end) - u128::from(start)) + 1);
        }

        #[test]
        fn ipv4_iterator_consistency(range in any_ipv4_range()) {
            prop_assert_eq!(range.to_iter().count() as u64, range.len());
        }

        #[test]
        fn ipv6_iterator_consistency(range in any_ipv6_range()) {
            prop_assert_eq!(range.to_iter().count() as u128, range.len());
        }

        #[test]
        fn cidr_v4_roundtrip(v4 in any_ipv4(), prefix in 1..=32u8) {
            let range = cidr_range(IpAddr::V4(v4), prefix).unwrap();
            prop_assert_eq!(range.len() as u128, 1u128 << (32 - prefix));
        }

        #[test]
        fn cidr_v6_roundtrip(v6 in any_ipv6(), prefix in 1..=128u8) {
            let range = cidr_range(IpAddr::V6(v6), prefix).unwrap();
            prop_assert_eq!(range.len(), 1u128 << (128 - prefix));
        }
    }
}
