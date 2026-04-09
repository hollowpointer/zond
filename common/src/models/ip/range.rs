// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! IP range management and CIDR calculations.
//!
//! This module provides the [`Ipv4Range`] struct, which represents a contiguous
//! block of IPv4 addresses, and utilities for generating ranges from CIDR notation.

use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

/// Errors associated with IP address range operations.
#[derive(Debug, Error, PartialEq)]
pub enum IpError {
    /// Occurs when the start address is numerically greater than the end address.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(Ipv4Addr, Ipv4Addr),

    /// Occurs when a CIDR prefix is outside the valid range (0-32 for IPv4).
    #[error("Invalid CIDR prefix: {0}")]
    InvalidPrefix(u8),

    /// Wrapper for underlying network library errors.
    #[error("Network error: {0}")]
    NetworkError(String),
}

/// A contiguous range of IPv4 addresses defined by a start and end point.
///
/// Both boundaries are inclusive.
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
            Err(IpError::InvalidRange(start, end))
        }
    }

    /// Returns an iterator over every [`IpAddr`] within the range.
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
    ///
    /// Note: A range where start == end has a length of 1.
    pub fn len(&self) -> u32 {
        let s_u32: u32 = u32::from(self.start_addr);
        let e_u32: u32 = u32::from(self.end_addr);

        // Since new() enforces e_u32 >= s_u32, this is safe from underflow.
        (e_u32 - s_u32) + 1
    }

    /// Returns true if the range contains no addresses.
    ///
    /// Given the constraints of [`Ipv4Range::new`], this will effectively always be false
    /// for a successfully constructed range.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Creates an [`Ipv4Range`] from an IP address and a CIDR prefix.
///
/// # Errors
///
/// Returns [`IpError::InvalidPrefix`] if the prefix is greater than 32, or
/// [`IpError::NetworkError`] if the underlying CIDR calculation fails.
pub fn cidr_range(ip: Ipv4Addr, prefix: u8) -> Result<Ipv4Range, IpError> {
    if prefix > 32 {
        return Err(IpError::InvalidPrefix(prefix));
    }

    let network = pnet::ipnetwork::Ipv4Network::new(ip, prefix)
        .map_err(|e| IpError::NetworkError(e.to_string()))?;

    let start = network.network();
    let end = network.broadcast();

    // This is safe to unwrap because pnet ensures broadcast >= network.
    Ok(Ipv4Range::new(start, end).unwrap())
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
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_new_valid() {
        let start = Ipv4Addr::new(192, 168, 1, 1);
        let end = Ipv4Addr::new(192, 168, 1, 10);
        let range = Ipv4Range::new(start, end).unwrap();

        assert_eq!(range.start_addr, start);
        assert_eq!(range.end_addr, end);
    }

    #[test]
    fn test_new_invalid_order() {
        let start = Ipv4Addr::new(10, 0, 0, 2);
        let end = Ipv4Addr::new(10, 0, 0, 1);
        let result = Ipv4Range::new(start, end);

        assert!(matches!(result, Err(IpError::InvalidRange(_, _))));
        if let Err(IpError::InvalidRange(s, e)) = result {
            assert_eq!(s, start);
            assert_eq!(e, end);
        }
    }

    #[test]
    fn test_new_identical_addr() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let range = Ipv4Range::new(ip, ip).unwrap();
        assert_eq!(range.len(), 1);
        assert!(!range.is_empty());
    }

    #[test]
    fn test_len_calculations() {
        let cases = vec![
            (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 0), 1),
            (
                Ipv4Addr::new(10, 0, 0, 0),
                Ipv4Addr::new(10, 0, 0, 255),
                256,
            ),
            (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 10), 11),
        ];

        for (start, end, expected_len) in cases {
            let range = Ipv4Range::new(start, end).unwrap();
            assert_eq!(range.len(), expected_len);
        }
    }

    #[test]
    fn test_contains_logic() {
        let range =
            Ipv4Range::new(Ipv4Addr::new(172, 16, 0, 10), Ipv4Addr::new(172, 16, 0, 20)).unwrap();

        assert!(range.contains(&Ipv4Addr::new(172, 16, 0, 10)));
        assert!(range.contains(&Ipv4Addr::new(172, 16, 0, 15)));
        assert!(range.contains(&Ipv4Addr::new(172, 16, 0, 20)));

        assert!(!range.contains(&Ipv4Addr::new(172, 16, 0, 9)));
        assert!(!range.contains(&Ipv4Addr::new(172, 16, 0, 21)));
        assert!(!range.contains(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_iteration_values() {
        let range = Ipv4Range::new(
            Ipv4Addr::new(192, 168, 1, 254),
            Ipv4Addr::new(192, 168, 2, 1),
        )
        .unwrap();
        let results: Vec<IpAddr> = range.to_iter().collect();

        let expected = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 0)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)),
        ];

        assert_eq!(results, expected);
        assert_eq!(results.len() as u32, range.len());
    }

    #[test]
    fn test_cidr_conversions() {
        // Standard /24
        let r24 = cidr_range(Ipv4Addr::new(192, 168, 5, 123), 24).unwrap();
        assert_eq!(r24.start_addr, Ipv4Addr::new(192, 168, 5, 0));
        assert_eq!(r24.end_addr, Ipv4Addr::new(192, 168, 5, 255));
        assert_eq!(r24.len(), 256);

        // Host /32
        let r32 = cidr_range(Ipv4Addr::new(1, 1, 1, 1), 32).unwrap();
        assert_eq!(r32.start_addr, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(r32.end_addr, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(r32.len(), 1);

        // Entire IPv4 Internet /0
        let r0 = cidr_range(Ipv4Addr::new(8, 8, 8, 8), 0).unwrap();
        assert_eq!(r0.start_addr, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(r0.end_addr, Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn test_cidr_invalid_prefix() {
        let result = cidr_range(Ipv4Addr::new(127, 0, 0, 1), 33);
        assert_eq!(result, Err(IpError::InvalidPrefix(33)));
    }

    #[test]
    fn test_max_u32_range_boundaries() {
        // Tests handling of u32::MAX boundaries without panic
        let start = Ipv4Addr::new(255, 255, 255, 254);
        let end = Ipv4Addr::new(255, 255, 255, 255);
        let range = Ipv4Range::new(start, end).unwrap();

        assert_eq!(range.len(), 2);

        let mut iter = range.to_iter();
        assert_eq!(iter.next(), Some(IpAddr::V4(start)));
        assert_eq!(iter.next(), Some(IpAddr::V4(end)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_error_formatting() {
        let err = IpError::InvalidRange(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            format!("{err}"),
            "Invalid range: start address 10.0.0.2 is greater than end address 10.0.0.1"
        );

        let prefix_err = IpError::InvalidPrefix(40);
        assert_eq!(format!("{prefix_err}"), "Invalid CIDR prefix: 40");
    }
}
