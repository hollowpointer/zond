// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Network Target Parser
//!
//! This module provides the logic to resolve abstract input strings into a concrete,
//! deduplicated [`IpSet`]. It acts as the translation layer between user intent
//! (CLI arguments, configuration strings) and the underlying network models.
//!
//! ## Supported Formats
//!
//! The parser recognizes several distinct IPv4 formats:
//!
//! * **Single IP**: Standard dotted-decimal notation (e.g., `127.0.0.1`).
//! * **CIDR Block**: Network address with a prefix length (e.g., `192.168.1.0/24`).
//! * **Explicit Range**: Two full IPs separated by a hyphen (e.g., `10.0.0.1-10.0.0.50`).
//! * **Shortened Range**: An IP followed by a hyphen and a partial suffix (e.g., `10.0.0.1-50` or `192.168.1.1-2.254`).
//! * **Keywords**: Special identifiers like `lan`, which resolve dynamically based on the host's active interface.
//!
//! ## Merging Behavior
//!
//! All inputs are resolved into an [`IpSet`]. The parser ensures that overlapping
//! or adjacent inputs are merged into contiguous ranges to optimize scanning performance.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

use crate::net::interface;
use crate::models::ip::range::{IpError, Ipv4Range};
use crate::models::ip::set::IpSet;
use crate::{info, success, warn};

/// Global indicator set to `true` if a "lan" resolution was successfully performed.
pub static IS_LAN_SCAN: AtomicBool = AtomicBool::new(false);

/// Errors encountered during the parsing or resolution of IP-related strings.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpParseError {
    /// The provided CIDR prefix is outside the valid IPv4 range of 0-32.
    #[error("Invalid CIDR prefix: {0} (must be 0-32)")]
    InvalidPrefix(u8),

    /// The start address of a range is numerically higher than the end address.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(Ipv4Addr, Ipv4Addr),

    /// The input string does not match any known IP, Range, or CIDR format.
    #[error("Malformed IP or range string: '{0}'")]
    Malformed(String),

    /// Failed to retrieve local interface information for "lan" resolution.
    #[error("Could not resolve LAN interface: {0}")]
    LanError(String),

    /// Wrapper for underlying network library or calculation failures.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// The provided input resulted in zero valid IP addresses.
    #[error("Target input resulted in an empty set")]
    EmptySet,
}

/// Resolves a collection of input strings into a consolidated [`IpSet`].
///
/// Handles whitespace trimming, comma-separated lists, and individual item parsing.
///
/// # Arguments
///
/// * `inputs` - A slice of string-like objects representing scan targets.
///
/// # Errors
///
/// Returns an [`IpParseError`] if any component fails to parse or if the final set
/// is empty.
///
/// # Examples
///
/// ```
/// use zond_common::parse::ip::to_set;
///
/// let targets = vec!["192.168.1.0/24", "10.0.0.1, 10.0.0.5-10"];
/// let set = to_set(&targets).unwrap();
///
/// // /24 (256) + single (1) + range 5-10 (6) = 263
/// assert_eq!(set.len(), 263);
/// ```
pub fn to_set<S: AsRef<str>>(inputs: &[S]) -> Result<IpSet, IpParseError> {
    let mut set = IpSet::new();

    for input in inputs {
        let s = input.as_ref().trim();
        if s.is_empty() {
            continue;
        }

        if s.contains(',') {
            for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                parse_and_insert(part, &mut set)?;
            }
        } else {
            parse_and_insert(s, &mut set)?;
        }
    }

    if set.is_empty() {
        return Err(IpParseError::EmptySet);
    }

    let len = set.len();
    let suffix = if len == 1 { "" } else { "es" };
    success!("{len} IP address{suffix} resolved successfully");

    Ok(set)
}

/// Identifies the format of a single target string and inserts it into the set.
fn parse_and_insert(s: &str, set: &mut IpSet) -> Result<(), IpParseError> {
    if s.eq_ignore_ascii_case("lan") {
        return resolve_lan(set);
    }

    if s.contains('/') {
        let range = parse_cidr(s)?;
        set.insert_range(range);
        return Ok(());
    }

    if s.contains('-') {
        let range = parse_range(s)?;
        set.insert_range(range);
        return Ok(());
    }

    let ip = s
        .parse::<IpAddr>()
        .map_err(|_| IpParseError::Malformed(s.to_string()))?;
    set.insert(ip);

    Ok(())
}

/// Dynamically resolves the host's primary LAN interface into an inclusive range.
fn resolve_lan(set: &mut IpSet) -> Result<(), IpParseError> {
    let net = interface::get_lan_network()
        .map_err(|e| IpParseError::LanError(e.to_string()))?
        .ok_or_else(|| IpParseError::LanError("No active network interface found".into()))?;

    let start_u32 = u32::from(net.network()).saturating_add(1);
    let end_u32 = u32::from(net.broadcast()).saturating_sub(1);

    if start_u32 <= end_u32 {
        IS_LAN_SCAN.store(true, Ordering::Relaxed);
        let range = Ipv4Range::new(Ipv4Addr::from(start_u32), Ipv4Addr::from(end_u32)).map_err(
            |e| match e {
                IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
                _ => IpParseError::LanError("Invalid LAN range".into()),
            },
        )?;

        info!(
            verbosity = 1,
            "Resolved LAN: {} - {}", range.start_addr, range.end_addr
        );
        set.insert_range(range);
    } else {
        warn!("Small subnet; scanning full network range.");
        set.insert_range(Ipv4Range::new(net.network(), net.broadcast()).unwrap());
    }

    Ok(())
}

/// Parses hyphenated range strings into an [`Ipv4Range`].
fn parse_range(s: &str) -> Result<Ipv4Range, IpParseError> {
    let (start_str, end_str) = s
        .split_once('-')
        .ok_or_else(|| IpParseError::Malformed(s.into()))?;

    let start_addr = start_str
        .parse::<Ipv4Addr>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    let end_addr = if let Ok(addr) = end_str.parse::<Ipv4Addr>() {
        addr
    } else {
        let mut octets = start_addr.octets();
        let parts: Vec<u8> = end_str
            .split('.')
            .map(|p| p.parse::<u8>())
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| IpParseError::Malformed(s.into()))?;

        if parts.is_empty() || parts.len() > 4 {
            return Err(IpParseError::Malformed(s.into()));
        }

        let offset = 4 - parts.len();
        octets[offset..].copy_from_slice(&parts);
        Ipv4Addr::from(octets)
    };

    Ipv4Range::new(start_addr, end_addr).map_err(|e| match e {
        IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
        _ => IpParseError::Malformed("Invalid range constructor".into()),
    })
}

/// Parses CIDR notation strings into an [`Ipv4Range`].
fn parse_cidr(s: &str) -> Result<Ipv4Range, IpParseError> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| IpParseError::Malformed(s.into()))?;

    let ip = ip_str
        .parse::<Ipv4Addr>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|_| IpParseError::InvalidPrefix(0))?;

    if prefix > 32 {
        return Err(IpParseError::InvalidPrefix(prefix));
    }

    let network = pnet::ipnetwork::Ipv4Network::new(ip, prefix)
        .map_err(|e| IpParseError::NetworkError(e.to_string()))?;

    Ok(Ipv4Range::new(network.network(), network.broadcast()).unwrap())
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
    fn to_set_basic_single() {
        let input = vec!["192.168.1.1"];
        let set = to_set(&input).expect("Should parse single IP");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn to_set_comma_separated() {
        let input = vec!["10.0.0.1, 10.0.0.2, 10.0.0.5"];
        let set = to_set(&input).expect("Should parse comma list");
        assert_eq!(set.len(), 3);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn parse_cidr_blocks() {
        let input = vec!["172.16.0.0/24"];
        let set = to_set(&input).expect("Should parse CIDR");
        assert_eq!(set.len(), 256);
    }

    #[test]
    fn parse_short_range_suffix() {
        let input = vec!["192.168.1.250-2.10"];
        let set = to_set(&input).unwrap();
        assert_eq!(set.len(), 17);
    }

    #[test]
    fn error_invalid_cidr() {
        let input = vec!["192.168.1.1/33"];
        let result = to_set(&input);
        assert_eq!(result.unwrap_err(), IpParseError::InvalidPrefix(33));
    }

    #[test]
    fn error_invalid_range_order() {
        let input = vec!["10.0.0.10-1"];
        let result = to_set(&input);
        assert!(matches!(result, Err(IpParseError::InvalidRange(_, _))));
    }

    #[test]
    fn empty_input_error() {
        let input: Vec<&str> = vec!["", " "];
        let result = to_set(&input);
        assert_eq!(result.unwrap_err(), IpParseError::EmptySet);
    }
}
