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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicBool;
use thiserror::Error;

use crate::models::ip::range::{IpError, Ipv4Range, IpRange};
use crate::models::ip::set::IpSet;
use crate::success;

/// Global indicator set to `true` if a "lan" resolution was successfully performed.
pub static IS_LAN_SCAN: AtomicBool = AtomicBool::new(false);

pub enum Keyword {
    Lan,
    Vpn,
}

/// Errors encountered during the parsing or resolution of IP-related strings.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpParseError {
    /// The provided CIDR prefix is outside the valid IPv4 range of 0-32.
    #[error("Invalid CIDR prefix: {0} (must be 0-32)")]
    InvalidPrefix(u8),

    /// The start address of a range is numerically higher than the end address.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(IpAddr, IpAddr),

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
/// use zond_common::parse::ip::{to_set, Keyword};
/// use zond_common::models::ip::set::IpSet;
///
/// let targets = vec!["192.168.1.0/24", "10.0.0.1, 10.0.0.5-10"];
/// let noop_resolver = |_: Keyword, _: &mut IpSet| Ok(());
/// let mut set = to_set(&targets, &noop_resolver).unwrap();
///
/// // /24 (256) + single (1) + range 5-10 (6) = 263
/// assert_eq!(set.len(), 263);
/// ```
pub fn to_set<S, F>(inputs: &[S], resolve_fn: &F) -> Result<IpSet, IpParseError>
where
    S: AsRef<str>,
    F: Fn(Keyword, &mut IpSet) -> Result<(), IpParseError>,
{
    let mut set = IpSet::new();

    for input in inputs {
        let s = input.as_ref().trim();
        if s.is_empty() {
            continue;
        }

        if s.contains(',') {
            for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                parse_and_insert(part, &mut set, resolve_fn)?;
            }
        } else {
            parse_and_insert(s, &mut set, resolve_fn)?;
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
fn parse_and_insert<F>(s: &str, set: &mut IpSet, resolve_fn: F) -> Result<(), IpParseError>
where
    F: Fn(Keyword, &mut IpSet) -> Result<(), IpParseError>,
{
    if s.eq_ignore_ascii_case("lan") {
        return resolve_fn(Keyword::Lan, set);
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

/// Parses hyphenated range strings into an [`IpRange`].
fn parse_range(s: &str) -> Result<IpRange, IpParseError> {
    let (start_str, end_str) = s
        .split_once('-')
        .ok_or_else(|| IpParseError::Malformed(s.into()))?;

    let start_addr = start_str
        .parse::<IpAddr>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    match start_addr {
        IpAddr::V4(start_v4) => {
            let end_v4 = if let Ok(addr) = end_str.parse::<Ipv4Addr>() {
                addr
            } else {
                let mut octets = start_v4.octets();
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
            Ipv4Range::new(start_v4, end_v4)
                .map(IpRange::V4)
                .map_err(map_range_error)
        }
        IpAddr::V6(start_v6) => {
            let end_v6 = end_str
                .parse::<Ipv6Addr>()
                .map_err(|_| IpParseError::Malformed(s.into()))?;
            crate::models::ip::range::Ipv6Range::new(start_v6, end_v6)
                .map(IpRange::V6)
                .map_err(map_range_error)
        }
    }
}

/// Parses CIDR notation strings into an [`IpRange`].
fn parse_cidr(s: &str) -> Result<IpRange, IpParseError> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| IpParseError::Malformed(s.into()))?;

    let ip = ip_str
        .parse::<IpAddr>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    crate::models::ip::range::cidr_range(ip, prefix).map_err(map_range_error)
}

fn map_range_error(e: IpError) -> IpParseError {
    match e {
        IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
        IpError::InvalidPrefix(p) => IpParseError::InvalidPrefix(p),
        IpError::NetworkError(msg) => IpParseError::NetworkError(msg),
        _ => IpParseError::Malformed("Invalid IP range".into()),
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

    fn noop_resolver(_: Keyword, _: &mut IpSet) -> Result<(), IpParseError> {
        Ok(())
    }

    #[test]
    fn to_set_basic_single() {
        let input = vec!["192.168.1.1"];
        let mut set = to_set(&input, &noop_resolver).expect("Should parse single IP");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn to_set_comma_separated() {
        let input = vec!["10.0.0.1, 10.0.0.2, 10.0.0.5"];
        let mut set = to_set(&input, &noop_resolver).expect("Should parse comma list");
        assert_eq!(set.len(), 3);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn parse_cidr_blocks() {
        let input = vec!["172.16.0.0/24"];
        let mut set = to_set(&input, &noop_resolver).expect("Should parse CIDR");
        assert_eq!(set.len(), 256);
    }

    #[test]
    fn parse_short_range_suffix() {
        let input = vec!["192.168.1.250-2.10"];
        let mut set = to_set(&input, &noop_resolver).unwrap();
        assert_eq!(set.len(), 17);
    }

    #[test]
    fn error_invalid_cidr() {
        let input = vec!["192.168.1.1/33"];
        let result = to_set(&input, &noop_resolver);
        assert_eq!(result.unwrap_err(), IpParseError::InvalidPrefix(33));
    }

    #[test]
    fn error_invalid_range_order() {
        let input = vec!["10.0.0.10-1"];
        let result = to_set(&input, &noop_resolver);
        assert!(matches!(result, Err(IpParseError::InvalidRange(_, _))));
    }

    #[test]
    fn empty_input_error() {
        let input: Vec<&str> = vec!["", " "];
        let result = to_set(&input, &noop_resolver);
        assert_eq!(result.unwrap_err(), IpParseError::EmptySet);
    }

    #[test]
    fn lan_keyword_resolution() {
        let input = vec!["lan"];

        let mock_lan = |key: Keyword, set: &mut IpSet| match key {
            Keyword::Lan => {
                set.insert("10.0.0.1".parse().unwrap());
                Ok(())
            }
            _ => Ok(()),
        };

        let mut set = to_set(&input, &mock_lan).expect("Should resolve LAN keyword");

        assert!(set.contains(&"10.0.0.1".parse().unwrap()));
        assert_eq!(set.len(), 1);
    }
}
