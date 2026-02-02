// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Scan Target Model
//!
//! Defines the possible inputs for a network scan.
//!
//! This module handles parsing strings (IPs, ranges, CIDRs, keywords)
//! and converting them into a unified collection of IP addresses.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, ensure};

use crate::interface;
use crate::models::range::{self, IpCollection, Ipv4Range};
use crate::{info, success, warn};

/// Global flag to indicate if we are strictly scanning the LAN.
pub static IS_LAN_SCAN: AtomicBool = AtomicBool::new(false);

/// Represents a validated network target.
///
/// Simplified to only contain concrete network data.
#[derive(Clone, Debug, PartialEq)]
pub enum Target {
    /// A single host (e.g., 192.168.1.1)
    Host(IpAddr),
    /// A range of hosts (e.g., 192.168.1.0/24 or 10-20)
    Range(Ipv4Range),
}

/// The main entry point. Converts CLI arguments into an IP collection.
///
/// Handles:
/// * Comma-separated strings ("1.1.1.1, 2.2.2.2")
/// * Space-separated strings ("1.1.1.1 2.2.2.2")
/// * Keywords ("lan")
/// * CIDR and Range parsing
pub fn to_collection<S: AsRef<str>>(inputs: &[S]) -> anyhow::Result<IpCollection> {
    let mut collection = IpCollection::new();

    for input in inputs {
        let s = input.as_ref().trim();
        if s.is_empty() {
            continue;
        }

        if s.contains(',') {
            let split_inputs: Vec<&str> = s
                .split(',')
                .map(|part| part.trim())
                .filter(|part| !part.is_empty())
                .collect();

            parse_many_into(&split_inputs, &mut collection)?;
        } else {
            parse_single_into(s, &mut collection)?;
        }
    }

    ensure!(!collection.is_empty(), "No valid targets found");

    collection.compact();

    let len = collection.len();
    let unit = if len == 1 {
        " has been"
    } else {
        "es have been"
    };
    success!("{len} IP address{unit} parsed successfully");

    Ok(collection)
}

/// Helper to parse a list of strings directly into the collection
fn parse_many_into<S: AsRef<str>>(
    inputs: &[S],
    collection: &mut IpCollection,
) -> anyhow::Result<()> {
    for input in inputs {
        parse_single_into(input.as_ref(), collection)?;
    }
    Ok(())
}

/// Parses a single string and adds it to the collection.
fn parse_single_into(s: &str, collection: &mut IpCollection) -> anyhow::Result<()> {
    if s.eq_ignore_ascii_case("lan") {
        return resolve_lan(collection);
    }

    if s.eq_ignore_ascii_case("vpn") {
        bail!("VPN scan target not yet implemented");
    }

    if let Some(target) = parse_as_target(s)? {
        match target {
            Target::Host(ip) => {
                info!(verbosity = 2, "Parsed '{s}' as a single host: {ip}");
                collection.add_single(ip)
            }
            Target::Range(range) => {
                info!(
                    verbosity = 2,
                    "Parsed '{s}' as a range: {} to {} ({} hosts)",
                    range.start_addr,
                    range.end_addr,
                    range.len()
                );
                collection.add_range(range)
            }
        }
        return Ok(());
    }

    bail!("Invalid target format: '{}'", s);
}

/// Tries to parse a string into a concrete Target (Host or Range).
fn parse_as_target(s: &str) -> anyhow::Result<Option<Target>> {
    // Host?
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Some(Target::Host(ip)));
    }

    // IP Range? (Start-End)
    if let Some(range) = parse_ip_range(s)? {
        return Ok(Some(Target::Range(range)));
    }

    // CIDR? (Network/Prefix)
    if let Some(range) = parse_cidr_range(s)? {
        return Ok(Some(Target::Range(range)));
    }

    Ok(None)
}

/// Logic for the "lan" keyword.
fn resolve_lan(collection: &mut IpCollection) -> anyhow::Result<()> {
    let Some(net) = interface::get_lan_network()? else {
        bail!("Could not detect a valid LAN interface.");
    };

    let net_u32: u32 = u32::from(net.network());
    let broadcast_u32: u32 = u32::from(net.broadcast());

    // Calculates usable range (exclude network and broadcast)
    let start_u32 = net_u32.saturating_add(1);
    let end_u32 = broadcast_u32.saturating_sub(1);

    let start_ip = Ipv4Addr::from(start_u32);
    let end_ip = Ipv4Addr::from(end_u32);

    if start_u32 <= end_u32 {
        IS_LAN_SCAN.store(true, Ordering::Relaxed);
        info!(verbosity = 1, "Scanning from {start_ip} to {end_ip}");
        collection.add_range(Ipv4Range::new(start_ip, end_ip));
    } else {
        warn!("Network too small to strip broadcast, scanning full range.");
        collection.add_range(Ipv4Range::new(net.network(), net.broadcast()));
    }

    Ok(())
}

/// Parses a range string like "1.1.1.1-2.2.2.2" or "1.1.1.1-50".
fn parse_ip_range(s: &str) -> anyhow::Result<Option<Ipv4Range>> {
    let Some((start_str, end_str)) = s.split_once('-') else {
        return Ok(None);
    };

    let start_addr = start_str
        .parse::<Ipv4Addr>()
        .map_err(|e| anyhow::anyhow!("Invalid start IP in range '{start_str}': {e}"))?;

    let end_addr = parse_range_end_addr(end_str, &start_addr, s)?;

    Ok(Some(Ipv4Range::new(start_addr, end_addr)))
}

/// Helper to parse the end address of a range.
fn parse_range_end_addr(
    end_str: &str,
    start_addr: &Ipv4Addr,
    original_s: &str,
) -> anyhow::Result<Ipv4Addr> {
    if let Ok(full_addr) = end_str.parse::<Ipv4Addr>() {
        return Ok(full_addr);
    }

    // Handles abbreviated suffix (e.g. "50", "1.50")
    let mut end_octets = start_addr.octets();
    let partial_octets: Vec<u8> = end_str
        .split('.')
        .map(|octet_str| octet_str.parse::<u8>())
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| anyhow::anyhow!("Invalid end range '{end_str}': {e}"))?;

    if partial_octets.is_empty() {
        bail!("End range cannot be empty: {original_s}");
    }
    if partial_octets.len() > 4 {
        bail!("End range has too many octets: {end_str}");
    }

    // Overlays the partial octets onto the end of the start address
    let partial_len = partial_octets.len();
    let start_index = 4 - partial_len;
    end_octets[start_index..].copy_from_slice(&partial_octets);

    Ok(Ipv4Addr::from(end_octets))
}

/// Parses CIDR notation like "192.168.1.0/24".
fn parse_cidr_range(s: &str) -> anyhow::Result<Option<Ipv4Range>> {
    let Some((ip_str, prefix_str)) = s.split_once('/') else {
        return Ok(None);
    };

    let ipv4_addr = ip_str
        .parse::<Ipv4Addr>()
        .map_err(|e| anyhow::anyhow!("Invalid IP in CIDR '{ip_str}': {e}"))?;

    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|e| anyhow::anyhow!("Invalid prefix in CIDR '{prefix_str}': {e}"))?;

    let ipv4_range = range::cidr_range(ipv4_addr, prefix).map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(Some(ipv4_range))
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
    fn test_parse_simple_host() {
        let input = vec!["192.168.1.1"];
        let col = to_collection(&input).unwrap();
        assert_eq!(col.len(), 1);
    }

    #[test]
    fn test_parse_range_explicit() {
        let input = vec!["192.168.1.1-192.168.1.5"];
        let col = to_collection(&input).unwrap();
        assert_eq!(col.len(), 5);
    }

    #[test]
    fn test_parse_range_short() {
        let input = vec!["192.168.1.1-5"];
        let col = to_collection(&input).unwrap();
        assert_eq!(col.len(), 5);
    }

    #[test]
    fn test_parse_cidr() {
        let input = vec!["192.168.1.0/30"];
        let col = to_collection(&input).unwrap();
        // /30 has 4 IPs
        assert_eq!(col.len(), 4);
    }

    #[test]
    fn test_mixed_inputs() {
        // "1.1.1.1" (1) + "10.0.0.1-2" (2) = 3 total
        let input = vec!["1.1.1.1", "10.0.0.1-2"];
        let col = to_collection(&input).unwrap();
        assert_eq!(col.len(), 3);
    }

    #[test]
    fn test_comma_splitting() {
        let input = vec!["1.1.1.1, 1.1.1.2"];
        let col = to_collection(&input).unwrap();
        assert_eq!(col.len(), 2);
    }
}
