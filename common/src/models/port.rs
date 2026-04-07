// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Port Model
//!
//! This module defines the [`Port`] entity, which represents a service identified on a [`Host`].
//!
//! Unlike raw port ranges used during the discovery phase, the [`Port`] struct is a
//! "Rich" model. It encapsulates not just the port number and protocol, but also
//! state information (Open/Closed) and service metadata gathered during fingerprinting.

use std::{num::ParseIntError, ops::RangeInclusive, str::FromStr};
use thiserror::Error;

const DEFAULT_PORTSET_PORTS: &str = "22, 80, 443, 445, 3389";

#[derive(Debug, Error)]
pub enum PortSetParseError {
    #[error("Failed to parse port from '{input}': {source}")]
    InvalidPort {
        input: String,
        #[source]
        source: ParseIntError,
    },

    #[error("Invalid port range: start ({start}) cannot be strictly greater than end ({end})")]
    InvalidRange { start: u16, end: u16 },

    #[error("Malformed port specification, expected a single port or a range: '{0}'")]
    MalformedSpec(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    /// Actively accepting connections.
    Open,

    /// Actively rejecting connections.
    Closed,

    /// Likely a firewall dropping packets without a word.
    Ghosted,

    /// An intermediary device sent an explicit rejection message.
    Blocked,
}

/// Represents a specific networking endpoint on a host.
///
/// A `Port` is the primary unit of data returned after a scan has
/// moved past the initial "ping" or "syn-check" phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// The 16-bit port number (e.g., 80, 443).
    pub number: u16,

    /// The transport layer protocol used (TCP or UDP).
    pub protocol: Protocol,

    /// The current state of the port as determined by a scanner.
    pub state: PortState,

    /// Optional service information (e.g., "http", "ssh").
    /// This is typically populated during service version detection.
    pub service_info: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PortSet {
    tcp: Vec<RangeInclusive<u16>>,
    udp: Vec<RangeInclusive<u16>>,
}

impl Port {
    /// Creates a new, basic Port instance.
    pub fn new(number: u16, protocol: Protocol, state: PortState) -> Self {
        Self {
            number,
            protocol,
            state,
            service_info: None,
        }
    }

    /// Adds service banner or version information to the port.
    pub fn with_banner(mut self, banner: &str) -> Self {
        self.service_info = Some(banner.to_string());
        self
    }
}

impl PortSet {
    pub fn has_tcp(&self, port: u16) -> bool {
        self.tcp.iter().any(|range| range.contains(&port))
    }

    pub fn has_udp(&self, port: u16) -> bool {
        self.udp.iter().any(|range| range.contains(&port))
    }
}

impl Default for PortSet {
    /// Returns a default [`PortSet`] optimized for rapid host discovery.
    ///
    /// Rather than an empty set, this provides a "Greatest Hits" list of
    /// common TCP services. This allows for high-probability host
    /// verification with a minimal network footprint.
    ///
    /// ### Included Ports
    /// | Port | Service | Reason |
    /// |------|---------|--------|
    /// | 22   | SSH     | Standard Linux/IoT remote access |
    /// | 80   | HTTP    | Unencrypted web traffic / captive portals |
    /// | 443  | HTTPS   | Standard encrypted web traffic |
    /// | 445  | SMB     | Windows networking / Active Directory |
    /// | 3389 | RDP     | Windows Remote Desktop |
    fn default() -> Self {
        Self::try_from(DEFAULT_PORTSET_PORTS).expect("Static discovery ports must be valid.")
    }
}

impl TryFrom<&str> for PortSet {
    type Error = PortSetParseError;

    /// Attempts to parse a string slice into a [`PortSet`].
    ///
    /// This conversion parses a string containing port numbers or ranges.
    /// Delimiters can be spaces or commas. Ports prefixed with `u:` are
    /// assigned to UDP, otherwise they default to TCP.
    ///
    /// # Errors
    ///
    /// Returns a [`PortSetParseError`] if:
    /// - A port number cannot be parsed as a `u16`.
    /// - A port range has a start value greater than its end value.
    /// - The specification format is malformed (e.g., multiple hyphens).
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_common::models::port::PortSet;
    ///
    /// let input = "22, 80, 443-1024, u:53";
    /// let port_set = PortSet::try_from(input).unwrap();
    ///
    /// assert!(port_set.has_tcp(22));
    /// assert!(port_set.has_tcp(500));
    /// assert!(port_set.has_udp(53));
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

        Ok(Self { tcp, udp })
    }
}

impl TryFrom<String> for PortSet {
    type Error = PortSetParseError;

    /// Attempts to parse a [`String`] into a [`PortSet`].
    ///
    /// This is a convenience wrapper around the `TryFrom<&str>` implementation.
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
    fn port_set_try_from_str_parses_correctly() {
        let port_set_single = PortSet::try_from("21");
        let port_set_multiple = PortSet::try_from("21, 22 80, 800-1000, u:53 8080");

        assert!(port_set_single.is_ok());
        assert!(port_set_multiple.is_ok());

        let port_set_single = port_set_single.unwrap();
        let port_set_multiple = port_set_multiple.unwrap();

        assert!(port_set_single.has_tcp(21));

        assert!(port_set_multiple.has_tcp(21));
        assert!(port_set_multiple.has_tcp(22));
        assert!(port_set_multiple.has_tcp(80));
        assert!(port_set_multiple.has_tcp(900));
        assert!(port_set_multiple.has_udp(53));
        assert!(port_set_multiple.has_tcp(8080));
    }

    #[test]
    fn port_set_try_from_str_parses_udp_variants() {
        let port_set_udp = PortSet::try_from("u:22 u:53-100, u:1024");

        assert!(port_set_udp.is_ok());

        let port_set_udp = port_set_udp.unwrap();

        assert!(port_set_udp.has_udp(22));
        assert!(port_set_udp.has_udp(53));
        assert!(port_set_udp.has_udp(80));
        assert!(port_set_udp.has_udp(100));
        assert!(port_set_udp.has_udp(1024));
    }

    #[test]
    fn port_set_empty_input() {
        let empty = PortSet::try_from("   ");
        assert!(empty.is_ok());
        let set = empty.unwrap();
        assert!(set.tcp.is_empty());
        assert!(set.udp.is_empty());
    }

    #[test]
    fn port_set_boundaries() {
        let limits = PortSet::try_from("0, 65535, u:0-65535").unwrap();
        assert!(limits.has_tcp(0));
        assert!(limits.has_tcp(65535));
        assert!(limits.has_udp(0));
        assert!(limits.has_udp(32768));
        assert!(limits.has_udp(65535));
    }

    #[test]
    fn port_set_messy_delimiters() {
        let messy = PortSet::try_from(", 80, , 443 ,").unwrap();
        assert!(messy.has_tcp(80));
        assert!(messy.has_tcp(443));
    }

    #[test]
    fn port_set_try_from_str_throws_errors() {
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
    fn port_set_try_from_string_parses_correctly() {
        let port_set = PortSet::try_from(String::from("21 80-100 u:5353"));

        assert!(port_set.is_ok());

        let port_set = port_set.unwrap();

        assert!(port_set.has_tcp(21));
        assert!(port_set.has_tcp(80));
        assert!(port_set.has_tcp(92));
        assert!(port_set.has_tcp(100));
        assert!(port_set.has_udp(5353));
    }
}
