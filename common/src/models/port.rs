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

use std::ops::RangeInclusive;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

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

#[derive(Debug, Clone, Default)]
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

impl From<String> for PortSet {
    /// Converts a [`String`] into a [`PortSet`].
    ///
    /// This conversion parses a string containing port numbers or ranges.
    /// Delimiters can be spaces or commas. Ports prefixed with `u:` are
    /// assigned to UDP, otherwise they default to TCP.
    ///
    /// # Panics
    ///
    /// This implementation will panic if:
    /// - A port number cannot be parsed as a `u16`.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_common::models::port::PortSet;
    ///
    /// let input = String::from("22, 80, 443-1024, u:53");
    /// let port_set = PortSet::from(input);
    ///
    /// assert!(port_set.has_tcp(22));
    /// assert!(port_set.has_tcp(500));
    /// assert!(port_set.has_udp(53));
    /// ```
    fn from(value: String) -> Self {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();

        for part in value.split([',', ' ']).filter(|s| !s.trim().is_empty()) {
            let part = part.trim();

            let (is_udp, raw_range) = if let Some(stripped) = part.strip_prefix("u:") {
                (true, stripped)
            } else {
                (false, part)
            };

            let range = if let Some((start, end)) = raw_range.split_once('-') {
                let s = start.parse::<u16>().expect("Invalid start port");
                let e = end.parse::<u16>().expect("Invalid end port");
                s..=e
            } else {
                let p = raw_range.parse::<u16>().expect("Invalid port number");
                p..=p
            };

            if is_udp {
                udp.push(range);
            } else {
                tcp.push(range);
            }
        }

        Self { tcp, udp }
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
