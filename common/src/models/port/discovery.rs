// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Discovery Telemetry
//!
//! This module provides the [`Discovery`] model, capturing low-level
//! network details gathered during the initial port identification phase.

use std::{net::IpAddr, time::SystemTime};

/// Low-level network response types identified during scanning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScanResponse {
    /// Received a TCP SYN/ACK (Port is Open).
    SynAck,
    /// Received a TCP RST (Port is Closed).
    Rst,
    /// No response received within timeout (Port is likely Dropped/Filtered).
    NoResponse,
    /// Received an ICMP Destination Unreachable (Port is Filtered/Blocked).
    IcmpUnreach,
    /// Custom or protocol-specific response.
    Custom(String),
}

/// Telemetry and rationale for a port's discovered state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The specific packet response that determined the state.
    pub reason: ScanResponse,

    /// The time at which the port state was first confirmed.
    pub timestamp: SystemTime,

    /// The Time-to-Live (TTL) value from the response packet.
    /// Useful for distance estimation and OS fingerprinting.
    pub ttl: Option<u8>,

    /// The IP address of the interface where this discovery was made.
    /// Essential for multi-homed hosts where port states may vary by interface.
    pub source_ip: Option<IpAddr>,
}

impl Discovery {
    /// Creates a new discovery record with current timestamp.
    pub fn new(reason: ScanResponse) -> Self {
        Self {
            reason,
            timestamp: SystemTime::now(),
            ttl: None,
            source_ip: None,
        }
    }
}
