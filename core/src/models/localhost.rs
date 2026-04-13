// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Local Host Info Model
//!
//! Information about the *local machine* (where the program is running),
//! rather than remote hosts discovered on the network.
//!
//! This includes:
//! * Active network services (ports opened by local processes).
//! * Firewall status.

use std::collections::HashSet;
use std::net::IpAddr;

/// Represents a group of services running on a specific local IP address.
#[derive(Debug, Clone)]
pub struct IpServiceGroup {
    pub ip_addr: IpAddr,
    pub tcp_services: Vec<Service>,
    pub udp_services: Vec<Service>,
}

impl IpServiceGroup {
    pub fn new(ip_addr: IpAddr, tcp_services: Vec<Service>, udp_services: Vec<Service>) -> Self {
        Self {
            ip_addr,
            tcp_services,
            udp_services,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub local_addr: IpAddr,
    pub local_ports: HashSet<u16>,
}

impl Service {
    pub fn new(name: String, local_addr: IpAddr, local_ports: HashSet<u16>) -> Self {
        Self {
            name,
            local_addr,
            local_ports,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallStatus {
    Active,
    Inactive,
    NotDetected,
}
