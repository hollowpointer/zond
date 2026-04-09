// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Network sender configuration and identity management.
//!
//! This module provides the [`SenderConfig`] struct, which serves as the primary
//! configuration object for active network discovery operations. It acts as the
//! identity of the scanner, encapsulating local network interface details
//! (MAC, IP, subnets) and defining the scope of the scan (target addresses, packet types).
//!
//! `SenderConfig` bridges the gap between raw `pnet` network interfaces and higher-level
//! protocol generation. It is consumed by:
//! - The `core` scanner to initialize scanning loops and filter incoming traffic.
//! - The `protocols` module to source source MAC/IP addresses for constructing
//!   ARP, ICMP, and other discovery packets.

use pnet::{
    datalink::NetworkInterface,
    ipnetwork::{Ipv4Network, Ipv6Network},
    util::MacAddr,
};

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;

use crate::net::interface::NetworkInterfaceExtension;

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum PacketType {
    ARP,
    ICMPv6,
}

#[derive(Error, Debug)]
pub enum SenderError {
    #[error("local MAC address not set")]
    LocalMacNotSet,
    #[error("no IPv4 networks available")]
    NoIpv4Network,
    #[error("missing link-local IPv6 address")]
    MissingLinkLocal,
}

/// Configuration for the network sender.
///
/// This struct holds the configuration for sending packets, including
/// local network details, target addresses, and the packet types to be sent.
#[derive(Debug, Clone, Default)]
pub struct SenderConfig {
    /// The MAC address of the local network interface.
    pub local_mac: Option<MacAddr>,
    ipv4_nets: Vec<Ipv4Network>,
    ipv6_nets: Vec<Ipv6Network>,
    targets_v4: HashSet<Ipv4Addr>,
    targets_v6: HashSet<Ipv6Addr>,
    packet_types: HashSet<PacketType>,
}

impl From<&NetworkInterface> for SenderConfig {
    fn from(interface: &NetworkInterface) -> Self {
        Self {
            local_mac: interface.mac,
            ipv4_nets: interface.get_ipv4_nets(),
            ipv6_nets: interface.get_ipv6_nets(),
            targets_v4: HashSet::new(),
            targets_v6: HashSet::new(),
            packet_types: HashSet::new(),
        }
    }
}

impl SenderConfig {
    /// Returns the local MAC address if set.
    ///
    /// # Errors
    ///
    /// Returns an error if the local MAC address has not been configured.
    pub fn get_local_mac(&self) -> Result<MacAddr, SenderError> {
        self.local_mac.ok_or(SenderError::LocalMacNotSet)
    }

    /// Returns the first configured IPv4 network.
    ///
    /// # Errors
    ///
    /// Returns an error if no IPv4 networks are configured.
    pub fn get_ipv4_net(&self) -> Result<Ipv4Network, SenderError> {
        let ipv4_net = self
            .ipv4_nets
            .first()
            .copied()
            .ok_or(SenderError::NoIpv4Network)?;

        Ok(ipv4_net)
    }

    /// Returns the link-local IPv6 address for the interface.
    ///
    /// # Errors
    ///
    /// Returns an error if no link-local IPv6 address is found.
    pub fn get_link_local(&self) -> Result<Ipv6Addr, SenderError> {
        self.ipv6_nets
            .iter()
            .find_map(|ipv6_net| {
                let ip = ipv6_net.ip();
                ip.is_unicast_link_local().then_some(ip)
            })
            .ok_or(SenderError::MissingLinkLocal)
    }

    /// Returns an iterator over the IPv4 target addresses.
    pub fn iter_targets_v4(&self) -> impl Iterator<Item = &Ipv4Addr> {
        self.targets_v4.iter()
    }

    /// Returns the total number of target addresses (IPv4 + IPv6).
    pub fn len(&self) -> usize {
        self.targets_v4.len() + self.targets_v6.len()
    }

    /// Returns `true` if there are no target addresses.
    pub fn is_empty(&self) -> bool {
        self.targets_v4.is_empty() && self.targets_v6.is_empty()
    }

    /// Adds a target IP address to the configuration.
    ///
    /// The address is added to either the IPv4 or IPv6 target set depending on its version.
    pub fn add_target(&mut self, target_addr: IpAddr) {
        match target_addr {
            IpAddr::V4(ipv4_addr) => self.targets_v4.insert(ipv4_addr),
            IpAddr::V6(ipv6_addr) => self.targets_v6.insert(ipv6_addr),
        };
    }

    /// Adds multiple target IP addresses to the configuration.
    pub fn add_targets<T: IntoIterator<Item = IpAddr>>(&mut self, targets: T) {
        for target in targets {
            self.add_target(target);
        }
    }

    /// Checks if a target IP address is present in the configuration.
    pub fn has_addr(&self, target_addr: &IpAddr) -> bool {
        match target_addr {
            IpAddr::V4(ipv4_addr) => self.targets_v4.contains(ipv4_addr),
            IpAddr::V6(ipv6_addr) => self.targets_v6.contains(ipv6_addr),
        }
    }

    /// Checks if an IP address belongs to any of the configured subnets.
    pub fn is_addr_in_subnet(&self, ip_addr: IpAddr) -> bool {
        match ip_addr {
            IpAddr::V4(ipv4_addr) => self.ipv4_nets.iter().any(|net| net.contains(ipv4_addr)),
            IpAddr::V6(ipv6_addr) => self.ipv6_nets.iter().any(|net| net.contains(ipv6_addr)),
        }
    }

    pub fn add_packet_type(&mut self, packet_type: PacketType) {
        self.packet_types.insert(packet_type);
    }

    pub fn has_packet_type(&self, packet_type: PacketType) -> bool {
        self.packet_types.contains(&packet_type)
    }
}
