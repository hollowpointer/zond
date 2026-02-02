// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use pnet::{
    datalink::NetworkInterface,
    ipnetwork::{Ipv4Network, Ipv6Network},
    util::MacAddr,
};

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::interface::NetworkInterfaceExtension;

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum PacketType {
    ARP,
    ICMPv6,
}

#[derive(Debug, Clone, Default)]
pub struct SenderConfig {
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
    pub fn get_local_mac(&self) -> anyhow::Result<MacAddr> {
        self.local_mac
            .ok_or_else(|| anyhow::anyhow!("local MAC not set"))
    }

    pub fn get_ipv4_net(&self) -> anyhow::Result<Ipv4Network> {
        let ipv4_net = self
            .ipv4_nets
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("no IPv4 networks available in configuration"))?;

        Ok(ipv4_net)
    }

    pub fn get_link_local(&self) -> anyhow::Result<Ipv6Addr> {
        self.ipv6_nets
            .iter()
            .find_map(|ipv6_net| {
                let ip = ipv6_net.ip();
                ip.is_unicast_link_local().then_some(ip)
            })
            .ok_or_else(|| anyhow::anyhow!("missing link local address"))
    }

    pub fn get_targets_v4(&self) -> HashSet<Ipv4Addr> {
        self.targets_v4.clone()
    }

    pub fn len(&self) -> usize {
        self.targets_v4.len() + self.targets_v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.targets_v4.is_empty() && self.targets_v6.is_empty()
    }

    pub fn add_target(&mut self, target_addr: IpAddr) {
        match target_addr {
            IpAddr::V4(ipv4_addr) => self.targets_v4.insert(ipv4_addr),
            IpAddr::V6(ipv6_addr) => self.targets_v6.insert(ipv6_addr),
        };
    }

    pub fn add_targets<T: IntoIterator<Item = IpAddr>>(&mut self, targets: T) {
        for target in targets {
            self.add_target(target);
        }
    }

    pub fn has_addr(&self, target_addr: &IpAddr) -> bool {
        match target_addr {
            IpAddr::V4(ipv4_addr) => self.targets_v4.contains(ipv4_addr),
            IpAddr::V6(ipv6_addr) => self.targets_v6.contains(ipv6_addr),
        }
    }

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
