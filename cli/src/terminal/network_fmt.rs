// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use crate::terminal::{colors, print};
use colored::*;
use zond_common::utils::ip::{self, Ipv6AddressType};
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;

pub fn to_key_value_pair_net(ip_net: &[IpNetwork]) -> Vec<(String, ColoredString)> {
    ip_net
        .iter()
        .map(|ip_network| match ip_network {
            IpNetwork::V4(ipv4_network) => {
                let address: ColoredString = ipv4_network.ip().to_string().color(colors::IPV4_ADDR);
                let prefix: ColoredString =
                    ipv4_network.prefix().to_string().color(colors::IPV4_PREFIX);
                let result: ColoredString = format!("{address}/{prefix}").color(colors::SEPARATOR);
                ("IPv4".to_string(), result)
            }
            IpNetwork::V6(ipv6_network) => {
                let address: ColoredString = ipv6_network.ip().to_string().color(colors::IPV6_ADDR);
                let prefix: ColoredString =
                    ipv6_network.prefix().to_string().color(colors::IPV6_PREFIX);
                let value: ColoredString = format!("{address}/{prefix}").color(colors::SEPARATOR);
                let ipv6_type = ip::get_ipv6_type(&ipv6_network.ip());

                let key = match ipv6_type {
                    Ipv6AddressType::GlobalUnicast => "GUA",
                    Ipv6AddressType::LinkLocal => "LLA",
                    Ipv6AddressType::UniqueLocal => "ULA",
                    _ => "IPv6",
                };
                (key.to_string(), value)
            }
        })
        .collect()
}

pub fn print_interface(interface: &NetworkInterface, idx: usize) {
    print::tree_head(idx, &interface.name);
    let mut key_value_pair: Vec<(String, ColoredString)> = to_key_value_pair_net(&interface.ips);
    if let Some(mac_addr) = interface.mac {
        key_value_pair.push((
            "MAC".to_string(),
            mac_addr.to_string().color(colors::MAC_ADDR),
        ));
    }
    print::as_tree(key_value_pair);
}
