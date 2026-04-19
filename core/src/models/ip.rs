// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::net::{IpAddr, Ipv6Addr};

pub mod range;
pub mod set;

#[derive(Debug, Default)]
pub enum Ipv6AddressType {
    GlobalUnicast,
    UniqueLocal,
    LinkLocal,
    Loopback,
    #[default]
    Unspecified,
}

pub fn get_ipv6_type(ipv6_addr: &Ipv6Addr) -> Ipv6AddressType {
    match true {
        _ if is_global_unicast(ipv6_addr) => Ipv6AddressType::GlobalUnicast,
        _ if ipv6_addr.is_unique_local() => Ipv6AddressType::UniqueLocal,
        _ if ipv6_addr.is_unicast_link_local() => Ipv6AddressType::LinkLocal,
        _ if ipv6_addr.is_loopback() => Ipv6AddressType::Loopback,
        _ => Ipv6AddressType::Unspecified,
    }
}

pub fn is_global_unicast(ipv6_addr: &Ipv6Addr) -> bool {
    let first_byte = ipv6_addr.octets()[0];
    (0x20..=0x3F).contains(&first_byte)
}

pub fn is_private(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ipv4) => ipv4.is_private(),
        IpAddr::V6(ipv6) => ipv6.is_unicast_link_local() || ipv6.is_unique_local(),
    }
}
