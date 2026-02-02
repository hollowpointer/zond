// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ip;
pub mod mdns;
pub mod ndp;
pub mod tcp;
pub mod udp;
pub mod utils;

use zond_common::sender::{PacketType, SenderConfig};

use pnet::ipnetwork::Ipv4Network;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::util::MacAddr;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

type Bytes = Vec<u8>;
type PacketIter = Box<dyn Iterator<Item = (Bytes, IpAddr)> + Send>;

pub fn eth_packet_iter(sender_config: &SenderConfig) -> anyhow::Result<PacketIter> {
    let mut combined_iter: PacketIter = Box::new(std::iter::empty());

    if sender_config.has_packet_type(PacketType::ARP) {
        let arp_iter = create_arp_packets(sender_config)?;
        combined_iter = Box::new(combined_iter.chain(arp_iter));
    }

    if sender_config.has_packet_type(PacketType::ICMPv6) {
        let icmp_iter = create_icmpv6_packets(sender_config)?;
        combined_iter = Box::new(combined_iter.chain(icmp_iter));
    }

    Ok(combined_iter)
}

pub fn create_arp_packets(sender_config: &SenderConfig) -> anyhow::Result<PacketIter> {
    let src_mac: MacAddr = sender_config.get_local_mac()?;
    let dst_mac: MacAddr = MacAddr::broadcast();
    let src_net: Ipv4Network = sender_config.get_ipv4_net()?;
    let src_addr: Ipv4Addr = src_net.ip();

    let targets: HashSet<Ipv4Addr> = sender_config.get_targets_v4().iter().cloned().collect();

    let iter = targets.into_iter().map(move |dst_addr| {
        let packet: Vec<u8> = arp::create_packet(src_mac, dst_mac, src_addr, dst_addr)
            .expect("Failed to create ARP packet");

        (packet, IpAddr::V4(dst_addr))
    });

    Ok(Box::new(iter))
}

fn create_icmpv6_packets(sender_config: &SenderConfig) -> anyhow::Result<PacketIter> {
    let link_local: Ipv6Addr = sender_config.get_link_local()?;
    let local_mac: MacAddr = sender_config.get_local_mac()?;
    let packet: Vec<u8> = icmp::create_all_nodes_echo_request_v6(local_mac, link_local)?;

    let iter = std::iter::once((packet, IpAddr::V6(link_local)));

    Ok(Box::new(iter))
}

pub fn get_ip_addr_from_eth(frame: &EthernetPacket) -> anyhow::Result<IpAddr> {
    match frame.get_ethertype() {
        EtherTypes::Arp => Ok(IpAddr::V4(arp::get_ipv4_addr_from_eth(frame)?)),
        EtherTypes::Ipv4 => Ok(IpAddr::V4(ip::get_ipv4_addr_from_eth(frame)?)),
        EtherTypes::Ipv6 => Ok(IpAddr::V6(ip::get_ipv6_src_addr_from_eth(frame)?)),
        _ => Err(anyhow::anyhow!(
            "Unsupported EtherType: {:?}",
            frame.get_ethertype()
        )),
    }
}
