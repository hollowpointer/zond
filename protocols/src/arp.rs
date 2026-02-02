// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use crate::ethernet;
use crate::utils::{ARP_LEN, MIN_ETH_FRAME_NO_FCS};
use anyhow::Context;
use pnet::datalink::MacAddr;
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use std::net::Ipv4Addr;

pub fn create_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
) -> anyhow::Result<Vec<u8>> {
    let eth_header: Vec<u8> =
        ethernet::make_header(src_mac, MacAddr::broadcast(), EtherTypes::Arp)?;

    let mut arp_buffer: [u8; ARP_LEN] = [0u8; ARP_LEN];
    {
        let mut arp_packet: MutableArpPacket = MutableArpPacket::new(&mut arp_buffer)
            .context("failed to create mutable ARP packet")?;
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(src_mac);
        arp_packet.set_target_hw_addr(dst_mac);
        arp_packet.set_sender_proto_addr(src_addr);
        arp_packet.set_target_proto_addr(dst_addr);
    }

    let mut final_packet: Vec<u8> = Vec::with_capacity(MIN_ETH_FRAME_NO_FCS);

    final_packet.extend_from_slice(&eth_header);
    final_packet.extend_from_slice(&arp_buffer);
    final_packet.resize(MIN_ETH_FRAME_NO_FCS, 0u8);

    Ok(final_packet)
}

pub fn get_ipv4_addr_from_eth(eth_packet: &EthernetPacket) -> anyhow::Result<Ipv4Addr> {
    let arp_packet: ArpPacket = ArpPacket::new(eth_packet.payload()).context(format!(
        "truncated or invalid ARP packet (payload len {})",
        eth_packet.payload().len()
    ))?;
    Ok(arp_packet.get_sender_proto_addr())
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
    use pnet::packet::Packet;
    use pnet::packet::arp::ArpHardwareTypes;
    use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::util::MacAddr;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;

    const ETH_HDR_LEN: usize = 14;
    const ARP_LEN: usize = 28;
    fn get_ip_addr(packet: EthernetPacket) -> anyhow::Result<IpAddr> {
        match packet.get_ethertype() {
            EtherTypes::Arp => {
                let payload = packet.payload();
                if payload.len() < ARP_LEN {
                    return Err(anyhow::anyhow!(
                        "truncated or invalid ARP packet (payload len {})",
                        payload.len()
                    ));
                }
                let arp = ArpPacket::new(payload).context("failed to parse ARP packet")?;
                Ok(IpAddr::V4(arp.get_sender_proto_addr()))
            }
            _ => Err(anyhow::anyhow!("not an ARP packet")),
        }
    }

    fn build_mock_arp_packet(sender_ip: Ipv4Addr, payload_size: usize) -> Vec<u8> {
        let mut eth_buffer = vec![0u8; ETH_HDR_LEN];
        {
            let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buffer).unwrap();
            eth_pkt.set_destination(MacAddr::broadcast());
            eth_pkt.set_source(MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06));
            eth_pkt.set_ethertype(EtherTypes::Arp);
        }

        let mut arp_buffer = vec![0u8; payload_size];

        if payload_size >= ARP_LEN {
            let mut arp_pkt = MutableArpPacket::new(&mut arp_buffer[..ARP_LEN]).unwrap();

            arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_pkt.set_protocol_type(EtherTypes::Ipv4);
            arp_pkt.set_hw_addr_len(6);
            arp_pkt.set_proto_addr_len(4);
            arp_pkt.set_operation(ArpOperations::Reply);
            arp_pkt.set_sender_hw_addr(MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06));
            arp_pkt.set_sender_proto_addr(sender_ip);
            arp_pkt.set_target_hw_addr(MacAddr::zero());
            arp_pkt.set_target_proto_addr(Ipv4Addr::new(192, 168, 1, 1));
        }

        [eth_buffer, arp_buffer].concat()
    }

    #[test]
    fn create_arp_request_packet() {
        let src_mac = MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        let dst_mac = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let src_addr = Ipv4Addr::new(192, 168, 1, 10);
        let dst_addr = Ipv4Addr::new(192, 168, 1, 1);

        let buffer =
            create_packet(src_mac, dst_mac, src_addr, dst_addr).expect("Packet creation failed");

        assert!(buffer.len() >= 60);

        let eth_packet = EthernetPacket::new(&buffer).expect("Failed to parse Ethernet packet");

        assert_eq!(eth_packet.get_destination(), MacAddr::broadcast());
        assert_eq!(eth_packet.get_source(), src_mac);
        assert_eq!(eth_packet.get_ethertype(), EtherTypes::Arp);

        let arp_payload = eth_packet.payload();
        assert!(arp_payload.len() >= ARP_LEN);

        let arp_packet = ArpPacket::new(arp_payload).expect("Failed to parse ARP packet");
        assert_eq!(arp_packet.get_operation(), ArpOperations::Request);
        assert_eq!(arp_packet.get_hardware_type(), ArpHardwareTypes::Ethernet);
        assert_eq!(arp_packet.get_protocol_type(), EtherTypes::Ipv4);
        assert_eq!(arp_packet.get_hw_addr_len(), 6);
        assert_eq!(arp_packet.get_proto_addr_len(), 4);
        assert_eq!(arp_packet.get_sender_hw_addr(), src_mac);
        assert_eq!(arp_packet.get_sender_proto_addr(), src_addr);
        assert_eq!(arp_packet.get_target_hw_addr(), dst_mac);
        assert_eq!(arp_packet.get_target_proto_addr(), dst_addr);
    }

    #[test]
    fn test_get_ip_addr_success() {
        let expected_ip = Ipv4Addr::new(192, 168, 1, 123);
        let valid_arp_payload_size = ARP_LEN;
        let buffer = build_mock_arp_packet(expected_ip, valid_arp_payload_size);
        let ethernet_packet = EthernetPacket::new(&buffer).unwrap();
        let result = get_ip_addr(ethernet_packet);
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip, IpAddr::V4(expected_ip));
    }

    #[test]
    fn test_get_ip_addr_truncated_payload() {
        let truncated_payload_size = 10;
        let buffer = build_mock_arp_packet(Ipv4Addr::UNSPECIFIED, truncated_payload_size);
        let ethernet_packet = EthernetPacket::new(&buffer).unwrap();
        assert_eq!(ethernet_packet.payload().len(), truncated_payload_size);
        let result = get_ip_addr(ethernet_packet);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("truncated or invalid ARP packet"));
        assert!(err_msg.contains("(payload len 10)"));
    }

    #[test]
    fn test_get_ip_addr_wrong_payload_type() {
        const IPV4_PAYLOAD_SIZE: usize = 20;
        let mut buffer = build_mock_arp_packet(Ipv4Addr::UNSPECIFIED, IPV4_PAYLOAD_SIZE);

        let mut eth_pkt = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth_pkt.set_ethertype(EtherTypes::Ipv4);

        let ethernet_packet = EthernetPacket::new(&buffer).unwrap();
        assert_eq!(ethernet_packet.payload().len(), IPV4_PAYLOAD_SIZE);

        let result = get_ip_addr(ethernet_packet);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not an ARP packet"));
    }
}
