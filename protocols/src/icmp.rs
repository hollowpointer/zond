// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use crate::ethernet;
use crate::ip;
use crate::utils::{ETH_HDR_LEN, ICMP_V6_ECHO_REQ_LEN, IP_V6_HDR_LEN};
use anyhow::Context;
use pnet::datalink::MacAddr;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::icmpv6::echo_reply::Icmpv6Codes;
use pnet::packet::icmpv6::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types, checksum};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use std::net::Ipv6Addr;

const TOTAL_LEN: usize = ETH_HDR_LEN + IP_V6_HDR_LEN + ICMP_V6_ECHO_REQ_LEN;
const PAYLOAD_LENGTH: u16 = ICMP_V6_ECHO_REQ_LEN as u16;
const NEXT_PROTOCOL: IpNextHeaderProtocol = IpNextHeaderProtocols::Icmpv6;

pub fn create_all_nodes_echo_request_v6(
    src_mac: MacAddr,
    src_addr: Ipv6Addr,
) -> anyhow::Result<Vec<u8>> {
    let dst_mac: MacAddr = MacAddr::new(0x33, 0x33, 0, 0, 0, 1);
    let dst_addr: Ipv6Addr = Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1);
    let eth_header: Vec<u8> = ethernet::make_header(src_mac, dst_mac, EtherTypes::Ipv6)?;
    let ipv6_header: Vec<u8> =
        ip::create_ipv6_header(src_addr, dst_addr, PAYLOAD_LENGTH, NEXT_PROTOCOL)?;
    let mut icmp_packet: [u8; ICMP_V6_ECHO_REQ_LEN] = [0u8; ICMP_V6_ECHO_REQ_LEN];

    {
        let mut icmp: MutableEchoRequestPacket =
            MutableEchoRequestPacket::new(&mut icmp_packet[..])
                .context("failed to create echo request packet")?;
        icmp.set_icmpv6_type(Icmpv6Types::EchoRequest);
        icmp.set_icmpv6_code(Icmpv6Codes::NoCode);
        icmp.set_identifier(rand::random());
        icmp.set_sequence_number(0);
        let icmp_imm: EchoRequestPacket = icmp.to_immutable();
        let icmp_pkt: Icmpv6Packet =
            Icmpv6Packet::new(icmp_imm.packet()).context("failed to create ICMPv6 packet")?;
        let csm = checksum(&icmp_pkt, &src_addr, &dst_addr);
        icmp.set_checksum(csm);
    }

    let mut final_packet: Vec<u8> = Vec::with_capacity(TOTAL_LEN);
    final_packet.extend_from_slice(&eth_header);
    final_packet.extend_from_slice(&ipv6_header);
    final_packet.extend_from_slice(&icmp_packet);

    Ok(final_packet)
}
