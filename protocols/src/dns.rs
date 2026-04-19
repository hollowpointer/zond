// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use dns_parser::{Builder, Packet, QueryClass, QueryType, RData};
use std::net::IpAddr;

pub fn get_hostname(payload: &[u8]) -> Result<(u16, String)> {
    let packet = Packet::parse(payload).context("Failed to parse DNS packet")?;

    for record in packet.answers {
        if let RData::PTR(ptr) = record.data {
            return Ok((packet.header.id, ptr.0.to_string()));
        }
    }

    Err(anyhow!("No valid PTR record found"))
}

fn reverse_address_to_ptr(ip_addr: &IpAddr) -> String {
    match ip_addr {
        IpAddr::V4(ipv4_addr) => {
            let octets: [u8; 4] = ipv4_addr.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(ipv6_addr) => {
            let octets: [u8; 16] = ipv6_addr.octets();
            let mut ret: String = String::with_capacity(72);

            for byte in octets.iter().rev() {
                let low: u8 = byte & 0x0F;
                let high: u8 = byte >> 4;

                use std::fmt::Write;
                write!(ret, "{:x}.{:x}.", low, high).unwrap();
            }

            ret.push_str("ip6.arpa");
            ret
        }
    }
}

/// Constructs a raw DNS query packet for a PTR lookup.
pub fn create_ptr_packet(ip_addr: &IpAddr, id: u16) -> Result<Vec<u8>> {
    let ptr_name: String = reverse_address_to_ptr(ip_addr);

    let mut builder: Builder = Builder::new_query(id, true);

    builder.add_question(&ptr_name, false, QueryType::PTR, QueryClass::IN);

    let packet_bytes: Vec<u8> = builder
        .build()
        .map_err(|e| anyhow!("Failed to build DNS packet: {:?}", e))?;

    Ok(packet_bytes)
}
