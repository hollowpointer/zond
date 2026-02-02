// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use dns_parser::{Builder, Packet, QueryClass, QueryType, RData};
use std::net::IpAddr;

use zond_common::utils::ip;

pub fn get_hostname(payload: &[u8]) -> Result<(u16, String)> {
    let packet = Packet::parse(payload).context("Failed to parse DNS packet")?;

    for record in packet.answers {
        if let RData::PTR(ptr) = record.data {
            return Ok((packet.header.id, ptr.0.to_string()));
        }
    }

    Err(anyhow!("No valid PTR record found"))
}

/// Constructs a raw DNS query packet for a PTR lookup.
pub fn create_ptr_packet(ip_addr: &IpAddr, id: u16) -> Result<Vec<u8>> {
    let ptr_name: String = ip::reverse_address_to_ptr(ip_addr);

    let mut builder: Builder = Builder::new_query(id, true);

    builder.add_question(&ptr_name, false, QueryType::PTR, QueryClass::IN);

    let packet_bytes: Vec<u8> = builder
        .build()
        .map_err(|e| anyhow!("Failed to build DNS packet: {:?}", e))?;

    Ok(packet_bytes)
}
