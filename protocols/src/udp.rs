// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use anyhow::Context;
use pnet::packet::udp::MutableUdpPacket;

const UDP_HDR_LEN: usize = 8;

pub fn create_packet(src_port: u16, dst_port: u16, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let total_len: usize = UDP_HDR_LEN + payload.len();
    let mut buffer: Vec<u8> = vec![0u8; total_len];
    {
        let mut udp: MutableUdpPacket = MutableUdpPacket::new(&mut buffer).context("creating udp packet")?;
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length(total_len as u16);
        udp.set_payload(&payload);
        udp.set_checksum(0);
    }
    Ok(buffer)
}
