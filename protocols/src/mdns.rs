// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use dns_parser::{Packet, RData};
use std::{collections::HashSet, net::IpAddr};

#[derive(Debug, Default)]
pub struct MdnsRecord {
    pub hostname: Option<String>,
    pub ips: HashSet<IpAddr>,
}

pub fn extract_resource(data: &[u8]) -> Result<MdnsRecord> {
    let packet = Packet::parse(data).context("failed to parse mDNS packet")?;
    let mut metadata: MdnsRecord = MdnsRecord::default();

    for record in packet.answers.iter().chain(packet.additional.iter()) {
        match &record.data {
            RData::PTR(ptr) => {
                let name: String = ptr.0.to_string();
                if !name.ends_with(".arpa") {
                    metadata.hostname = Some(name);
                }
            }

            RData::A(a) => {
                metadata.ips.insert(IpAddr::V4(a.0));
            }

            RData::AAAA(aaaa) => {
                metadata.ips.insert(IpAddr::V6(aaaa.0));
            }

            _ => {}
        }
    }

    Ok(metadata)
}
