// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{net::Ipv4Addr, sync::atomic::Ordering};

use zond_core::{
    info,
    models::ip::{
        range::{IpError, Ipv4Range},
        set::IpSet,
    },
    parse::{IS_LAN_SCAN, IpParseError, ip::Keyword},
    warn,
};

use crate::interface;

pub fn resolve(keyword: Keyword, ip_set: &mut IpSet) -> Result<(), IpParseError> {
    match keyword {
        Keyword::Lan => resolve_lan(ip_set),
        Keyword::Vpn => Ok(IpParseError),
    }
}

/// Dynamically resolves the host's primary LAN interface into an inclusive range.
fn resolve_lan(set: &mut IpSet) -> Result<(), IpParseError> {
    let net = interface::get_lan_network()
        .map_err(|e| IpParseError::LanError(e.to_string()))?
        .ok_or_else(|| IpParseError::LanError("No active network interface found".into()))?;

    let start_u32 = u32::from(net.network()).saturating_add(1);
    let end_u32 = u32::from(net.broadcast()).saturating_sub(1);

    if start_u32 <= end_u32 {
        IS_LAN_SCAN.store(true, Ordering::Relaxed);
        let range = Ipv4Range::new(Ipv4Addr::from(start_u32), Ipv4Addr::from(end_u32)).map_err(
            |e| match e {
                IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
                _ => IpParseError::LanError("Invalid LAN range".into()),
            },
        )?;

        info!(
            verbosity = 1,
            "Resolved LAN: {} - {}", range.start_addr, range.end_addr
        );
        set.insert_range(range);
    } else {
        warn!("Small subnet; scanning full network range.");
        set.insert_range(Ipv4Range::new(net.network(), net.broadcast()).unwrap());
    }

    Ok(())
}
