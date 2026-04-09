// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use pnet::datalink::NetworkInterface;
use crate::models::ip::set::IpSet;

/// Returns a list of prioritized network interfaces (e.g. wired first, then wireless, etc.)
pub fn get_prioritized_interfaces(limit: usize) -> anyhow::Result<Vec<NetworkInterface>> {
    let mut interfaces: Vec<NetworkInterface> = pnet::datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .collect();

    interfaces.sort_by_key(|i| if i.name.starts_with("e") { 0 } else { 1 });

    Ok(interfaces.into_iter().take(limit).collect())
}

pub fn is_layer_2_capable(intf: &NetworkInterface) -> bool {
    !intf.is_point_to_point() && !intf.is_loopback() && intf.mac.is_some()
}

pub fn is_on_link(intf: &NetworkInterface, ips: &IpSet) -> bool {
    for range in ips.ranges() {
        let mut range_covered = false;
        for iface_ipnet in &intf.ips {
            if let pnet::ipnetwork::IpNetwork::V4(network) = iface_ipnet
                && network.contains(range.start_addr)
                && network.contains(range.end_addr)
            {
                range_covered = true;
                break;
            }
        }
        if !range_covered {
            return false;
        }
    }
    true
}
